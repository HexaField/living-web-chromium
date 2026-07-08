// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 06 browser-process Sync Module runtime
// (content::ModuleRuntimeHost) plus its concrete browser host-import backings
// (content::ModuleGraphAdapter / content::ModuleCryptoAdapter) and the shared
// Chromium-independent cores content/browser/module_runtime/
// module_capabilities.{h,cc} (the §8 capability algebra) and module_manifest.
// {h,cc} (the §4.2 content-addressing + §8.2 manifest). These exercise the same
// normative behaviour as the standalone Module_* conformance harness, but against
// the browser port bound to content::DIDKeyProvider (the §5.4 scoped signer) and
// content::GraphBackendManager (the real Spec 02 graphs a module reads and
// writes), so the full-tree content_unittests build has direct coverage of §7.1
// installation (content-hash + manifest binding), §7.2 consent gating, §8/§8.3
// capability + scope enforcement on every host surface, §8.1 storage quota +
// §9.5 per-(module,graph) isolation, §5.4/§9.7 scoped commit/signal signing, the
// §7.3/§7.4/§7.5 lifecycle, and §6.4/§7.6 introspection. The grant/scope/quota/
// signing decisions live in the two shared cores, consumed verbatim by both the
// standalone runtime and this host, so the bytes the sandbox enforces are
// byte-identical between the two build worlds; only WASM instantiation itself
// (the §6.1 component-model boundary) is absent — the test plays the module,
// calling the §6.3 host imports the way a component would.

#include "content/browser/module_runtime/module_runtime_host.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph_sync/graph_diff.h"
#include "content/browser/graph_sync/sync_backend.h"
#include "content/browser/module_runtime/module_capabilities.h"
#include "content/browser/module_runtime/module_manifest.h"
#include "content/browser/module_runtime/module_runtime_backends.h"
#include "crypto/sha2.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

using living_web::FormatModuleContentHash;
using living_web::HostError;
using living_web::IsWellFormedContentHash;
using living_web::ManifestBindsContentHash;
using living_web::ModuleManifest;
using living_web::ParseModuleManifest;
using living_web::ToLowerHex;
using living_web::Triple;

// ---- triple constructors (mirror the standalone MakeLit/MakeIri) -----------

// An xsd:string literal-object triple.
Triple MakeLit(const std::string& s,
               const std::string& p,
               const std::string& lex) {
  Triple t;
  t.subject = s;
  t.predicate = p;
  living_web::LiteralValue lv;
  lv.lexical = lex;
  t.object = living_web::ObjectTerm::Literal(lv);
  return t;
}

// ---- module-manifest / content-hash helpers (mirror the standalone harness) -

// The fake module binaries the harness content-addresses. Neither build world
// executes them — WASM instantiation is the §6.1 component-model boundary — so
// any distinct bytes drive the host contract; two binaries give two distinct
// §4.2 content hashes.
const char kModWasmA[] = "living-web-sync-module-A::wasm-component-bytes::v1";
const char kModWasmB[] = "living-web-sync-module-B::wasm-component-bytes::v1";

std::string ModContentHash(const std::string& wasm) {
  return FormatModuleContentHash(crypto::SHA256HashString(wasm));
}

std::string ModJsonArr(const std::vector<std::string>& v) {
  std::string s = "[";
  for (size_t i = 0; i < v.size(); ++i) {
    s += "\"" + v[i] + "\"";
    if (i + 1 < v.size())
      s += ",";
  }
  return s + "]";
}

// A §8.2 manifest JSON binding |content_hash|, requiring |kinds| / |caps|.
std::string ModManifest(const std::string& name,
                        const std::string& version,
                        const std::string& content_hash,
                        const std::vector<std::string>& kinds,
                        const std::vector<std::string>& caps) {
  return std::string("{") + "\"name\":\"" + name + "\"," + "\"version\":\"" +
         version + "\"," + "\"wasmContentHash\":\"" + content_hash + "\"," +
         "\"supportedConstraintKinds\":" + ModJsonArr(kinds) + "," +
         "\"capabilitiesRequired\":" + ModJsonArr(caps) + "}";
}

// ---- host-network loopback (mirror the standalone ModConnection/Network) -----

// An in-process loopback transport: framed messages sent are echoed back on
// receive. No external I/O, but a real byte stream with real close semantics —
// the browser overlay's network-service backing is out of this branch (§6.2).
class LoopbackConnection : public HostConnection {
 public:
  bool Send(const std::vector<uint8_t>& message, HostError* err) override {
    if (!open_) {
      *err = HostError::kNetworkError;
      return false;
    }
    inbox_.push_back(message);
    return true;
  }
  bool Receive(std::vector<uint8_t>* out,
               bool* closed,
               HostError* /*err*/) override {
    if (inbox_.empty()) {
      out->clear();
      *closed = !open_;
      return true;
    }
    *out = inbox_.front();
    inbox_.erase(inbox_.begin());
    *closed = false;
    return true;
  }
  bool IsOpen() const override { return open_; }
  void Close() override { open_ = false; }

 private:
  bool open_ = true;
  std::vector<std::vector<uint8_t>> inbox_;
};

class LoopbackNetwork : public HostNetworkBackend {
 public:
  HostConnection* Connect(const std::string&,
                          RelayProtocol,
                          HostError*) override {
    conns_.push_back(std::make_unique<LoopbackConnection>());
    return conns_.back().get();
  }
  HostConnection* PeerConnect(const std::string&,
                              const std::string&,
                              HostError*) override {
    conns_.push_back(std::make_unique<LoopbackConnection>());
    return conns_.back().get();
  }
  bool Fetch(const std::string& url,
             std::vector<uint8_t>* out,
             HostError*) override {
    out->assign(url.begin(), url.end());  // echo the URL bytes as the body
    return true;
  }

 private:
  std::vector<std::unique_ptr<LoopbackConnection>> conns_;
};

// Mounts a fresh external-trust Spec 02 graph for |did| and binds it into the
// host-graph adapter — the browser analogue of the standalone ModGraphBackend::
// AddGraph. The backend is owned by |graphs| and outlives the binding.
GraphBackend* AddBoundGraph(GraphBackendManager* graphs,
                            ModuleGraphAdapter* mgraph,
                            const std::string& did) {
  GraphBackend* g = graphs->CreateMounted(did);
  mgraph->Bind(did, g);
  return g;
}

// ---- §4.2 content-addressing (module_manifest.cc) ----

TEST(ModuleRuntimeHostTest, ContentHash_FormatAndWellFormedness) {
  const std::string h = FormatModuleContentHash(crypto::SHA256HashString("abc"));
  EXPECT_EQ(h.size(), size_t(71));  // "sha256-" (7) + 64 hex
  EXPECT_TRUE(h.compare(0, 7, "sha256-") == 0);
  EXPECT_TRUE(IsWellFormedContentHash(h));
  // Deterministic: same binary → same address (§4.2 mutual verifiability).
  EXPECT_EQ(h, FormatModuleContentHash(crypto::SHA256HashString("abc")));

  EXPECT_FALSE(IsWellFormedContentHash(h.substr(0, 70)));  // 63 hex digits
  EXPECT_FALSE(IsWellFormedContentHash("sha256-" + std::string(64, 'g')));
  std::string upper = h;
  upper[7] = 'A';  // uppercase hex is not lowercase-hex
  EXPECT_FALSE(IsWellFormedContentHash(upper));
  EXPECT_FALSE(IsWellFormedContentHash("sha512-" + h.substr(7)));  // wrong prefix
}

// ---- §8.2 manifest parse ----

TEST(ModuleRuntimeHostTest, Manifest_ParseValidPopulatesFields) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest m;
  std::string err;
  EXPECT_TRUE(ParseModuleManifest(
      ModManifest("Default Sync", "1.2.0", ch, {"capability", "shape"},
                  {"graph.read", "graph.write"}),
      &m, &err));
  EXPECT_TRUE(m.valid);
  EXPECT_EQ(m.name, std::string("Default Sync"));
  EXPECT_EQ(m.version, std::string("1.2.0"));
  EXPECT_EQ(m.wasm_content_hash, ch);
  EXPECT_EQ(m.supported_constraint_kinds.size(), size_t(2));
  EXPECT_EQ(m.capabilities_required.size(), size_t(2));

  // Optional publisher/description are captured when present, ignored when not.
  ModuleManifest m2;
  EXPECT_TRUE(ParseModuleManifest(
      std::string("{\"name\":\"n\",\"version\":\"1\",\"wasmContentHash\":\"") +
          ch +
          "\",\"supportedConstraintKinds\":[],\"capabilitiesRequired\":[],"
          "\"publisher\":\"acme\",\"description\":\"d\"}",
      &m2, &err));
  EXPECT_EQ(m2.publisher, std::string("acme"));
  EXPECT_EQ(m2.description, std::string("d"));
}

TEST(ModuleRuntimeHostTest, Manifest_RejectsMalformed) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest m;
  std::string err;
  auto reject = [&](const std::string& json) {
    return !ParseModuleManifest(json, &m, &err) && !m.valid;
  };
  // Missing each required field.
  EXPECT_TRUE(reject(std::string("{\"version\":\"1\",\"wasmContentHash\":\"") +
                     ch +
                     "\",\"supportedConstraintKinds\":[],"
                     "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"wasmContentHash\":\"") + ch +
                     "\",\"supportedConstraintKinds\":[],"
                     "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(
      "{\"name\":\"n\",\"version\":\"1\",\"supportedConstraintKinds\":[],"
      "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch + "\",\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch + "\",\"supportedConstraintKinds\":[]}"));
  // Malformed content hash.
  EXPECT_TRUE(
      reject("{\"name\":\"n\",\"version\":\"1\",\"wasmContentHash\":\"sha256-xy"
             "\",\"supportedConstraintKinds\":[],\"capabilitiesRequired\":[]}"));
  // Wrong-typed array fields.
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch +
                     "\",\"supportedConstraintKinds\":\"nope\","
                     "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch +
                     "\",\"supportedConstraintKinds\":[],"
                     "\"capabilitiesRequired\":[1,2]}"));
}

TEST(ModuleRuntimeHostTest, Manifest_BindsContentHash) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest m;
  std::string err;
  EXPECT_TRUE(ParseModuleManifest(
      ModManifest("n", "1", ch, {"capability"}, {"graph.read"}), &m, &err));
  EXPECT_TRUE(ManifestBindsContentHash(m, ch));
  EXPECT_FALSE(ManifestBindsContentHash(m, ModContentHash(kModWasmB)));
  EXPECT_FALSE(ManifestBindsContentHash(m, std::string()));
}

// ---- §7.1 installation ----

TEST(ModuleRuntimeHostTest, Install_VerifiesContentHashAndCaps) {
  ModuleGraphAdapter mgraph;
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);
  const std::string ch = ModContentHash(kModWasmA);

  // A manifest that binds the exact binary installs, consent pending (§7.2).
  auto ok = rt.Install(
      kModWasmA, ModManifest("m", "1", ch, {"capability"}, {"graph.read"}));
  EXPECT_TRUE(ok.ok);
  EXPECT_EQ(ok.content_hash, ch);
  EXPECT_TRUE(rt.IsInstalled(ch));
  EXPECT_TRUE(rt.ConsentOf(ch) == ConsentDecision::kPending);

  // A manifest binding a DIFFERENT binary is rejected (§8.2/§9.2).
  auto wrong = rt.Install(
      kModWasmA, ModManifest("m", "1", ModContentHash(kModWasmB), {"capability"},
                             {"graph.read"}));
  EXPECT_FALSE(wrong.ok);
  EXPECT_TRUE(wrong.error == HostError::kInvalidArgument);

  // An unknown capability token is rejected at install (§7.1 step 3).
  auto badcap = rt.Install(
      kModWasmB, ModManifest("m", "1", ModContentHash(kModWasmB), {"capability"},
                             {"graph.read", "totally.made.up"}));
  EXPECT_FALSE(badcap.ok);
  EXPECT_TRUE(badcap.error == HostError::kInvalidArgument);
}

// ---- §7.2 consent gates instantiation and every surface ----

TEST(ModuleRuntimeHostTest, Consent_GatesInstantiationAndSurfaces) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"}, {"graph.read"}))
          .ok);

  // Instantiation before consent is not-authorised (§7.2).
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"})
                  .error == HostError::kNotAuthorised);

  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"})
                  .ok);
  EXPECT_TRUE(rt.ReaderSnapshot(ch, "space://s", "did:graph:g1").ok);

  // Revoking consent immediately closes the surfaces (§8.3 — no forging past).
  EXPECT_TRUE(rt.DenyConsent(ch));
  EXPECT_TRUE(rt.ReaderSnapshot(ch, "space://s", "did:graph:g1").error ==
              HostError::kNotAuthorised);
}

// ---- §6.3 host-graph: capability + scope + real read/write ----

TEST(ModuleRuntimeHostTest, HostGraph_CapabilityScopeAndRealIO) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(rt.Install(kModWasmA,
                         ModManifest("m", "1", ch, {"capability"},
                                     {"graph.read", "graph.write"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  // Write a real diff through the writer surface; it lands in Oxigraph.
  GraphDiff diff;
  diff.graph_did = "did:graph:g1";
  DiffTriple dt;
  dt.triple = MakeLit("urn:note:1", "https://schema.org/name", "Hello");
  diff.additions.push_back(dt);
  EXPECT_TRUE(rt.WriterApply(ch, "space://s", "did:graph:g1", diff).ok);

  // Read it back through the reader surface.
  auto q = rt.ReaderQueryTriples(ch, "space://s", "did:graph:g1", TripleQuery{});
  EXPECT_TRUE(q.ok);
  EXPECT_EQ(q.value.size(), size_t(1));
  EXPECT_EQ(q.value[0].subject, std::string("urn:note:1"));

  // Snapshot and SPARQL are equally real.
  auto snap = rt.ReaderSnapshot(ch, "space://s", "did:graph:g1");
  EXPECT_TRUE(snap.ok);
  EXPECT_EQ(snap.value.size(), size_t(1));
  auto sr = rt.ReaderQuerySparql(ch, "space://s", "did:graph:g1",
                                 "SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }");
  EXPECT_TRUE(sr.ok);
  EXPECT_GT(sr.value.size(), size_t(0));

  // A graph outside the authorised set is unknown-scope (§5.3), not a read.
  EXPECT_TRUE(
      rt.ReaderQueryTriples(ch, "space://s", "did:graph:other", TripleQuery{})
          .error == HostError::kUnknownScope);
}

TEST(ModuleRuntimeHostTest, HostGraph_WriteRequiresGrant) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);
  const std::string ch = ModContentHash(kModWasmA);
  // graph.read only — no graph.write.
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"}, {"graph.read"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  GraphDiff diff;
  diff.graph_did = "did:graph:g1";
  DiffTriple dt;
  dt.triple = MakeLit("urn:x", "urn:p", "v");
  diff.additions.push_back(dt);
  EXPECT_TRUE(rt.WriterApply(ch, "space://s", "did:graph:g1", diff).error ==
              HostError::kNotAuthorised);
}

// ---- §5.4 / §9.7 scoped signer ----
//
// The browser host-crypto backing (ModuleCryptoAdapter) signs "on behalf of the
// local agent" (§5.4) — the DIDKeyProvider's active credential — so the signer
// is the realm's active "Human" credential and the verify surface checks against
// its DID (unlike the standalone harness, which uses a separate signer provider).

TEST(ModuleRuntimeHostTest, ScopedSigner_CommitLedgerAndVerify) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleCryptoAdapter mcrypto(&id);
  ModuleRuntimeHost rt(&mgraph, &mcrypto, nullptr);
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(rt.Install(kModWasmA,
                         ModManifest("m", "1", ch, {"capability"},
                                     {"crypto.commit-sign", "crypto.verify"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  const std::string commit_id =
      ToLowerHex(crypto::SHA256HashString("commit-payload-1"));

  // §9.7: a commit-id the module never built cannot be signed.
  EXPECT_TRUE(rt.SignCommit(ch, "space://s", "did:graph:g1", commit_id).error ==
              HostError::kSigningRefused);

  // The runtime observes module.commit build the diff → the id becomes eligible.
  EXPECT_TRUE(rt.RecordCommit(ch, "space://s", "did:graph:g1", commit_id).ok);
  auto sig = rt.SignCommit(ch, "space://s", "did:graph:g1", commit_id);
  EXPECT_TRUE(sig.ok);
  EXPECT_EQ(sig.value.signature.size(), size_t(64));

  // The signature verifies over the commit-id via the verify surface, against
  // the active credential's DID (the §5.4 local agent).
  std::vector<uint8_t> msg(commit_id.begin(), commit_id.end());
  auto ver = rt.Verify(ch, "space://s", msg, sig.value,
                       id.GetActiveCredential()->did);
  EXPECT_TRUE(ver.ok);
  EXPECT_TRUE(ver.value);

  // Recording against a non-authorised graph is unknown-scope; signing a
  // commit for a graph it was not built on stays refused (exhaustive shapes).
  EXPECT_TRUE(
      rt.RecordCommit(ch, "space://s", "did:graph:other", commit_id).error ==
      HostError::kUnknownScope);
  EXPECT_TRUE(rt.SignCommit(ch, "space://s", "did:graph:other", commit_id)
                  .error == HostError::kSigningRefused);
}

TEST(ModuleRuntimeHostTest, ScopedSigner_SignalGatedByCapability) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleCryptoAdapter mcrypto(&id);
  const std::string ch = ModContentHash(kModWasmA);

  // Without crypto.signal-sign the signal signer is not-authorised.
  ModuleRuntimeHost ro(&mgraph, &mcrypto, nullptr);
  EXPECT_TRUE(ro.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                {"crypto.commit-sign"}))
                  .ok);
  EXPECT_TRUE(ro.GrantConsent(ch));
  EXPECT_TRUE(
      ro.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(ro.SignSignal(ch, "space://s", "did:key:peer", {1, 2, 3}).error ==
              HostError::kNotAuthorised);

  // With it, a signal envelope is signed.
  ModuleRuntimeHost rw(&mgraph, &mcrypto, nullptr);
  EXPECT_TRUE(rw.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                {"crypto.signal-sign"}))
                  .ok);
  EXPECT_TRUE(rw.GrantConsent(ch));
  EXPECT_TRUE(
      rw.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  auto s = rw.SignSignal(ch, "space://s", "did:key:peer", {1, 2, 3});
  EXPECT_TRUE(s.ok);
  EXPECT_EQ(s.value.signature.size(), size_t(64));
}

// ---- §8.1 host-storage: quota + per-(module,graph) isolation ----

TEST(ModuleRuntimeHostTest, HostStorage_QuotaScopeAndIsolation) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);

  const std::string chA = ModContentHash(kModWasmA);
  const std::string chB = ModContentHash(kModWasmB);
  EXPECT_TRUE(rt.Install(kModWasmA, ModManifest("A", "1", chA, {"capability"},
                                                {"storage.module.64"}))
                  .ok);
  EXPECT_TRUE(rt.Install(kModWasmB, ModManifest("B", "1", chB, {"capability"},
                                                {"storage.module.64"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(chA));
  EXPECT_TRUE(rt.GrantConsent(chB));
  EXPECT_TRUE(
      rt.Instantiate(chA, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(
      rt.Instantiate(chB, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  // Within the 64-byte cap ("k"=1 + 63 value = 64): accepted.
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "k",
                            std::vector<uint8_t>(63, 'x'))
                  .ok);
  auto got = rt.StorageGet(chA, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(got.ok);
  EXPECT_TRUE(got.value.has_value());
  EXPECT_EQ(got.value->size(), size_t(63));

  // One more byte exceeds the declared cap (§8.1).
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "k",
                            std::vector<uint8_t>(64, 'y'))
                  .error == HostError::kQuotaExceeded);

  // Module B shares the graph but sees NONE of A's keys (§9.5 isolation).
  auto b = rt.StorageGet(chB, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(b.ok);
  EXPECT_FALSE(b.value.has_value());

  // Storage outside the authorised graph set is unknown-scope.
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:other", "k", {1})
                  .error == HostError::kUnknownScope);

  // Delete frees the accounting so subsequent writes fit; list-keys honours
  // the prefix filter. "k" (64 bytes) must be released before "p1" + "big"
  // (3 + 53 = 56 bytes) can be admitted under the 64-byte cap.
  EXPECT_TRUE(rt.StorageDelete(chA, "space://s", "did:graph:g1", "k").ok);
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "p1", {1}).ok);
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "big",
                            std::vector<uint8_t>(50, 'z'))
                  .ok);
  auto keys = rt.StorageListKeys(chA, "space://s", "did:graph:g1",
                                 std::optional<std::string>("p"));
  EXPECT_TRUE(keys.ok);
  EXPECT_EQ(keys.value.size(), size_t(1));
  EXPECT_EQ(keys.value[0], std::string("p1"));
}

// ---- §6.3 host-network: capability gating over a loopback transport ----

TEST(ModuleRuntimeHostTest, HostNetwork_GatingAndTransport) {
  LoopbackNetwork net;
  ModuleRuntimeHost rt(nullptr, nullptr, &net);
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"},
                             {"network.relay.wss://relay.example/hub",
                              "network.peer.lw-sync/1",
                              "network.fetch.https://cdn.example/"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {}).ok);

  // Granted relay endpoint: a live connection with real send/receive/close.
  auto conn = rt.NetworkConnect(ch, "space://s", "wss://relay.example/hub",
                                RelayProtocol::kWebSocket);
  EXPECT_TRUE(conn.ok);
  HostError se = HostError::kNone;
  EXPECT_TRUE(conn.value->Send({7, 8, 9}, &se));
  std::vector<uint8_t> rx;
  bool closed = true;
  HostError re = HostError::kNone;
  EXPECT_TRUE(conn.value->Receive(&rx, &closed, &re));
  EXPECT_EQ(rx.size(), size_t(3));
  EXPECT_FALSE(closed);
  conn.value->Close();
  EXPECT_FALSE(conn.value->IsOpen());

  // Un-granted relay endpoint: not-authorised.
  EXPECT_TRUE(rt.NetworkConnect(ch, "space://s", "wss://evil.example/",
                                RelayProtocol::kWebSocket)
                  .error == HostError::kNotAuthorised);

  // Peer protocol match / mismatch.
  EXPECT_TRUE(rt.PeerConnect(ch, "space://s", "did:key:peer", "lw-sync/1").ok);
  EXPECT_TRUE(rt.PeerConnect(ch, "space://s", "did:key:peer", "other/9").error ==
              HostError::kNotAuthorised);

  // Fetch is origin-scoped: same origin ok, foreign origin denied.
  auto f = rt.Fetch(ch, "space://s", "https://cdn.example/model.bin");
  EXPECT_TRUE(f.ok);
  EXPECT_GT(f.value.size(), size_t(0));
  EXPECT_TRUE(rt.Fetch(ch, "space://s", "https://evil.example/x").error ==
              HostError::kNotAuthorised);
}

// ---- §6.3 host-clock / host-random gating ----

TEST(ModuleRuntimeHostTest, HostClockRandom_GatingAndCoarsening) {
  ModuleRuntimeHost rt(nullptr, nullptr, nullptr);
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"},
                             {"time.wallclock", "time.monotonic",
                              "random.csprng"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {}).ok);

  auto wc = rt.NowWallclockMs(ch, "space://s");
  EXPECT_TRUE(wc.ok);
  EXPECT_EQ(wc.value % 1000, uint64_t(0));  // §8 coarsened to 1s
  EXPECT_TRUE(rt.NowMonotonicNs(ch, "space://s").ok);
  auto rnd = rt.GetRandomBytes(ch, "space://s", 16);
  EXPECT_TRUE(rnd.ok);
  EXPECT_EQ(rnd.value.size(), size_t(16));

  // A module without these grants is denied on every clock/random surface.
  const std::string ch2 = ModContentHash(kModWasmB);
  EXPECT_TRUE(
      rt.Install(kModWasmB,
                 ModManifest("m", "1", ch2, {"capability"}, {"graph.read"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch2));
  EXPECT_TRUE(rt.Instantiate(ch2, "space://s", "did:key:local", {}).ok);
  EXPECT_TRUE(rt.NowWallclockMs(ch2, "space://s").error ==
              HostError::kNotAuthorised);
  EXPECT_TRUE(rt.NowMonotonicNs(ch2, "space://s").error ==
              HostError::kNotAuthorised);
  EXPECT_TRUE(rt.GetRandomBytes(ch2, "space://s", 8).error ==
              HostError::kNotAuthorised);
}

// ---- §7.4 / §7.5 lifecycle: suspend, resume, remove (stores preserved) ----

TEST(ModuleRuntimeHostTest, Lifecycle_SuspendResumeRemovePreservesStores) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(rt.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                {"storage.module.128"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(rt.StorageSet(ch, "space://s", "did:graph:g1", "k",
                            std::vector<uint8_t>{1, 2, 3, 4})
                  .ok);

  // §7.5 suspension stops surface activity.
  EXPECT_TRUE(rt.Suspend(ch, "space://s").ok);
  EXPECT_TRUE(rt.StorageGet(ch, "space://s", "did:graph:g1", "k").error ==
              HostError::kNotAuthorised);
  // Resume restores it without re-instantiation.
  EXPECT_TRUE(rt.Resume(ch, "space://s").ok);
  auto got = rt.StorageGet(ch, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(got.ok);
  EXPECT_TRUE(got.value.has_value());

  // §7.4 removal drops instances + grants but PRESERVES the per-graph store.
  EXPECT_TRUE(rt.Remove(ch));
  EXPECT_FALSE(rt.IsInstalled(ch));
  EXPECT_EQ(rt.InstanceCount(), size_t(0));

  // Re-install + re-consent + re-mount: the preserved store is still there.
  EXPECT_TRUE(rt.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                {"storage.module.128"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  auto revived = rt.StorageGet(ch, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(revived.ok);
  EXPECT_TRUE(revived.value.has_value());
  EXPECT_EQ(revived.value->size(), size_t(4));

  // Purging after the grace period truly clears it.
  EXPECT_TRUE(rt.PurgeStorage(ch, "did:graph:g1"));
  EXPECT_FALSE(
      rt.StorageGet(ch, "space://s", "did:graph:g1", "k").value.has_value());
}

// ---- §7.3 fork constraint-kind superset precondition ----

TEST(ModuleRuntimeHostTest, Fork_ConstraintKindSuperset) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest child;
  std::string err;
  EXPECT_TRUE(ParseModuleManifest(
      ModManifest("child", "2", ch, {"capability", "expiry", "shape"},
                  {"graph.read"}),
      &child, &err));

  std::vector<std::string> missing;
  // Child supports a superset of the parent's in-force kinds → compatible.
  EXPECT_TRUE(ModuleRuntimeHost::ForkCompatible(child, {"capability", "expiry"},
                                                &missing));
  EXPECT_TRUE(missing.empty());

  // A kind the child lacks blocks the fork and is reported.
  EXPECT_FALSE(ModuleRuntimeHost::ForkCompatible(child, {"capability", "geo"},
                                                 &missing));
  EXPECT_EQ(missing.size(), size_t(1));
  EXPECT_EQ(missing[0], std::string("geo"));
}

// ---- §4.4 instancing + §7.6 introspection ----

TEST(ModuleRuntimeHostTest, Instancing_PerSpaceScope) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  AddBoundGraph(&graphs, &mgraph, "did:graph:g2");
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                        {"graph.read", "storage.module.64"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));

  // One instance per (content-hash, space-uri); each carries its own scope.
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://A", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://B", "did:key:local", {"did:graph:g2"}).ok);
  EXPECT_EQ(rt.InstanceCount(), size_t(2));

  // Space A cannot reach graph g2 (authorised only in space B).
  EXPECT_TRUE(
      rt.ReaderQueryTriples(ch, "space://A", "did:graph:g2", TripleQuery{})
          .error == HostError::kUnknownScope);
  EXPECT_TRUE(
      rt.ReaderQueryTriples(ch, "space://B", "did:graph:g2", TripleQuery{}).ok);
}

TEST(ModuleRuntimeHostTest, ListModules_Introspection) {
  DIDKeyProvider id;
  id.CreateKey("Human");
  GraphBackendManager graphs(&id);
  ModuleGraphAdapter mgraph;
  AddBoundGraph(&graphs, &mgraph, "did:graph:g1");
  ModuleRuntimeHost rt(&mgraph, nullptr, nullptr);
  const std::string chA = ModContentHash(kModWasmA);
  const std::string chB = ModContentHash(kModWasmB);
  EXPECT_TRUE(
      rt.Install(kModWasmA, ModManifest("Alpha", "1", chA, {"capability"},
                                        {"storage.module.128"}))
          .ok);
  EXPECT_TRUE(
      rt.Install(kModWasmB,
                 ModManifest("Beta", "1", chB, {"capability"}, {"graph.read"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(chA));  // Beta stays pending

  EXPECT_TRUE(
      rt.Instantiate(chA, "space://A", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(
      rt.Instantiate(chA, "space://B", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(rt.StorageSet(chA, "space://A", "did:graph:g1", "k",
                            std::vector<uint8_t>(10, 'a'))
                  .ok);

  bool saw_alpha = false, saw_beta = false;
  for (const ModuleStatus& s : rt.ListModules()) {
    if (s.content_hash == chA) {
      saw_alpha = true;
      EXPECT_TRUE(s.consent == ConsentDecision::kGranted);
      EXPECT_EQ(s.space_count, size_t(2));
      EXPECT_GT(s.storage_bytes, uint64_t(0));
      EXPECT_EQ(s.name, std::string("Alpha"));
    } else if (s.content_hash == chB) {
      saw_beta = true;
      EXPECT_TRUE(s.consent == ConsentDecision::kPending);
      EXPECT_EQ(s.space_count, size_t(0));
    }
  }
  EXPECT_TRUE(saw_alpha);
  EXPECT_TRUE(saw_beta);
}

}  // namespace
}  // namespace content
