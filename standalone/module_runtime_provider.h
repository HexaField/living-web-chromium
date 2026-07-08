// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Standalone Sync Module Runtime host (Spec 06).
//
// This header-only host is the Chromium-independent mirror of the browser
// module runtime (content/browser/module_runtime/module_runtime_host.*). It
// composes the two shared cores — the §8 capability algebra of
// module_capabilities.{h,cc} and the §4.2/§8.2 manifest + content-addressing of
// module_manifest.{h,cc} — into the full §7 module lifecycle and the seven §6.3
// host-import surfaces (`host-graph`, `host-crypto`, `host-network`,
// `host-clock`, `host-random`, `host-storage`, `host-log`).
//
// What it enforces, normatively (the Chromium-independent host contract):
//   * §7.1 installation: SHA-256 content-hash verification (§9.2) and manifest
//     binding (§8.2), rejecting a binary whose hash the manifest does not embed;
//   * §7.2 consent: no host surface is reachable before the user grants consent
//     for the module's content hash;
//   * §4.4 instancing: one instance per (content-hash, space-uri); module-private
//     storage keyed by (content-hash, graph-did), isolated between modules (§9.5);
//   * §8 / §8.3 capability gating on EVERY surface — `not-authorised` when the
//     grant is absent, `unknown-scope` when the graph/space is outside the
//     authorised set — so a module cannot forge its way past a denial;
//   * §8.1 storage quota (`quota-exceeded`) from the declared
//     `storage.module.<size>` cap;
//   * §5.4 / §9.7 scoped signing: the signer produces commit-bundle and
//     signal-envelope signatures only, only for authorised graphs/spaces, only
//     for a commit-id the module actually built (`signing-refused` otherwise);
//   * §7.4 removal (disconnect, unmount, drop grants — preserving the per-graph
//     stores for the §8.1 grace period) and §7.5 suspension/resume;
//   * §7.3 fork constraint-kind superset precondition (delegated to the manifest
//     core's ConstraintKindsCompatible).
//
// World-specific primitives are injected (ModuleRuntimeDeps): the SHA-256 hash,
// the graph read/write backend, the scoped Ed25519 crypto backend, the network
// transport, the wall/monotonic clocks, and the CSPRNG. The standalone harness
// backs these with real Oxigraph graphs, real Ed25519, a real clock and a real
// CSPRNG; the browser backs them with content/browser/graph, //crypto, the
// identity service, and the network service (§6.1). The runtime performs every
// grant/scope/quota decision itself — that enforcement is the spec — and only
// delegates the actual I/O once a decision has been made.

#ifndef LIVING_WEB_MODULE_RUNTIME_PROVIDER_H_
#define LIVING_WEB_MODULE_RUNTIME_PROVIDER_H_

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "content/browser/module_runtime/module_capabilities.h"
#include "content/browser/module_runtime/module_manifest.h"
#include "graph_provider.h"
#include "sync_provider.h"

namespace living_web {

// ---- result<T, host-error> (§6.3) ------------------------------------------

// A fallible host-import result. `ok` distinguishes success (carrying `value`)
// from a `host-error` (§6.3). Mirrors the WIT `result<T, host-error>`.
template <typename T>
struct HostResult {
  bool ok = false;
  HostError error = HostError::kInternal;
  T value{};

  static HostResult Success(T v) {
    HostResult r;
    r.ok = true;
    r.error = HostError::kNone;
    r.value = std::move(v);
    return r;
  }
  static HostResult Fail(HostError e) {
    HostResult r;
    r.ok = false;
    r.error = e;
    return r;
  }
};

// The void-valued form (`result<_, host-error>`).
struct HostStatus {
  bool ok = false;
  HostError error = HostError::kNone;

  static HostStatus Success() { return {true, HostError::kNone}; }
  static HostStatus Fail(HostError e) { return {false, e}; }
};

// ---- host-crypto `signed` record (§6.3) ------------------------------------

// A signature plus the verification method (a DID URL) that produced it.
struct HostSigned {
  std::vector<uint8_t> signature;
  std::string verification_method;  // DID URL of the signing key
};

// ---- host-network wire protocol (§6.3) -------------------------------------

enum class RelayProtocol { kWebTransport, kWebSocket };

// ---- host-log level (§6.3) -------------------------------------------------

enum class LogLevel { kTrace, kDebug, kInfo, kWarn, kError };

// ---- injected world-specific backends --------------------------------------

// `host-graph` backing (§5.3): real graph read/write over the graphs a module
// serves. The runtime calls these only AFTER the graph.read / graph.write grant
// and the authorised-graph scope check pass, so an implementation need not
// re-check authorisation. `err` receives a human-readable reason on failure.
class HostGraphBackend {
 public:
  virtual ~HostGraphBackend() = default;
  virtual bool QueryTriples(const std::string& graph_did,
                            const TripleQuery& query,
                            std::vector<Triple>* out,
                            std::string* err) = 0;
  virtual bool QuerySparql(const std::string& graph_did,
                           const std::string& sparql,
                           std::string* out,
                           std::string* err) = 0;
  virtual bool Snapshot(const std::string& graph_did,
                        std::vector<Triple>* out,
                        std::string* err) = 0;
  virtual bool Apply(const std::string& graph_did,
                     const GraphDiff& diff,
                     std::string* err) = 0;
};

// `host-crypto` backing (§5.4): the scoped Ed25519 signer/verifier. Key material
// never crosses into module memory; the runtime hands the backend only the
// exhaustive shapes §9.7 permits (a commit-id or a signal envelope). The runtime
// has already checked the capability grant and (for commit) the built-commit
// ledger before calling.
class HostCryptoBackend {
 public:
  virtual ~HostCryptoBackend() = default;
  // Sign the commit-bundle message for |graph_did| (the module's authorised
  // graph) — BuildSignatureMessage(commit_id).
  virtual bool SignCommit(const std::string& graph_did,
                          const std::string& commit_id,
                          HostSigned* out,
                          std::string* err) = 0;
  // Sign a signal envelope bound to (space_uri, local_did, remote_did, payload).
  virtual bool SignSignal(const std::string& space_uri,
                          const std::string& local_did,
                          const std::string& remote_did,
                          const std::vector<uint8_t>& payload,
                          HostSigned* out,
                          std::string* err) = 0;
  // Pure verification; no key material. |public_key| is a multibase key or DID
  // URL. Sets |*valid|.
  virtual bool Verify(const std::vector<uint8_t>& message,
                      const HostSigned& signature,
                      const std::string& public_key,
                      bool* valid) = 0;
};

// An open relay or peer transport (§6.3 `network-connection` / `peer-connection`).
// The module reads/writes framed messages; framing above the byte stream is the
// module's own protocol. Dropping/closing the handle closes the connection.
class HostConnection {
 public:
  virtual ~HostConnection() = default;
  virtual bool Send(const std::vector<uint8_t>& message, HostError* err) = 0;
  // Receives the next frame. On a clean close sets |*closed| = true and returns
  // true with |*out| empty; on error returns false and sets |*err|.
  virtual bool Receive(std::vector<uint8_t>* out,
                       bool* closed,
                       HostError* err) = 0;
  virtual bool IsOpen() const = 0;
  virtual void Close() = 0;
};

// `host-network` backing (§5.4): opens capability-gated transports. The runtime
// checks the network.relay/peer/fetch grant before calling; the backend performs
// the actual connect/fetch (a real transport in the browser; an in-process
// loopback/registry in the standalone harness) and returns a `network-error` via
// |*err| on transport failure.
class HostNetworkBackend {
 public:
  virtual ~HostNetworkBackend() = default;
  // Returns an open connection (owned by the backend) or nullptr + |*err|.
  virtual HostConnection* Connect(const std::string& endpoint,
                                  RelayProtocol protocol,
                                  HostError* err) = 0;
  virtual HostConnection* PeerConnect(const std::string& remote_did,
                                      const std::string& protocol,
                                      HostError* err) = 0;
  virtual bool Fetch(const std::string& url,
                     std::vector<uint8_t>* out,
                     HostError* err) = 0;
};

// The injected primitives the runtime delegates to once a grant decision is made.
struct ModuleRuntimeDeps {
  // Raw 32-byte SHA-256 digest of the argument (the world-specific hash: OpenSSL
  // in the harness, //crypto in the browser). REQUIRED for §7.1 installation.
  std::function<std::string(const std::string&)> sha256_raw;
  HostGraphBackend* graph = nullptr;       // §5.3
  HostCryptoBackend* crypto = nullptr;     // §5.4
  HostNetworkBackend* network = nullptr;   // §5.4
  std::function<uint64_t()> now_wallclock_ms;   // time.wallclock (raw, ms)
  std::function<uint64_t()> now_monotonic_ns;   // time.monotonic (ns)
  std::function<std::vector<uint8_t>(uint32_t)> random_bytes;  // random.csprng
  // Optional sink for host-log; absent = discard.
  std::function<void(const std::string& content_hash,
                     LogLevel,
                     const std::string& message)>
      log_sink;
};

// ---- lifecycle enums -------------------------------------------------------

enum class ConsentDecision { kPending, kGranted, kDenied };  // §7.2

// Mirrors the mojom ModuleState surfaced by SyncModuleInfo (Spec 05 seam).
enum class ModuleState { kRunning, kSuspended, kError };

// §7.6 management-UI / Spec 05 listModules() view of one installed module.
struct ModuleStatus {
  std::string content_hash;
  std::string name;
  ConsentDecision consent = ConsentDecision::kPending;
  ModuleState state = ModuleState::kRunning;
  size_t space_count = 0;      // live instances (one per space, §4.4)
  uint64_t storage_bytes = 0;  // total across this module's per-graph stores
};

// ---- the runtime -----------------------------------------------------------

class ModuleRuntime {
 public:
  explicit ModuleRuntime(ModuleRuntimeDeps deps) : deps_(std::move(deps)) {}

  ModuleRuntime(const ModuleRuntime&) = delete;
  ModuleRuntime& operator=(const ModuleRuntime&) = delete;

  const std::string& last_error() const { return last_error_; }

  // ---- §7.1 installation --------------------------------------------------

  struct InstallResult {
    bool ok = false;
    std::string content_hash;  // the module's §4.2 identity (== manifest binding)
    HostError error = HostError::kNone;
    std::string message;
  };

  // §7.1 steps 1–3 + capability extraction: compute the binary's §4.2 content
  // hash, parse the §8.2 manifest, verify the manifest binds that exact binary
  // (§8.2, §9.2), and require every declared capability token to be a known §8
  // kind (§7.1). On success registers the module with consent `kPending`
  // (awaiting §7.2). Re-installing the same hash refreshes the record but
  // preserves any prior consent decision. Idempotent per content hash.
  InstallResult Install(const std::string& wasm_binary,
                        const std::string& manifest_json) {
    InstallResult r;
    if (!deps_.sha256_raw) {
      r.error = HostError::kInternal;
      r.message = "runtime: no SHA-256 primitive configured";
      return r;
    }
    const std::string computed =
        FormatModuleContentHash(deps_.sha256_raw(wasm_binary));
    r.content_hash = computed;

    ModuleManifest manifest;
    std::string perr;
    if (!ParseModuleManifest(manifest_json, &manifest, &perr)) {
      r.error = HostError::kInvalidArgument;
      r.message = perr;
      return r;
    }
    if (!ManifestBindsContentHash(manifest, computed)) {
      r.error = HostError::kInvalidArgument;
      r.message =
          "manifest wasmContentHash does not bind the supplied WASM binary "
          "(§8.2/§9.2)";
      return r;
    }
    CapabilitySet caps = CapabilitySet::FromManifest(manifest.capabilities_required);
    if (!caps.AllKnown()) {
      r.error = HostError::kInvalidArgument;
      r.message = "manifest requires an unknown capability token (§7.1)";
      return r;
    }

    InstalledModule& m = modules_[computed];
    ConsentDecision prior = m.registered ? m.consent : ConsentDecision::kPending;
    m.registered = true;
    m.content_hash = computed;
    m.manifest = manifest;
    m.wasm_binary = wasm_binary;
    m.capabilities = caps;
    m.consent = prior;

    r.ok = true;
    return r;
  }

  // ---- §7.2 consent -------------------------------------------------------

  bool GrantConsent(const std::string& content_hash) {
    auto it = modules_.find(content_hash);
    if (it == modules_.end())
      return false;
    it->second.consent = ConsentDecision::kGranted;
    return true;
  }
  bool DenyConsent(const std::string& content_hash) {
    auto it = modules_.find(content_hash);
    if (it == modules_.end())
      return false;
    it->second.consent = ConsentDecision::kDenied;
    return true;
  }
  ConsentDecision ConsentOf(const std::string& content_hash) const {
    auto it = modules_.find(content_hash);
    return it == modules_.end() ? ConsentDecision::kPending : it->second.consent;
  }

  // ---- §4.4 instancing ----------------------------------------------------

  // §7.1 step 5 / §4.4: instantiate one instance per (content-hash, space-uri).
  // Requires the module installed with consent granted; else `not-authorised`.
  // |authorised_graph_dids| are the graphs the space carries — the module may
  // read/write and sign only for these (the §5.3 scope). Idempotent per pair:
  // a second call updates the authorised set and resets the instance to running.
  HostStatus Instantiate(const std::string& content_hash,
                         const std::string& space_uri,
                         const std::string& local_did,
                         const std::vector<std::string>& authorised_graph_dids) {
    auto it = modules_.find(content_hash);
    if (it == modules_.end() ||
        it->second.consent != ConsentDecision::kGranted) {
      return HostStatus::Fail(HostError::kNotAuthorised);
    }
    ModuleInstance& inst = instances_[InstanceKey(content_hash, space_uri)];
    inst.live = true;
    inst.content_hash = content_hash;
    inst.space_uri = space_uri;
    inst.local_did = local_did;
    inst.authorised_graphs.clear();
    for (const std::string& g : authorised_graph_dids)
      inst.authorised_graphs.insert(g);
    inst.state = ModuleState::kRunning;
    inst.connected = false;
    return HostStatus::Success();
  }

  // module.connect / disconnect (§5.1). Presence in the space; idempotent.
  HostStatus Connect(const std::string& content_hash,
                     const std::string& space_uri) {
    ModuleInstance* inst = LiveInstance(content_hash, space_uri);
    if (!inst)
      return HostStatus::Fail(HostError::kNotAuthorised);
    inst->connected = true;
    return HostStatus::Success();
  }
  HostStatus Disconnect(const std::string& content_hash,
                        const std::string& space_uri) {
    ModuleInstance* inst = LiveInstance(content_hash, space_uri);
    if (!inst)
      return HostStatus::Fail(HostError::kNotAuthorised);
    inst->connected = false;
    return HostStatus::Success();
  }

  // ---- §7.5 suspension ----------------------------------------------------

  HostStatus Suspend(const std::string& content_hash,
                     const std::string& space_uri) {
    ModuleInstance* inst = LiveInstance(content_hash, space_uri);
    if (!inst)
      return HostStatus::Fail(HostError::kNotAuthorised);
    inst->state = ModuleState::kSuspended;
    return HostStatus::Success();
  }
  HostStatus Resume(const std::string& content_hash,
                    const std::string& space_uri) {
    auto it = instances_.find(InstanceKey(content_hash, space_uri));
    if (it == instances_.end() || !it->second.live)
      return HostStatus::Fail(HostError::kNotAuthorised);
    it->second.state = ModuleState::kRunning;
    return HostStatus::Success();
  }

  // ---- §7.4 removal -------------------------------------------------------

  // Disconnects and drops every instance of the module and removes its binary
  // and capability grants. The per-graph module stores are PRESERVED (§8.1
  // grace period): a subsequent re-install + re-mount can revert. Returns true
  // iff the module was installed.
  bool Remove(const std::string& content_hash) {
    if (!modules_.count(content_hash))
      return false;
    for (auto it = instances_.begin(); it != instances_.end();) {
      if (it->second.content_hash == content_hash)
        it = instances_.erase(it);
      else
        ++it;
    }
    modules_.erase(content_hash);
    return true;
  }

  // Purge a preserved per-graph store after the §8.1 grace period expires.
  // Returns true iff a store existed for (content_hash, graph_did).
  bool PurgeStorage(const std::string& content_hash,
                    const std::string& graph_did) {
    return stores_.erase(StoreKey(content_hash, graph_did)) != 0;
  }

  // ---- §7.3 fork precondition ---------------------------------------------

  // §7.3 / §8.2 ([[GROUP-IDENTITY]] §4.8.1 step 2): a fork may name |child|
  // as its module only if child.supportedConstraintKinds ⊇ the parent's in-force
  // kinds. |missing| (when non-null) receives the kinds that block the fork.
  static bool ForkCompatible(const ModuleManifest& child,
                             const std::vector<std::string>& parent_in_force_kinds,
                             std::vector<std::string>* missing) {
    return ConstraintKindsCompatible(child.supported_constraint_kinds,
                                     parent_in_force_kinds, missing);
  }

  // ---- module.commit driver (runtime side of the §5.1 export) -------------

  // Records that the module's `commit` export produced |diff| for |graph_did|,
  // making its commit-id eligible for host-crypto.sign-commit (§5.4/§9.7). In a
  // real component runtime the host observes the diff the module builds when it
  // drives `module.commit`; the harness invokes this to represent that
  // observation. Requires the graph to be in the instance's authorised set;
  // else `unknown-scope`. This is a runtime-internal driver, NOT a host import a
  // module can call.
  HostStatus RecordCommit(const std::string& content_hash,
                          const std::string& space_uri,
                          const std::string& graph_did,
                          const std::string& commit_id) {
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return HostStatus::Fail(err);
    if (!inst->authorised_graphs.count(graph_did))
      return HostStatus::Fail(HostError::kUnknownScope);
    inst->built_commits[graph_did].insert(commit_id);
    return HostStatus::Success();
  }

  // ---- §6.3 host-graph ----------------------------------------------------

  HostResult<std::vector<Triple>> ReaderQueryTriples(
      const std::string& content_hash,
      const std::string& space_uri,
      const std::string& graph_did,
      const TripleQuery& query) {
    using R = HostResult<std::vector<Triple>>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsGraphRead())
      return R::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return R::Fail(HostError::kUnknownScope);
    if (!deps_.graph)
      return R::Fail(HostError::kInternal);
    std::vector<Triple> out;
    std::string e;
    if (!deps_.graph->QueryTriples(graph_did, query, &out, &e))
      return R::Fail(HostError::kInvalidArgument);
    return R::Success(std::move(out));
  }

  HostResult<std::string> ReaderQuerySparql(const std::string& content_hash,
                                            const std::string& space_uri,
                                            const std::string& graph_did,
                                            const std::string& sparql) {
    using R = HostResult<std::string>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsGraphRead())
      return R::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return R::Fail(HostError::kUnknownScope);
    if (!deps_.graph)
      return R::Fail(HostError::kInternal);
    std::string out, e;
    if (!deps_.graph->QuerySparql(graph_did, sparql, &out, &e))
      return R::Fail(HostError::kInvalidArgument);
    return R::Success(std::move(out));
  }

  HostResult<std::vector<Triple>> ReaderSnapshot(const std::string& content_hash,
                                                 const std::string& space_uri,
                                                 const std::string& graph_did) {
    using R = HostResult<std::vector<Triple>>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsGraphRead())
      return R::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return R::Fail(HostError::kUnknownScope);
    if (!deps_.graph)
      return R::Fail(HostError::kInternal);
    std::vector<Triple> out;
    std::string e;
    if (!deps_.graph->Snapshot(graph_did, &out, &e))
      return R::Fail(HostError::kInvalidArgument);
    return R::Success(std::move(out));
  }

  HostStatus WriterApply(const std::string& content_hash,
                         const std::string& space_uri,
                         const std::string& graph_did,
                         const GraphDiff& diff) {
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return HostStatus::Fail(err);
    if (!Caps(inst).AllowsGraphWrite())
      return HostStatus::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return HostStatus::Fail(HostError::kUnknownScope);
    if (!deps_.graph)
      return HostStatus::Fail(HostError::kInternal);
    std::string e;
    if (!deps_.graph->Apply(graph_did, diff, &e))
      return HostStatus::Fail(HostError::kInvalidArgument);
    return HostStatus::Success();
  }

  // ---- §6.3 host-crypto (§5.4, §9.7 scoped signer) ------------------------

  HostResult<HostSigned> SignCommit(const std::string& content_hash,
                                    const std::string& space_uri,
                                    const std::string& graph_did,
                                    const std::string& commit_id) {
    using R = HostResult<HostSigned>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsCommitSign())
      return R::Fail(HostError::kNotAuthorised);
    // §5.4/§9.7: the signer signs a commit-id only for an authorised graph and
    // only when it corresponds to a diff the module actually built. Both a
    // non-authorised graph and an unknown commit-id are `signing-refused` — the
    // signer's accepted shapes are exhaustive, so it cannot be repurposed.
    auto git = inst->built_commits.find(graph_did);
    if (git == inst->built_commits.end() || !git->second.count(commit_id))
      return R::Fail(HostError::kSigningRefused);
    if (!deps_.crypto)
      return R::Fail(HostError::kInternal);
    HostSigned sig;
    std::string e;
    if (!deps_.crypto->SignCommit(graph_did, commit_id, &sig, &e))
      return R::Fail(HostError::kSigningRefused);
    return R::Success(std::move(sig));
  }

  HostResult<HostSigned> SignSignal(const std::string& content_hash,
                                    const std::string& space_uri,
                                    const std::string& remote_did,
                                    const std::vector<uint8_t>& payload) {
    using R = HostResult<HostSigned>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsSignalSign())
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.crypto)
      return R::Fail(HostError::kInternal);
    HostSigned sig;
    std::string e;
    if (!deps_.crypto->SignSignal(inst->space_uri, inst->local_did, remote_did,
                                  payload, &sig, &e)) {
      return R::Fail(HostError::kSigningRefused);
    }
    return R::Success(std::move(sig));
  }

  HostResult<bool> Verify(const std::string& content_hash,
                          const std::string& space_uri,
                          const std::vector<uint8_t>& message,
                          const HostSigned& signature,
                          const std::string& public_key) {
    using R = HostResult<bool>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsVerify())
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.crypto)
      return R::Fail(HostError::kInternal);
    bool valid = false;
    if (!deps_.crypto->Verify(message, signature, public_key, &valid))
      return R::Fail(HostError::kInvalidArgument);
    return R::Success(valid);
  }

  // ---- §6.3 host-network (§5.4) -------------------------------------------

  HostResult<HostConnection*> NetworkConnect(const std::string& content_hash,
                                             const std::string& space_uri,
                                             const std::string& endpoint,
                                             RelayProtocol protocol) {
    using R = HostResult<HostConnection*>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsRelay(endpoint))
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.network)
      return R::Fail(HostError::kInternal);
    HostError nerr = HostError::kNetworkError;
    HostConnection* c = deps_.network->Connect(endpoint, protocol, &nerr);
    if (!c)
      return R::Fail(nerr);
    return R::Success(c);
  }

  HostResult<HostConnection*> PeerConnect(const std::string& content_hash,
                                          const std::string& space_uri,
                                          const std::string& remote_did,
                                          const std::string& protocol) {
    using R = HostResult<HostConnection*>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsPeer(protocol))
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.network)
      return R::Fail(HostError::kInternal);
    HostError nerr = HostError::kNetworkError;
    HostConnection* c = deps_.network->PeerConnect(remote_did, protocol, &nerr);
    if (!c)
      return R::Fail(nerr);
    return R::Success(c);
  }

  HostResult<std::vector<uint8_t>> Fetch(const std::string& content_hash,
                                         const std::string& space_uri,
                                         const std::string& url) {
    using R = HostResult<std::vector<uint8_t>>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsFetch(url))
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.network)
      return R::Fail(HostError::kInternal);
    std::vector<uint8_t> out;
    HostError nerr = HostError::kNetworkError;
    if (!deps_.network->Fetch(url, &out, &nerr))
      return R::Fail(nerr);
    return R::Success(std::move(out));
  }

  // ---- §6.3 host-clock ----------------------------------------------------

  HostResult<uint64_t> NowWallclockMs(const std::string& content_hash,
                                      const std::string& space_uri) {
    using R = HostResult<uint64_t>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsWallclock())
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.now_wallclock_ms)
      return R::Fail(HostError::kInternal);
    // §8 fingerprinting countermeasure: coarsen to 1-second resolution.
    uint64_t ms = deps_.now_wallclock_ms();
    return R::Success((ms / 1000) * 1000);
  }

  HostResult<uint64_t> NowMonotonicNs(const std::string& content_hash,
                                      const std::string& space_uri) {
    using R = HostResult<uint64_t>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsMonotonic())
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.now_monotonic_ns)
      return R::Fail(HostError::kInternal);
    return R::Success(deps_.now_monotonic_ns());
  }

  // ---- §6.3 host-random ---------------------------------------------------

  HostResult<std::vector<uint8_t>> GetRandomBytes(const std::string& content_hash,
                                                  const std::string& space_uri,
                                                  uint32_t len) {
    using R = HostResult<std::vector<uint8_t>>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).AllowsCsprng())
      return R::Fail(HostError::kNotAuthorised);
    if (!deps_.random_bytes)
      return R::Fail(HostError::kInternal);
    return R::Success(deps_.random_bytes(len));
  }

  // ---- §6.3 host-storage (§8.1; keyed by (content-hash, graph-did)) --------

  HostResult<std::optional<std::vector<uint8_t>>> StorageGet(
      const std::string& content_hash,
      const std::string& space_uri,
      const std::string& graph_did,
      const std::string& key) {
    using R = HostResult<std::optional<std::vector<uint8_t>>>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).HasStorage())
      return R::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return R::Fail(HostError::kUnknownScope);
    auto sit = stores_.find(StoreKey(content_hash, graph_did));
    if (sit == stores_.end())
      return R::Success(std::nullopt);
    auto kit = sit->second.entries.find(key);
    if (kit == sit->second.entries.end())
      return R::Success(std::nullopt);
    return R::Success(std::vector<uint8_t>(kit->second.begin(), kit->second.end()));
  }

  HostStatus StorageSet(const std::string& content_hash,
                        const std::string& space_uri,
                        const std::string& graph_did,
                        const std::string& key,
                        const std::vector<uint8_t>& value) {
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return HostStatus::Fail(err);
    if (!Caps(inst).HasStorage())
      return HostStatus::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return HostStatus::Fail(HostError::kUnknownScope);
    ModuleStore& store = stores_[StoreKey(content_hash, graph_did)];
    const uint64_t quota = Caps(inst).StorageQuotaBytes();
    // §8.1: reject a write that would exceed the declared cap. Accounting counts
    // key + value bytes per entry; replacing a key frees its previous size.
    uint64_t projected = store.bytes;
    auto existing = store.entries.find(key);
    if (existing != store.entries.end())
      projected -= (key.size() + existing->second.size());
    projected += key.size() + value.size();
    if (projected > quota)
      return HostStatus::Fail(HostError::kQuotaExceeded);
    store.bytes = projected;
    store.entries[key] = std::string(value.begin(), value.end());
    return HostStatus::Success();
  }

  HostStatus StorageDelete(const std::string& content_hash,
                           const std::string& space_uri,
                           const std::string& graph_did,
                           const std::string& key) {
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return HostStatus::Fail(err);
    if (!Caps(inst).HasStorage())
      return HostStatus::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return HostStatus::Fail(HostError::kUnknownScope);
    auto sit = stores_.find(StoreKey(content_hash, graph_did));
    if (sit != stores_.end()) {
      auto kit = sit->second.entries.find(key);
      if (kit != sit->second.entries.end()) {
        sit->second.bytes -= (key.size() + kit->second.size());
        sit->second.entries.erase(kit);
      }
    }
    return HostStatus::Success();  // §6.3: no error if the key was absent
  }

  HostResult<std::vector<std::string>> StorageListKeys(
      const std::string& content_hash,
      const std::string& space_uri,
      const std::string& graph_did,
      const std::optional<std::string>& prefix) {
    using R = HostResult<std::vector<std::string>>;
    HostError err = HostError::kNone;
    ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
    if (!inst)
      return R::Fail(err);
    if (!Caps(inst).HasStorage())
      return R::Fail(HostError::kNotAuthorised);
    if (!inst->authorised_graphs.count(graph_did))
      return R::Fail(HostError::kUnknownScope);
    std::vector<std::string> keys;
    auto sit = stores_.find(StoreKey(content_hash, graph_did));
    if (sit != stores_.end()) {
      for (const auto& kv : sit->second.entries) {
        if (!prefix || kv.first.compare(0, prefix->size(), *prefix) == 0)
          keys.push_back(kv.first);
      }
    }
    return R::Success(std::move(keys));
  }

  // ---- §6.3 host-log (no capability gate) ---------------------------------

  void Log(const std::string& content_hash,
           const std::string& space_uri,
           LogLevel level,
           const std::string& message) {
    // Only a live instance may log; the surface is otherwise ungated (§6.3).
    if (!LiveInstance(content_hash, space_uri))
      return;
    if (deps_.log_sink)
      deps_.log_sink(content_hash, level, message);
  }

  // ---- introspection (§7.6 management UI / Spec 05 listModules()) ----------

  bool IsInstalled(const std::string& content_hash) const {
    return modules_.count(content_hash) != 0;
  }

  size_t InstanceCount() const {
    size_t n = 0;
    for (const auto& kv : instances_)
      if (kv.second.live)
        ++n;
    return n;
  }

  const ModuleManifest* ManifestOf(const std::string& content_hash) const {
    auto it = modules_.find(content_hash);
    return it == modules_.end() ? nullptr : &it->second.manifest;
  }

  std::vector<ModuleStatus> ListModules() const {
    std::vector<ModuleStatus> out;
    out.reserve(modules_.size());
    for (const auto& mkv : modules_) {
      const InstalledModule& m = mkv.second;
      ModuleStatus s;
      s.content_hash = m.content_hash;
      s.name = m.manifest.name;
      s.consent = m.consent;

      size_t spaces = 0;
      bool any_error = false, any_running = false, any_suspended = false;
      for (const auto& ikv : instances_) {
        if (!ikv.second.live || ikv.second.content_hash != m.content_hash)
          continue;
        ++spaces;
        switch (ikv.second.state) {
          case ModuleState::kError: any_error = true; break;
          case ModuleState::kRunning: any_running = true; break;
          case ModuleState::kSuspended: any_suspended = true; break;
        }
      }
      s.space_count = spaces;
      s.state = any_error ? ModuleState::kError
                : any_running ? ModuleState::kRunning
                : any_suspended ? ModuleState::kSuspended
                                : ModuleState::kRunning;  // installed & idle

      uint64_t bytes = 0;
      const std::string sep = StoreKeyPrefix(m.content_hash);
      for (const auto& skv : stores_) {
        if (skv.first.compare(0, sep.size(), sep) == 0)
          bytes += skv.second.bytes;
      }
      s.storage_bytes = bytes;
      out.push_back(std::move(s));
    }
    return out;
  }

 private:
  struct InstalledModule {
    bool registered = false;
    std::string content_hash;
    ModuleManifest manifest;
    std::string wasm_binary;
    CapabilitySet capabilities;
    ConsentDecision consent = ConsentDecision::kPending;
  };

  struct ModuleInstance {
    bool live = false;
    std::string content_hash;
    std::string space_uri;
    std::string local_did;
    std::set<std::string> authorised_graphs;  // §5.3 scope
    bool connected = false;
    ModuleState state = ModuleState::kRunning;
    // §5.4/§9.7: commit-ids the module built via module.commit, per graph — the
    // only commit-ids the scoped signer will sign.
    std::map<std::string, std::set<std::string>> built_commits;
  };

  struct ModuleStore {
    std::map<std::string, std::string> entries;  // key → raw value bytes
    uint64_t bytes = 0;                          // key+value bytes accounted
  };

  static constexpr char kSep = '\x1f';  // ASCII unit separator (key delimiter)

  static std::string InstanceKey(const std::string& content_hash,
                                 const std::string& space_uri) {
    return content_hash + kSep + space_uri;
  }
  static std::string StoreKey(const std::string& content_hash,
                              const std::string& graph_did) {
    return content_hash + kSep + graph_did;
  }
  static std::string StoreKeyPrefix(const std::string& content_hash) {
    return content_hash + kSep;
  }

  // A live instance regardless of running/suspended state (for connect, resume,
  // log). Returns nullptr when no such instance exists.
  ModuleInstance* LiveInstance(const std::string& content_hash,
                               const std::string& space_uri) {
    auto it = instances_.find(InstanceKey(content_hash, space_uri));
    if (it == instances_.end() || !it->second.live)
      return nullptr;
    return &it->second;
  }

  // A running instance of a consented module — the precondition for every host
  // surface. Sets |*err|: `not-authorised` when the module/instance is absent,
  // consent is not granted, or the instance is suspended (§7.5 stops surface
  // activity).
  ModuleInstance* RunningInstance(const std::string& content_hash,
                                  const std::string& space_uri,
                                  HostError* err) {
    auto mit = modules_.find(content_hash);
    if (mit == modules_.end() ||
        mit->second.consent != ConsentDecision::kGranted) {
      *err = HostError::kNotAuthorised;
      return nullptr;
    }
    ModuleInstance* inst = LiveInstance(content_hash, space_uri);
    if (!inst || inst->state != ModuleState::kRunning) {
      *err = HostError::kNotAuthorised;
      return nullptr;
    }
    return inst;
  }

  const CapabilitySet& Caps(const ModuleInstance* inst) const {
    return modules_.at(inst->content_hash).capabilities;
  }

  ModuleRuntimeDeps deps_;
  std::map<std::string, InstalledModule> modules_;   // content-hash → module
  std::map<std::string, ModuleInstance> instances_;  // (hash,space) → instance
  std::map<std::string, ModuleStore> stores_;        // (hash,graph) → store
  std::string last_error_;
};

}  // namespace living_web

#endif  // LIVING_WEB_MODULE_RUNTIME_PROVIDER_H_
