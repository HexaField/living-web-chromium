// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The concrete browser backings for the §6.3 host imports the module runtime
// mediates (content/browser/module_runtime/module_runtime_host.h). The runtime
// itself makes every grant / scope / quota / signing decision above these
// adapters, byte-for-byte as standalone/module_runtime_provider.h does; the
// adapters only carry an already-authorised operation down to the realm's real
// Spec 02 graph store and Spec 01 signer. They are the browser analogues of the
// harness backends (standalone/living_web_tests.cc ModGraphBackend /
// ModCryptoBackend) and delegate verbatim, so a module observes exactly the
// graph and the keys the rest of the realm does.
//
// The host-network backing is deliberately absent from this branch: a real relay
// / peer transport is asynchronous, and delivering it to a module requires the
// WebAssembly Component Model execution engine's task-suspension bridge (Spec 06
// §6.2), which no browser seam wires up yet. PersonalGraphManager therefore
// constructs the runtime with a null network backend; the runtime already
// answers every network import with `internal` when it is null (spec-faithful,
// covered by the standalone conformance harness), and no code path reaches it
// because no module executes. See SPEC_COMPLIANCE (Spec 06) for the layering.

#ifndef CONTENT_BROWSER_MODULE_RUNTIME_MODULE_RUNTIME_BACKENDS_H_
#define CONTENT_BROWSER_MODULE_RUNTIME_MODULE_RUNTIME_BACKENDS_H_

#include <map>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/module_runtime/module_runtime_host.h"

namespace content {

class DIDKeyProvider;

// host-graph backing (§6.3) over the realm's live Spec 02 graphs. The runtime
// addresses a graph by its DID (§5.2); GraphBackendManager keys backends by
// their internal id, so this adapter keeps the graph-DID -> live-backend binding
// the runtime needs and delegates queryTriples / querySparql / snapshot / apply
// straight to the resolved GraphBackend. The bindings are maintained by
// PersonalGraphManager as graphs are mounted and unmounted (§6.2).
class ModuleGraphAdapter : public HostGraphBackend {
 public:
  ModuleGraphAdapter();
  ModuleGraphAdapter(const ModuleGraphAdapter&) = delete;
  ModuleGraphAdapter& operator=(const ModuleGraphAdapter&) = delete;
  ~ModuleGraphAdapter() override;

  // Binds (or rebinds) a graph DID to the live backend that stands in for it.
  // The backend is owned by GraphBackendManager and MUST outlive the binding;
  // the matching Unbind() runs before the backend is dropped (§6.2 unmount).
  void Bind(const std::string& graph_did, GraphBackend* backend);
  void Unbind(const std::string& graph_did);

  // HostGraphBackend:
  bool QueryTriples(const std::string& graph_did,
                    const TripleQuery& query,
                    std::vector<living_web::Triple>* out,
                    std::string* err) override;
  bool QuerySparql(const std::string& graph_did,
                   const std::string& sparql,
                   std::string* out,
                   std::string* err) override;
  bool Snapshot(const std::string& graph_did,
                std::vector<living_web::Triple>* out,
                std::string* err) override;
  bool Apply(const std::string& graph_did,
             const GraphDiff& diff,
             std::string* err) override;

 private:
  // The live backend bound to |graph_did|, or nullptr (sets |*err|) if the graph
  // is not mounted in this realm.
  GraphBackend* Resolve(const std::string& graph_did, std::string* err);

  std::map<std::string, raw_ptr<GraphBackend>> by_did_;
};

// host-crypto backing (§5.4, §9.7): the scoped Ed25519 signer/verifier over the
// realm's Spec 01 DIDKeyProvider. It signs "on behalf of the local agent"
// (§5.4) — the provider's active credential — and never lets key material cross
// into module memory; the runtime has already checked the capability grant and
// the built-commit ledger before calling. A faithful browser port of the harness
// ModCryptoBackend: identical pre-images, identical verify path.
class ModuleCryptoAdapter : public HostCryptoBackend {
 public:
  explicit ModuleCryptoAdapter(DIDKeyProvider* identity);
  ModuleCryptoAdapter(const ModuleCryptoAdapter&) = delete;
  ModuleCryptoAdapter& operator=(const ModuleCryptoAdapter&) = delete;
  ~ModuleCryptoAdapter() override;

  // HostCryptoBackend:
  bool SignCommit(const std::string& graph_did,
                  const std::string& commit_id,
                  HostSigned* out,
                  std::string* err) override;
  bool SignSignal(const std::string& space_uri,
                  const std::string& local_did,
                  const std::string& remote_did,
                  const std::vector<uint8_t>& payload,
                  HostSigned* out,
                  std::string* err) override;
  bool Verify(const std::vector<uint8_t>& message,
              const HostSigned& signature,
              const std::string& public_key,
              bool* valid) override;

 private:
  raw_ptr<DIDKeyProvider> identity_;  // Not owned; outlives this adapter.
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODULE_RUNTIME_MODULE_RUNTIME_BACKENDS_H_
