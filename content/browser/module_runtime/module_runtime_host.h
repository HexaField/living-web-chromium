// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// ModuleRuntimeHost — the browser-process Sync Module runtime (Spec 06).
//
// A faithful C++ port of living_web::ModuleRuntime (standalone/
// module_runtime_provider.h) onto the browser cores: content::GraphBackend (the
// Spec 02 host graph authority host-graph reads/writes), content::DIDKeyProvider
// (the scoped Ed25519 signer host-crypto is constituted over), and the network
// service (the host-network transport). The two ports share the Chromium-
// independent byte-critical cores content/browser/module_runtime/
// module_capabilities.{h,cc} (the §8 capability algebra) and module_manifest.{h,cc}
// (the §4.2 content-addressing + §8.2 manifest) verbatim with the standalone
// conformance harness, so every grant / scope / quota / signing decision — the
// bytes the sandbox enforces — is identical between the two build worlds.
//
// The runtime owns the §7 lifecycle and the seven §6.3 host-import surfaces
// (host-graph, host-crypto, host-network, host-clock, host-random, host-storage,
// host-log). It performs EVERY grant/scope/quota/signing decision itself — that
// enforcement is the spec — and only delegates the actual I/O to an injected
// backend once a decision has been made:
//
//   * §7.1 installation: SHA-256 content-hash verification (§9.2) via
//     crypto::SHA256HashString and manifest binding (§8.2), rejecting a binary
//     whose hash the manifest does not embed;
//   * §7.2 consent: no host surface is reachable before the user grants consent
//     for the module's content hash;
//   * §4.4 instancing: one instance per (content-hash, space-uri); module-private
//     storage keyed by (content-hash, graph-did), isolated between modules (§9.5);
//   * §8 / §8.3 capability gating on every surface — `not-authorised` when the
//     grant is absent, `unknown-scope` when the graph/space is outside the
//     authorised set — so a module cannot forge its way past a denial;
//   * §8.1 storage quota (`quota-exceeded`) from the declared storage.module.<size>;
//   * §5.4 / §9.7 scoped signing: commit-bundle and signal-envelope signatures
//     only, only for authorised graphs/spaces, only for a commit-id the module
//     actually built (`signing-refused` otherwise);
//   * §7.4 removal (preserving the per-graph stores for the §8.1 grace period)
//     and §7.5 suspension/resume;
//   * §7.3 fork constraint-kind superset precondition (ConstraintKindsCompatible).
//
// PersonalGraphManager owns one ModuleRuntimeHost per realm and reads its
// installed-module inventory for §6.4 GraphManager.listModules().

#ifndef CONTENT_BROWSER_MODULE_RUNTIME_MODULE_RUNTIME_HOST_H_
#define CONTENT_BROWSER_MODULE_RUNTIME_MODULE_RUNTIME_HOST_H_

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/module_runtime/module_capabilities.h"
#include "content/browser/module_runtime/module_manifest.h"

namespace content {

// The content-addressed triple-set delta a writer module applies (Spec 05
// §5.2). Declared in content/browser/graph_sync/sync_backend.h; forward-declared
// here because the module runtime only ever forwards a `const GraphDiff&` down to
// the injected HostGraphBackend — it never inspects the struct's fields, so the
// heavy sync_backend.h include stays out of this header (only the concrete graph
// adapter .cc, which walks diff.additions / diff.removals, pulls it in).
struct GraphDiff;

// ---- result<T, host-error> (§6.3) ------------------------------------------

// A fallible host-import result. `ok` distinguishes success (carrying `value`)
// from a `host-error` (§6.3). Mirrors the WIT `result<T, host-error>`; the error
// vocabulary is the Chromium-independent living_web::HostError shared core.
template <typename T>
struct HostResult {
  bool ok = false;
  living_web::HostError error = living_web::HostError::kInternal;
  T value{};

  static HostResult Success(T v) {
    HostResult r;
    r.ok = true;
    r.error = living_web::HostError::kNone;
    r.value = std::move(v);
    return r;
  }
  static HostResult Fail(living_web::HostError e) {
    HostResult r;
    r.ok = false;
    r.error = e;
    return r;
  }
};

// The void-valued form (`result<_, host-error>`).
struct HostStatus {
  bool ok = false;
  living_web::HostError error = living_web::HostError::kNone;

  static HostStatus Success() { return {true, living_web::HostError::kNone}; }
  static HostStatus Fail(living_web::HostError e) { return {false, e}; }
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
// re-check authorisation. In the browser this resolves `graph_did` to the
// content::GraphBackend the realm holds (module_runtime_backends.h).
class HostGraphBackend {
 public:
  virtual ~HostGraphBackend() = default;
  virtual bool QueryTriples(const std::string& graph_did,
                            const TripleQuery& query,
                            std::vector<living_web::Triple>* out,
                            std::string* err) = 0;
  virtual bool QuerySparql(const std::string& graph_did,
                           const std::string& sparql,
                           std::string* out,
                           std::string* err) = 0;
  virtual bool Snapshot(const std::string& graph_did,
                        std::vector<living_web::Triple>* out,
                        std::string* err) = 0;
  virtual bool Apply(const std::string& graph_did,
                     const GraphDiff& diff,
                     std::string* err) = 0;
};

// `host-crypto` backing (§5.4): the scoped Ed25519 signer/verifier. Key material
// never crosses into module memory; the runtime hands the backend only the
// exhaustive shapes §9.7 permits (a commit-id or a signal envelope). The runtime
// has already checked the capability grant and (for commit) the built-commit
// ledger before calling. In the browser this wraps content::DIDKeyProvider.
class HostCryptoBackend {
 public:
  virtual ~HostCryptoBackend() = default;
  virtual bool SignCommit(const std::string& graph_did,
                          const std::string& commit_id,
                          HostSigned* out,
                          std::string* err) = 0;
  virtual bool SignSignal(const std::string& space_uri,
                          const std::string& local_did,
                          const std::string& remote_did,
                          const std::vector<uint8_t>& payload,
                          HostSigned* out,
                          std::string* err) = 0;
  virtual bool Verify(const std::vector<uint8_t>& message,
                      const HostSigned& signature,
                      const std::string& public_key,
                      bool* valid) = 0;
};

// An open relay or peer transport (§6.3 `network-connection` / `peer-connection`).
// The module reads/writes framed messages; framing above the byte stream is the
// module's own protocol. Dropping/closing the handle closes the connection. In
// the browser this wraps a network-service WebTransport/WebSocket session.
class HostConnection {
 public:
  virtual ~HostConnection() = default;
  virtual bool Send(const std::vector<uint8_t>& message,
                    living_web::HostError* err) = 0;
  // Receives the next frame. On a clean close sets |*closed| = true and returns
  // true with |*out| empty; on error returns false and sets |*err|.
  virtual bool Receive(std::vector<uint8_t>* out,
                       bool* closed,
                       living_web::HostError* err) = 0;
  virtual bool IsOpen() const = 0;
  virtual void Close() = 0;
};

// `host-network` backing (§5.4): opens capability-gated transports. The runtime
// checks the network.relay/peer/fetch grant before calling; the backend performs
// the actual connect/fetch (the network service in the browser) and returns a
// `network-error` on transport failure.
class HostNetworkBackend {
 public:
  virtual ~HostNetworkBackend() = default;
  // Returns an open connection (owned by the backend) or nullptr + |*err|.
  virtual HostConnection* Connect(const std::string& endpoint,
                                  RelayProtocol protocol,
                                  living_web::HostError* err) = 0;
  virtual HostConnection* PeerConnect(const std::string& remote_did,
                                      const std::string& protocol,
                                      living_web::HostError* err) = 0;
  virtual bool Fetch(const std::string& url,
                     std::vector<uint8_t>* out,
                     living_web::HostError* err) = 0;
};

// ---- lifecycle enums / status ----------------------------------------------

enum class ConsentDecision { kPending, kGranted, kDenied };  // §7.2

// Mirrors the mojom ModuleState surfaced by SyncModuleInfo (Spec 05 seam). The
// graph::mojom::ModuleState conversion lives in the PersonalGraphManager port.
enum class ModuleRuntimeState { kRunning, kSuspended, kError };

// §7.6 management-UI / Spec 05 listModules() view of one installed module.
struct ModuleStatus {
  std::string content_hash;
  std::string name;
  ConsentDecision consent = ConsentDecision::kPending;
  ModuleRuntimeState state = ModuleRuntimeState::kRunning;
  size_t space_count = 0;      // live instances (one per space, §4.4)
  uint64_t storage_bytes = 0;  // total across this module's per-graph stores
};

// A diagnostic sink for host-log (§6.3). Absent = discard.
using ModuleLogSink =
    base::RepeatingCallback<void(const std::string& content_hash,
                                 LogLevel,
                                 const std::string& message)>;

// ---- the runtime -----------------------------------------------------------

class ModuleRuntimeHost {
 public:
  // The three backends are not owned; they outlive the host (PersonalGraphManager
  // owns both). |log_sink| MAY be null.
  ModuleRuntimeHost(HostGraphBackend* graph,
                    HostCryptoBackend* crypto,
                    HostNetworkBackend* network,
                    ModuleLogSink log_sink = ModuleLogSink());

  ModuleRuntimeHost(const ModuleRuntimeHost&) = delete;
  ModuleRuntimeHost& operator=(const ModuleRuntimeHost&) = delete;

  ~ModuleRuntimeHost();

  // ---- §7.1 installation --------------------------------------------------

  struct InstallResult {
    bool ok = false;
    std::string content_hash;  // the module's §4.2 identity (== manifest binding)
    living_web::HostError error = living_web::HostError::kNone;
    std::string message;
  };

  // §7.1 steps 1–3 + capability extraction: compute the binary's §4.2 content
  // hash (crypto::SHA256HashString), parse the §8.2 manifest, verify the manifest
  // binds that exact binary (§8.2, §9.2), and require every declared capability
  // token to be a known §8 kind (§7.1). On success registers the module with
  // consent `kPending` (awaiting §7.2). Idempotent per content hash: re-installing
  // refreshes the record but preserves any prior consent decision.
  InstallResult Install(const std::string& wasm_binary,
                        const std::string& manifest_json);

  // ---- §7.2 consent -------------------------------------------------------

  bool GrantConsent(const std::string& content_hash);
  bool DenyConsent(const std::string& content_hash);
  ConsentDecision ConsentOf(const std::string& content_hash) const;

  // ---- §4.4 instancing ----------------------------------------------------

  // §7.1 step 5 / §4.4: instantiate one instance per (content-hash, space-uri).
  // Requires the module installed with consent granted; else `not-authorised`.
  // |authorised_graph_dids| are the graphs the space carries — the §5.3 scope the
  // module may read/write and sign for. Idempotent per pair.
  HostStatus Instantiate(const std::string& content_hash,
                         const std::string& space_uri,
                         const std::string& local_did,
                         const std::vector<std::string>& authorised_graph_dids);

  HostStatus Connect(const std::string& content_hash,
                     const std::string& space_uri);
  HostStatus Disconnect(const std::string& content_hash,
                        const std::string& space_uri);

  // ---- §7.5 suspension ----------------------------------------------------

  HostStatus Suspend(const std::string& content_hash,
                     const std::string& space_uri);
  HostStatus Resume(const std::string& content_hash,
                    const std::string& space_uri);

  // ---- §7.4 removal -------------------------------------------------------

  // Drops every instance of the module and its binary + capability grants. The
  // per-graph module stores are PRESERVED (§8.1 grace period). True iff installed.
  bool Remove(const std::string& content_hash);

  // Purge a preserved per-graph store after the §8.1 grace period expires.
  bool PurgeStorage(const std::string& content_hash,
                    const std::string& graph_did);

  // ---- §7.3 fork precondition ---------------------------------------------

  // §7.3 / §8.2 ([[GROUP-IDENTITY]] §4.8.1 step 2): a fork may name |child| as its
  // module only if child.supportedConstraintKinds ⊇ the parent's in-force kinds.
  static bool ForkCompatible(
      const living_web::ModuleManifest& child,
      const std::vector<std::string>& parent_in_force_kinds,
      std::vector<std::string>* missing);

  // ---- module.commit driver (runtime side of the §5.1 export) -------------

  // Records that the module's `commit` export produced a diff with |commit_id|
  // for |graph_did|, making it eligible for host-crypto.sign-commit (§5.4/§9.7).
  // A runtime-internal driver, NOT a host import a module can call.
  HostStatus RecordCommit(const std::string& content_hash,
                          const std::string& space_uri,
                          const std::string& graph_did,
                          const std::string& commit_id);

  // ---- §6.3 host-graph ----------------------------------------------------

  HostResult<std::vector<living_web::Triple>> ReaderQueryTriples(
      const std::string& content_hash,
      const std::string& space_uri,
      const std::string& graph_did,
      const TripleQuery& query);
  HostResult<std::string> ReaderQuerySparql(const std::string& content_hash,
                                            const std::string& space_uri,
                                            const std::string& graph_did,
                                            const std::string& sparql);
  HostResult<std::vector<living_web::Triple>> ReaderSnapshot(
      const std::string& content_hash,
      const std::string& space_uri,
      const std::string& graph_did);
  HostStatus WriterApply(const std::string& content_hash,
                         const std::string& space_uri,
                         const std::string& graph_did,
                         const GraphDiff& diff);

  // ---- §6.3 host-crypto (§5.4, §9.7 scoped signer) ------------------------

  HostResult<HostSigned> SignCommit(const std::string& content_hash,
                                    const std::string& space_uri,
                                    const std::string& graph_did,
                                    const std::string& commit_id);
  HostResult<HostSigned> SignSignal(const std::string& content_hash,
                                    const std::string& space_uri,
                                    const std::string& remote_did,
                                    const std::vector<uint8_t>& payload);
  HostResult<bool> Verify(const std::string& content_hash,
                          const std::string& space_uri,
                          const std::vector<uint8_t>& message,
                          const HostSigned& signature,
                          const std::string& public_key);

  // ---- §6.3 host-network (§5.4) -------------------------------------------

  HostResult<HostConnection*> NetworkConnect(const std::string& content_hash,
                                             const std::string& space_uri,
                                             const std::string& endpoint,
                                             RelayProtocol protocol);
  HostResult<HostConnection*> PeerConnect(const std::string& content_hash,
                                          const std::string& space_uri,
                                          const std::string& remote_did,
                                          const std::string& protocol);
  HostResult<std::vector<uint8_t>> Fetch(const std::string& content_hash,
                                         const std::string& space_uri,
                                         const std::string& url);

  // ---- §6.3 host-clock ----------------------------------------------------

  HostResult<uint64_t> NowWallclockMs(const std::string& content_hash,
                                      const std::string& space_uri);
  HostResult<uint64_t> NowMonotonicNs(const std::string& content_hash,
                                      const std::string& space_uri);

  // ---- §6.3 host-random ---------------------------------------------------

  HostResult<std::vector<uint8_t>> GetRandomBytes(const std::string& content_hash,
                                                  const std::string& space_uri,
                                                  uint32_t len);

  // ---- §6.3 host-storage (§8.1; keyed by (content-hash, graph-did)) --------

  HostResult<std::optional<std::vector<uint8_t>>> StorageGet(
      const std::string& content_hash,
      const std::string& space_uri,
      const std::string& graph_did,
      const std::string& key);
  HostStatus StorageSet(const std::string& content_hash,
                        const std::string& space_uri,
                        const std::string& graph_did,
                        const std::string& key,
                        const std::vector<uint8_t>& value);
  HostStatus StorageDelete(const std::string& content_hash,
                           const std::string& space_uri,
                           const std::string& graph_did,
                           const std::string& key);
  HostResult<std::vector<std::string>> StorageListKeys(
      const std::string& content_hash,
      const std::string& space_uri,
      const std::string& graph_did,
      const std::optional<std::string>& prefix);

  // ---- §6.3 host-log (no capability gate) ---------------------------------

  void Log(const std::string& content_hash,
           const std::string& space_uri,
           LogLevel level,
           const std::string& message);

  // ---- introspection (§7.6 management UI / Spec 05 listModules()) ----------

  bool IsInstalled(const std::string& content_hash) const;
  size_t InstanceCount() const;
  const living_web::ModuleManifest* ManifestOf(
      const std::string& content_hash) const;
  std::vector<ModuleStatus> ListModules() const;

 private:
  struct InstalledModule {
    bool registered = false;
    std::string content_hash;
    living_web::ModuleManifest manifest;
    std::string wasm_binary;
    living_web::CapabilitySet capabilities;
    ConsentDecision consent = ConsentDecision::kPending;
  };

  struct ModuleInstance {
    bool live = false;
    std::string content_hash;
    std::string space_uri;
    std::string local_did;
    std::set<std::string> authorised_graphs;  // §5.3 scope
    bool connected = false;
    ModuleRuntimeState state = ModuleRuntimeState::kRunning;
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
                                 const std::string& space_uri);
  static std::string StoreKey(const std::string& content_hash,
                              const std::string& graph_did);
  static std::string StoreKeyPrefix(const std::string& content_hash);

  // A live instance regardless of running/suspended state (connect, resume, log).
  ModuleInstance* LiveInstance(const std::string& content_hash,
                               const std::string& space_uri);

  // A running instance of a consented module — the precondition for every host
  // surface. Sets |*err| to `not-authorised` when the module/instance is absent,
  // consent is not granted, or the instance is suspended (§7.5).
  ModuleInstance* RunningInstance(const std::string& content_hash,
                                  const std::string& space_uri,
                                  living_web::HostError* err);

  const living_web::CapabilitySet& Caps(const ModuleInstance* inst) const;

  raw_ptr<HostGraphBackend> graph_;      // Not owned.
  raw_ptr<HostCryptoBackend> crypto_;    // Not owned.
  raw_ptr<HostNetworkBackend> network_;  // Not owned.
  ModuleLogSink log_sink_;

  std::map<std::string, InstalledModule> modules_;   // content-hash → module
  std::map<std::string, ModuleInstance> instances_;  // (hash,space) → instance
  std::map<std::string, ModuleStore> stores_;        // (hash,graph) → store
};

}  // namespace content

#endif  // CONTENT_BROWSER_MODULE_RUNTIME_MODULE_RUNTIME_HOST_H_
