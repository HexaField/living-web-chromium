// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/module_runtime/module_runtime_host.h"

#include <utility>

#include "base/time/time.h"
#include "crypto/random.h"
#include "crypto/sha2.h"

namespace content {

// The browser port differs from the standalone provider only in where the
// world-specific primitives come from: the §4.2 content hash is
// crypto::SHA256HashString (the same SHA-256 backing every other browser core),
// the §6.3 host-clock reads base::Time / base::TimeTicks, and host-random draws
// from crypto::RandBytesAsVector (the platform CSPRNG). Every grant / scope /
// quota / signing decision is made here, above the injected graph / crypto /
// network backends, byte-for-byte as standalone/module_runtime_provider.h makes
// it — that enforcement is the spec, so it must not diverge between the two
// build worlds.

ModuleRuntimeHost::ModuleRuntimeHost(HostGraphBackend* graph,
                                     HostCryptoBackend* crypto,
                                     HostNetworkBackend* network,
                                     ModuleLogSink log_sink)
    : graph_(graph),
      crypto_(crypto),
      network_(network),
      log_sink_(std::move(log_sink)) {}

ModuleRuntimeHost::~ModuleRuntimeHost() = default;

// ---- key helpers -----------------------------------------------------------

std::string ModuleRuntimeHost::InstanceKey(const std::string& content_hash,
                                           const std::string& space_uri) {
  return content_hash + kSep + space_uri;
}

std::string ModuleRuntimeHost::StoreKey(const std::string& content_hash,
                                        const std::string& graph_did) {
  return content_hash + kSep + graph_did;
}

std::string ModuleRuntimeHost::StoreKeyPrefix(const std::string& content_hash) {
  return content_hash + kSep;
}

ModuleRuntimeHost::ModuleInstance* ModuleRuntimeHost::LiveInstance(
    const std::string& content_hash,
    const std::string& space_uri) {
  auto it = instances_.find(InstanceKey(content_hash, space_uri));
  if (it == instances_.end() || !it->second.live)
    return nullptr;
  return &it->second;
}

ModuleRuntimeHost::ModuleInstance* ModuleRuntimeHost::RunningInstance(
    const std::string& content_hash,
    const std::string& space_uri,
    living_web::HostError* err) {
  auto mit = modules_.find(content_hash);
  if (mit == modules_.end() ||
      mit->second.consent != ConsentDecision::kGranted) {
    *err = living_web::HostError::kNotAuthorised;
    return nullptr;
  }
  ModuleInstance* inst = LiveInstance(content_hash, space_uri);
  if (!inst || inst->state != ModuleRuntimeState::kRunning) {
    *err = living_web::HostError::kNotAuthorised;
    return nullptr;
  }
  return inst;
}

const living_web::CapabilitySet& ModuleRuntimeHost::Caps(
    const ModuleInstance* inst) const {
  return modules_.at(inst->content_hash).capabilities;
}

// ---- §7.1 installation -----------------------------------------------------

ModuleRuntimeHost::InstallResult ModuleRuntimeHost::Install(
    const std::string& wasm_binary,
    const std::string& manifest_json) {
  InstallResult r;
  // §4.2 / §9.2: the module's identity is "sha256-" + hex(SHA-256(binary)).
  const std::string computed = living_web::FormatModuleContentHash(
      crypto::SHA256HashString(wasm_binary));
  r.content_hash = computed;

  living_web::ModuleManifest manifest;
  std::string perr;
  if (!living_web::ParseModuleManifest(manifest_json, &manifest, &perr)) {
    r.error = living_web::HostError::kInvalidArgument;
    r.message = perr;
    return r;
  }
  if (!living_web::ManifestBindsContentHash(manifest, computed)) {
    r.error = living_web::HostError::kInvalidArgument;
    r.message =
        "manifest wasmContentHash does not bind the supplied WASM binary "
        "(§8.2/§9.2)";
    return r;
  }
  living_web::CapabilitySet caps =
      living_web::CapabilitySet::FromManifest(manifest.capabilities_required);
  if (!caps.AllKnown()) {
    r.error = living_web::HostError::kInvalidArgument;
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

// ---- §7.2 consent ----------------------------------------------------------

bool ModuleRuntimeHost::GrantConsent(const std::string& content_hash) {
  auto it = modules_.find(content_hash);
  if (it == modules_.end())
    return false;
  it->second.consent = ConsentDecision::kGranted;
  return true;
}

bool ModuleRuntimeHost::DenyConsent(const std::string& content_hash) {
  auto it = modules_.find(content_hash);
  if (it == modules_.end())
    return false;
  it->second.consent = ConsentDecision::kDenied;
  return true;
}

ConsentDecision ModuleRuntimeHost::ConsentOf(
    const std::string& content_hash) const {
  auto it = modules_.find(content_hash);
  return it == modules_.end() ? ConsentDecision::kPending : it->second.consent;
}

// ---- §4.4 instancing -------------------------------------------------------

HostStatus ModuleRuntimeHost::Instantiate(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& local_did,
    const std::vector<std::string>& authorised_graph_dids) {
  auto it = modules_.find(content_hash);
  if (it == modules_.end() ||
      it->second.consent != ConsentDecision::kGranted) {
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  }
  ModuleInstance& inst = instances_[InstanceKey(content_hash, space_uri)];
  inst.live = true;
  inst.content_hash = content_hash;
  inst.space_uri = space_uri;
  inst.local_did = local_did;
  inst.authorised_graphs.clear();
  for (const std::string& g : authorised_graph_dids)
    inst.authorised_graphs.insert(g);
  inst.state = ModuleRuntimeState::kRunning;
  inst.connected = false;
  return HostStatus::Success();
}

HostStatus ModuleRuntimeHost::Connect(const std::string& content_hash,
                                      const std::string& space_uri) {
  ModuleInstance* inst = LiveInstance(content_hash, space_uri);
  if (!inst)
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  inst->connected = true;
  return HostStatus::Success();
}

HostStatus ModuleRuntimeHost::Disconnect(const std::string& content_hash,
                                         const std::string& space_uri) {
  ModuleInstance* inst = LiveInstance(content_hash, space_uri);
  if (!inst)
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  inst->connected = false;
  return HostStatus::Success();
}

// ---- §7.5 suspension -------------------------------------------------------

HostStatus ModuleRuntimeHost::Suspend(const std::string& content_hash,
                                      const std::string& space_uri) {
  ModuleInstance* inst = LiveInstance(content_hash, space_uri);
  if (!inst)
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  inst->state = ModuleRuntimeState::kSuspended;
  return HostStatus::Success();
}

HostStatus ModuleRuntimeHost::Resume(const std::string& content_hash,
                                     const std::string& space_uri) {
  auto it = instances_.find(InstanceKey(content_hash, space_uri));
  if (it == instances_.end() || !it->second.live)
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  it->second.state = ModuleRuntimeState::kRunning;
  return HostStatus::Success();
}

// ---- §7.4 removal ----------------------------------------------------------

bool ModuleRuntimeHost::Remove(const std::string& content_hash) {
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

bool ModuleRuntimeHost::PurgeStorage(const std::string& content_hash,
                                     const std::string& graph_did) {
  return stores_.erase(StoreKey(content_hash, graph_did)) != 0;
}

// ---- §7.3 fork precondition ------------------------------------------------

// static
bool ModuleRuntimeHost::ForkCompatible(
    const living_web::ModuleManifest& child,
    const std::vector<std::string>& parent_in_force_kinds,
    std::vector<std::string>* missing) {
  return living_web::ConstraintKindsCompatible(
      child.supported_constraint_kinds, parent_in_force_kinds, missing);
}

// ---- module.commit driver --------------------------------------------------

HostStatus ModuleRuntimeHost::RecordCommit(const std::string& content_hash,
                                           const std::string& space_uri,
                                           const std::string& graph_did,
                                           const std::string& commit_id) {
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return HostStatus::Fail(err);
  if (!inst->authorised_graphs.count(graph_did))
    return HostStatus::Fail(living_web::HostError::kUnknownScope);
  inst->built_commits[graph_did].insert(commit_id);
  return HostStatus::Success();
}

// ---- §6.3 host-graph -------------------------------------------------------

HostResult<std::vector<living_web::Triple>>
ModuleRuntimeHost::ReaderQueryTriples(const std::string& content_hash,
                                      const std::string& space_uri,
                                      const std::string& graph_did,
                                      const TripleQuery& query) {
  using R = HostResult<std::vector<living_web::Triple>>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsGraphRead())
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return R::Fail(living_web::HostError::kUnknownScope);
  if (!graph_)
    return R::Fail(living_web::HostError::kInternal);
  std::vector<living_web::Triple> out;
  std::string e;
  if (!graph_->QueryTriples(graph_did, query, &out, &e))
    return R::Fail(living_web::HostError::kInvalidArgument);
  return R::Success(std::move(out));
}

HostResult<std::string> ModuleRuntimeHost::ReaderQuerySparql(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& graph_did,
    const std::string& sparql) {
  using R = HostResult<std::string>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsGraphRead())
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return R::Fail(living_web::HostError::kUnknownScope);
  if (!graph_)
    return R::Fail(living_web::HostError::kInternal);
  std::string out, e;
  if (!graph_->QuerySparql(graph_did, sparql, &out, &e))
    return R::Fail(living_web::HostError::kInvalidArgument);
  return R::Success(std::move(out));
}

HostResult<std::vector<living_web::Triple>> ModuleRuntimeHost::ReaderSnapshot(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& graph_did) {
  using R = HostResult<std::vector<living_web::Triple>>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsGraphRead())
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return R::Fail(living_web::HostError::kUnknownScope);
  if (!graph_)
    return R::Fail(living_web::HostError::kInternal);
  std::vector<living_web::Triple> out;
  std::string e;
  if (!graph_->Snapshot(graph_did, &out, &e))
    return R::Fail(living_web::HostError::kInvalidArgument);
  return R::Success(std::move(out));
}

HostStatus ModuleRuntimeHost::WriterApply(const std::string& content_hash,
                                          const std::string& space_uri,
                                          const std::string& graph_did,
                                          const GraphDiff& diff) {
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return HostStatus::Fail(err);
  if (!Caps(inst).AllowsGraphWrite())
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return HostStatus::Fail(living_web::HostError::kUnknownScope);
  if (!graph_)
    return HostStatus::Fail(living_web::HostError::kInternal);
  std::string e;
  if (!graph_->Apply(graph_did, diff, &e))
    return HostStatus::Fail(living_web::HostError::kInvalidArgument);
  return HostStatus::Success();
}

// ---- §6.3 host-crypto (§5.4, §9.7 scoped signer) ---------------------------

HostResult<HostSigned> ModuleRuntimeHost::SignCommit(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& graph_did,
    const std::string& commit_id) {
  using R = HostResult<HostSigned>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsCommitSign())
    return R::Fail(living_web::HostError::kNotAuthorised);
  // §5.4/§9.7: the signer signs a commit-id only for an authorised graph and
  // only when it corresponds to a diff the module actually built. Both a
  // non-authorised graph and an unknown commit-id are `signing-refused` — the
  // signer's accepted shapes are exhaustive, so it cannot be repurposed.
  auto git = inst->built_commits.find(graph_did);
  if (git == inst->built_commits.end() || !git->second.count(commit_id))
    return R::Fail(living_web::HostError::kSigningRefused);
  if (!crypto_)
    return R::Fail(living_web::HostError::kInternal);
  HostSigned sig;
  std::string e;
  if (!crypto_->SignCommit(graph_did, commit_id, &sig, &e))
    return R::Fail(living_web::HostError::kSigningRefused);
  return R::Success(std::move(sig));
}

HostResult<HostSigned> ModuleRuntimeHost::SignSignal(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& remote_did,
    const std::vector<uint8_t>& payload) {
  using R = HostResult<HostSigned>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsSignalSign())
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!crypto_)
    return R::Fail(living_web::HostError::kInternal);
  HostSigned sig;
  std::string e;
  if (!crypto_->SignSignal(inst->space_uri, inst->local_did, remote_did,
                           payload, &sig, &e)) {
    return R::Fail(living_web::HostError::kSigningRefused);
  }
  return R::Success(std::move(sig));
}

HostResult<bool> ModuleRuntimeHost::Verify(const std::string& content_hash,
                                           const std::string& space_uri,
                                           const std::vector<uint8_t>& message,
                                           const HostSigned& signature,
                                           const std::string& public_key) {
  using R = HostResult<bool>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsVerify())
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!crypto_)
    return R::Fail(living_web::HostError::kInternal);
  bool valid = false;
  if (!crypto_->Verify(message, signature, public_key, &valid))
    return R::Fail(living_web::HostError::kInvalidArgument);
  return R::Success(valid);
}

// ---- §6.3 host-network (§5.4) ----------------------------------------------

HostResult<HostConnection*> ModuleRuntimeHost::NetworkConnect(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& endpoint,
    RelayProtocol protocol) {
  using R = HostResult<HostConnection*>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsRelay(endpoint))
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!network_)
    return R::Fail(living_web::HostError::kInternal);
  living_web::HostError nerr = living_web::HostError::kNetworkError;
  HostConnection* c = network_->Connect(endpoint, protocol, &nerr);
  if (!c)
    return R::Fail(nerr);
  return R::Success(c);
}

HostResult<HostConnection*> ModuleRuntimeHost::PeerConnect(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& remote_did,
    const std::string& protocol) {
  using R = HostResult<HostConnection*>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsPeer(protocol))
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!network_)
    return R::Fail(living_web::HostError::kInternal);
  living_web::HostError nerr = living_web::HostError::kNetworkError;
  HostConnection* c = network_->PeerConnect(remote_did, protocol, &nerr);
  if (!c)
    return R::Fail(nerr);
  return R::Success(c);
}

HostResult<std::vector<uint8_t>> ModuleRuntimeHost::Fetch(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& url) {
  using R = HostResult<std::vector<uint8_t>>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsFetch(url))
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!network_)
    return R::Fail(living_web::HostError::kInternal);
  std::vector<uint8_t> out;
  living_web::HostError nerr = living_web::HostError::kNetworkError;
  if (!network_->Fetch(url, &out, &nerr))
    return R::Fail(nerr);
  return R::Success(std::move(out));
}

// ---- §6.3 host-clock -------------------------------------------------------

HostResult<uint64_t> ModuleRuntimeHost::NowWallclockMs(
    const std::string& content_hash,
    const std::string& space_uri) {
  using R = HostResult<uint64_t>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsWallclock())
    return R::Fail(living_web::HostError::kNotAuthorised);
  // §8 fingerprinting countermeasure: coarsen to 1-second resolution.
  uint64_t ms =
      static_cast<uint64_t>(base::Time::Now().InMillisecondsSinceUnixEpoch());
  return R::Success((ms / 1000) * 1000);
}

HostResult<uint64_t> ModuleRuntimeHost::NowMonotonicNs(
    const std::string& content_hash,
    const std::string& space_uri) {
  using R = HostResult<uint64_t>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsMonotonic())
    return R::Fail(living_web::HostError::kNotAuthorised);
  uint64_t ns = static_cast<uint64_t>(
      base::TimeTicks::Now().since_origin().InNanoseconds());
  return R::Success(ns);
}

// ---- §6.3 host-random ------------------------------------------------------

HostResult<std::vector<uint8_t>> ModuleRuntimeHost::GetRandomBytes(
    const std::string& content_hash,
    const std::string& space_uri,
    uint32_t len) {
  using R = HostResult<std::vector<uint8_t>>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).AllowsCsprng())
    return R::Fail(living_web::HostError::kNotAuthorised);
  return R::Success(crypto::RandBytesAsVector(len));
}

// ---- §6.3 host-storage (§8.1; keyed by (content-hash, graph-did)) ----------

HostResult<std::optional<std::vector<uint8_t>>> ModuleRuntimeHost::StorageGet(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& graph_did,
    const std::string& key) {
  using R = HostResult<std::optional<std::vector<uint8_t>>>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).HasStorage())
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return R::Fail(living_web::HostError::kUnknownScope);
  auto sit = stores_.find(StoreKey(content_hash, graph_did));
  if (sit == stores_.end())
    return R::Success(std::nullopt);
  auto kit = sit->second.entries.find(key);
  if (kit == sit->second.entries.end())
    return R::Success(std::nullopt);
  return R::Success(
      std::vector<uint8_t>(kit->second.begin(), kit->second.end()));
}

HostStatus ModuleRuntimeHost::StorageSet(const std::string& content_hash,
                                         const std::string& space_uri,
                                         const std::string& graph_did,
                                         const std::string& key,
                                         const std::vector<uint8_t>& value) {
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return HostStatus::Fail(err);
  if (!Caps(inst).HasStorage())
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return HostStatus::Fail(living_web::HostError::kUnknownScope);
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
    return HostStatus::Fail(living_web::HostError::kQuotaExceeded);
  store.bytes = projected;
  store.entries[key] = std::string(value.begin(), value.end());
  return HostStatus::Success();
}

HostStatus ModuleRuntimeHost::StorageDelete(const std::string& content_hash,
                                            const std::string& space_uri,
                                            const std::string& graph_did,
                                            const std::string& key) {
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return HostStatus::Fail(err);
  if (!Caps(inst).HasStorage())
    return HostStatus::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return HostStatus::Fail(living_web::HostError::kUnknownScope);
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

HostResult<std::vector<std::string>> ModuleRuntimeHost::StorageListKeys(
    const std::string& content_hash,
    const std::string& space_uri,
    const std::string& graph_did,
    const std::optional<std::string>& prefix) {
  using R = HostResult<std::vector<std::string>>;
  living_web::HostError err = living_web::HostError::kNone;
  ModuleInstance* inst = RunningInstance(content_hash, space_uri, &err);
  if (!inst)
    return R::Fail(err);
  if (!Caps(inst).HasStorage())
    return R::Fail(living_web::HostError::kNotAuthorised);
  if (!inst->authorised_graphs.count(graph_did))
    return R::Fail(living_web::HostError::kUnknownScope);
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

// ---- §6.3 host-log (no capability gate) ------------------------------------

void ModuleRuntimeHost::Log(const std::string& content_hash,
                            const std::string& space_uri,
                            LogLevel level,
                            const std::string& message) {
  // Only a live instance may log; the surface is otherwise ungated (§6.3).
  if (!LiveInstance(content_hash, space_uri))
    return;
  if (log_sink_)
    log_sink_.Run(content_hash, level, message);
}

// ---- introspection (§7.6 management UI / Spec 05 listModules()) ------------

bool ModuleRuntimeHost::IsInstalled(const std::string& content_hash) const {
  return modules_.count(content_hash) != 0;
}

size_t ModuleRuntimeHost::InstanceCount() const {
  size_t n = 0;
  for (const auto& kv : instances_)
    if (kv.second.live)
      ++n;
  return n;
}

const living_web::ModuleManifest* ModuleRuntimeHost::ManifestOf(
    const std::string& content_hash) const {
  auto it = modules_.find(content_hash);
  return it == modules_.end() ? nullptr : &it->second.manifest;
}

std::vector<ModuleStatus> ModuleRuntimeHost::ListModules() const {
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
        case ModuleRuntimeState::kError: any_error = true; break;
        case ModuleRuntimeState::kRunning: any_running = true; break;
        case ModuleRuntimeState::kSuspended: any_suspended = true; break;
      }
    }
    s.space_count = spaces;
    s.state = any_error ? ModuleRuntimeState::kError
              : any_running ? ModuleRuntimeState::kRunning
              : any_suspended ? ModuleRuntimeState::kSuspended
                              : ModuleRuntimeState::kRunning;  // installed & idle

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

}  // namespace content
