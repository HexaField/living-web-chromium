// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/personal_graph_manager.h"

#include <algorithm>
#include <utility>

#include "base/functional/bind.h"

namespace content {

PersonalGraphManager::PersonalGraphManager(DIDKeyProvider* identity)
    : backends_(identity),
      governance_(identity),
      sync_(identity, &governance_),
      module_crypto_(identity),
      // §6.2: no host-network backing in this branch — module execution (and
      // thus any network import) awaits the Component Model engine. The runtime
      // answers network imports with `internal` when it is null.
      module_runtime_(&module_graph_, &module_crypto_, /*network=*/nullptr) {}

PersonalGraphManager::~PersonalGraphManager() = default;

void PersonalGraphManager::BindReceiver(
    mojo::PendingReceiver<graph::mojom::PersonalGraphManager> receiver) {
  receivers_.Add(this, std::move(receiver));
}

// static
graph::mojom::GraphTrustLevel PersonalGraphManager::TrustToMojo(
    GraphTrustLevel t) {
  switch (t) {
    case GraphTrustLevel::kLocal:
      return graph::mojom::GraphTrustLevel::kLocal;
    case GraphTrustLevel::kExternal:
      return graph::mojom::GraphTrustLevel::kExternal;
  }
  return graph::mojom::GraphTrustLevel::kLocal;
}

// static
GraphTrustLevel PersonalGraphManager::TrustFromMojo(
    graph::mojom::GraphTrustLevel t) {
  switch (t) {
    case graph::mojom::GraphTrustLevel::kLocal:
      return GraphTrustLevel::kLocal;
    case graph::mojom::GraphTrustLevel::kExternal:
      return GraphTrustLevel::kExternal;
  }
  return GraphTrustLevel::kExternal;
}

// static
graph::mojom::GraphInfoPtr PersonalGraphManager::BuildInfo(
    GraphBackend* backend) {
  auto info = graph::mojom::GraphInfo::New();
  info->id = backend->id();
  std::string iri;
  if (backend->GetIri(&iri))
    info->iri = iri;
  info->did = backend->did();
  info->display_name = backend->display_name();
  info->trust_level = TrustToMojo(backend->trust_level());
  return info;
}

// static
graph::mojom::ModuleState PersonalGraphManager::ModuleStateToMojo(
    ModuleRuntimeState s) {
  switch (s) {
    case ModuleRuntimeState::kRunning:
      return graph::mojom::ModuleState::kRunning;
    case ModuleRuntimeState::kSuspended:
      return graph::mojom::ModuleState::kSuspended;
    case ModuleRuntimeState::kError:
      return graph::mojom::ModuleState::kError;
  }
  return graph::mojom::ModuleState::kRunning;
}

void PersonalGraphManager::Retain(std::unique_ptr<PersonalGraphHost> host,
                                  const std::string& id) {
  PersonalGraphHost* raw = host.get();
  raw->set_disconnect_handler(
      base::BindOnce(&PersonalGraphManager::OnHostDisconnected,
                     weak_factory_.GetWeakPtr(), raw, id));
  hosts_.push_back(std::move(host));
}

void PersonalGraphManager::OnHostDisconnected(PersonalGraphHost* host,
                                              const std::string& id) {
  // Erase the host first (severing its raw_ptr to the backend), then drop the
  // backend and its store.
  std::erase_if(hosts_, [host](const std::unique_ptr<PersonalGraphHost>& h) {
    return h.get() == host;
  });
  backends_.Remove(id);
  // If the dropped host backed a mount, the renderer letting go of the Graph is
  // an implicit unmount: drop the entry and announce the lost subscription (§6.4).
  for (auto it = mounts_.begin(); it != mounts_.end();) {
    if (it->second.backend_id == id) {
      module_graph_.Unbind(it->first);
      if (manager_client_)
        manager_client_->OnSubscriptionLost(it->first, it->second.mode,
                                            "disconnected");
      it = mounts_.erase(it);
    } else {
      ++it;
    }
  }
}

void PersonalGraphManager::Create(
    const std::optional<std::string>& display_name,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
    CreateCallback callback) {
  GraphBackend* backend = backends_.Create(display_name);
  Retain(std::make_unique<PersonalGraphHost>(backend, &backends_, &governance_,
                                             &sync_, std::move(receiver)),
         backend->id());
  std::move(callback).Run(BuildInfo(backend));
}

void PersonalGraphManager::FromSnapshot(
    graph::mojom::GraphSnapshotPtr snapshot,
    graph::mojom::GraphTrustLevel trust,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
    FromSnapshotCallback callback) {
  std::string error;
  GraphBackend* backend = backends_.FromSnapshot(
      PersonalGraphHost::FromMojo(snapshot), TrustFromMojo(trust), &error);
  if (!backend) {
    std::move(callback).Run(nullptr, error);
    return;
  }
  Retain(std::make_unique<PersonalGraphHost>(backend, &backends_, &governance_,
                                             &sync_, std::move(receiver)),
         backend->id());
  std::move(callback).Run(BuildInfo(backend), std::nullopt);
}

// ---- Spec 05 §6.2/§6.4 sync surface ---------------------------------------

void PersonalGraphManager::Mount(
    const std::string& graph_did,
    graph::mojom::MountOptionsPtr options,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
    MountCallback callback) {
  // §6.2: a graph is mounted once per realm.
  if (mounts_.count(graph_did)) {
    std::move(callback).Run(nullptr, "InvalidStateError");
    return;
  }
  // Materialise an empty external-trust backend standing in for the remote graph.
  // Its state is filled by the active sync module from options.snapshot_uri and
  // subsequent diffs (live transport is Spec 06); the browser owns the store.
  GraphBackend* backend = backends_.CreateMounted(graph_did);

  // §6.2 step 2: authorise the mount against the graph's governance — the
  // §9.2.2 mountContext gate for a read mount, or the createLink authority for a
  // write/governance mount. A not-yet-synced (empty) graph carries no
  // constraints, so the mount is permissive; the per-diff §9.2.1 checks enforce
  // authority as state arrives.
  const std::string author = governance_.ActiveAuthorDid();
  bool authorised = true;
  if (options->mode == graph::mojom::MountMode::kRead) {
    std::optional<CapabilityProof> proof;  // presentations layered above (Spec 06)
    authorised = sync_.ValidateReadAccess(backend, author, proof).accepted;
  } else {
    authorised =
        governance_.CanPerformAction(backend, living_web::kActionCreateLink,
                                     author)
            .allowed;
  }
  if (!authorised) {
    backends_.Remove(backend->id());
    std::move(callback).Run(nullptr, "NotAllowedError");
    return;
  }

  // §6.2: expose the mounted graph to the module runtime by DID, so a writer
  // module's host-graph imports (apply/query/snapshot) resolve to this backend.
  // Unbound on unmount / implicit unmount, before the backend is dropped.
  module_graph_.Bind(graph_did, backend);

  const bool writable = options->mode != graph::mojom::MountMode::kRead;
  auto host = std::make_unique<PersonalGraphHost>(
      backend, &backends_, &governance_, &sync_, std::move(receiver));
  PersonalGraphHost* raw = host.get();
  Retain(std::move(host), backend->id());
  raw->InitAsMount(options->space_uri, options->module_hash, writable);

  MountEntry entry;
  entry.host = raw;
  entry.backend_id = backend->id();
  entry.mode = options->mode;
  entry.space_uri = options->space_uri;
  entry.module_hash = options->module_hash;
  entry.sync_state = graph::mojom::GraphSyncState::kSynced;
  mounts_[graph_did] = std::move(entry);

  if (manager_client_)
    manager_client_->OnSubscriptionGained(graph_did, options->mode);
  std::move(callback).Run(BuildInfo(backend), std::nullopt);
}

void PersonalGraphManager::Unmount(const std::string& graph_did,
                                   UnmountCallback callback) {
  auto it = mounts_.find(graph_did);
  if (it == mounts_.end()) {
    std::move(callback).Run("NotFoundError");
    return;
  }
  const graph::mojom::MountMode mode = it->second.mode;
  const std::string backend_id = it->second.backend_id;
  PersonalGraphHost* host = it->second.host;
  // Drop the mount entry before tearing down the host so the host's own
  // disconnect handler (should it race) does not fire a second subscription-lost.
  mounts_.erase(it);
  std::erase_if(hosts_, [host](const std::unique_ptr<PersonalGraphHost>& h) {
    return h.get() == host;
  });
  module_graph_.Unbind(graph_did);
  backends_.Remove(backend_id);
  if (manager_client_)
    manager_client_->OnSubscriptionLost(graph_did, mode, "unmounted");
  std::move(callback).Run(std::nullopt);
}

void PersonalGraphManager::ListMounted(ListMountedCallback callback) {
  std::vector<graph::mojom::MountedGraphInfoPtr> out;
  out.reserve(mounts_.size());
  for (const auto& kv : mounts_) {
    auto info = graph::mojom::MountedGraphInfo::New();
    info->graph_did = kv.first;
    info->mode = kv.second.mode;
    info->sync_state = kv.second.sync_state;
    info->space_uri = kv.second.space_uri;
    info->module_hash = kv.second.module_hash;
    info->peer_count = 0;  // no module attached (Spec 06 supplies peers)
    out.push_back(std::move(info));
  }
  std::move(callback).Run(std::move(out));
}

void PersonalGraphManager::ListModules(ListModulesCallback callback) {
  // §6.4: the installed-module inventory is owned by the module runtime
  // ([[SYNC-MODULE-ARCHITECTURE]], Spec 06). Project each ModuleStatus onto the
  // wire SyncModuleInfo.
  std::vector<graph::mojom::SyncModuleInfoPtr> out;
  for (const ModuleStatus& m : module_runtime_.ListModules()) {
    auto info = graph::mojom::SyncModuleInfo::New();
    info->content_hash = m.content_hash;
    if (!m.name.empty())
      info->name = m.name;
    info->space_count = static_cast<uint32_t>(m.space_count);
    info->state = ModuleStateToMojo(m.state);
    info->storage_bytes = m.storage_bytes;
    out.push_back(std::move(info));
  }
  std::move(callback).Run(std::move(out));
}

void PersonalGraphManager::ListSpaces(ListSpacesCallback callback) {
  // §6.4: the realm's active-space inventory — the distinct space:// URIs this
  // realm participates in, aggregated from BOTH the mount table (remote graphs
  // opened into the realm) and the local graphs its hosts have published. The
  // manager owns every host in |hosts_|, so it reads published spaces straight
  // off them without a host→manager backpointer; a mount-backing host reports
  // published() == false, so the two sources never double-count a graph. Where a
  // published local graph and a mounted remote graph share one space (a unified
  // topology, §7.2), the space's graph_count sums both.
  std::map<std::string, graph::mojom::SyncSpaceInfoPtr> by_uri;
  auto accumulate = [&by_uri](const std::string& uri,
                              const std::string& module_hash) {
    if (uri.empty())
      return;
    auto it = by_uri.find(uri);
    if (it == by_uri.end()) {
      auto info = graph::mojom::SyncSpaceInfo::New();
      info->space_uri = uri;
      info->module_hash = module_hash;
      info->graph_count = 1;
      info->peer_count = 0;
      by_uri[uri] = std::move(info);
    } else {
      ++it->second->graph_count;
    }
  };
  for (const auto& kv : mounts_)
    accumulate(kv.second.space_uri, kv.second.module_hash);
  for (const auto& host : hosts_) {
    if (host->published())
      accumulate(host->space_uri(), host->module_hash());
  }
  std::vector<graph::mojom::SyncSpaceInfoPtr> out;
  out.reserve(by_uri.size());
  for (auto& kv : by_uri)
    out.push_back(std::move(kv.second));
  std::move(callback).Run(std::move(out));
}

void PersonalGraphManager::SubscribeManager(
    mojo::PendingRemote<graph::mojom::PersonalGraphManagerClient> client) {
  manager_client_.reset();
  manager_client_.Bind(std::move(client));
}

}  // namespace content
