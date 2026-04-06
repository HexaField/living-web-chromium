// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/sync_service.h"

#include "base/logging.h"
#include "base/uuid.h"
#include "content/browser/graph/graph_manager.h"
#include "content/browser/graph_sync/shared_graph_host.h"
#include "crypto/sha2.h"

namespace content {

SyncSession::SyncSession() = default;
SyncSession::~SyncSession() = default;
SyncSession::SyncSession(SyncSession&&) = default;
SyncSession& SyncSession::operator=(SyncSession&&) = default;

SyncService::SyncService() = default;
SyncService::~SyncService() = default;

// static
SyncService* SyncService::GetInstance() {
  static SyncService instance;
  return &instance;
}

void SyncService::BindReceiver(
    mojo::PendingReceiver<graph::mojom::GraphSyncService> receiver) {
  receivers_.Add(this, std::move(receiver));
}

void SyncService::ShareGraph(const std::string& graph_uuid,
                              graph::mojom::SharedGraphOptionsPtr options,
                              ShareGraphCallback callback) {
  // Generate a shared graph URI.
  std::string uri = "living-web://" +
      base::Uuid::GenerateRandomV4().AsLowercaseString();

  auto session = std::make_unique<SyncSession>();
  session->graph_uuid = graph_uuid;
  session->uri = uri;
  session->name = options->name.value_or("");
  session->state = graph::mojom::SyncState::kIdle;
  session->current_revision =
      crypto::SHA256HashString(uri).substr(0, 16);  // Initial revision

  auto info = graph::mojom::SharedGraphInfo::New();
  info->uri = uri;
  info->name = session->name;
  info->sync_state = graph::mojom::SyncState::kIdle;
  info->peer_count = 0;

  LOG(INFO) << "Shared graph: " << graph_uuid << " as " << uri;

  sessions_[uri] = std::move(session);
  std::move(callback).Run(std::move(info));
}

void SyncService::JoinGraph(const std::string& shared_graph_uri,
                             JoinGraphCallback callback) {
  // Check if we already have this session (local share).
  auto it = sessions_.find(shared_graph_uri);
  if (it != sessions_.end()) {
    auto info = graph::mojom::SharedGraphInfo::New();
    info->uri = shared_graph_uri;
    info->name = it->second->name;
    info->sync_state = it->second->state;
    info->peer_count =
        static_cast<uint32_t>(it->second->peer_dids.size());
    std::move(callback).Run(std::move(info));
    return;
  }

  // Create a new session for the joined graph.
  auto session = std::make_unique<SyncSession>();
  session->uri = shared_graph_uri;
  session->state = graph::mojom::SyncState::kSyncing;

  auto info = graph::mojom::SharedGraphInfo::New();
  info->uri = shared_graph_uri;
  info->name = "";
  info->sync_state = graph::mojom::SyncState::kSyncing;
  info->peer_count = 0;

  LOG(INFO) << "Joined shared graph: " << shared_graph_uri;

  sessions_[shared_graph_uri] = std::move(session);
  std::move(callback).Run(std::move(info));
}

void SyncService::ListSharedGraphs(ListSharedGraphsCallback callback) {
  std::vector<graph::mojom::SharedGraphInfoPtr> infos;
  for (const auto& [uri, session] : sessions_) {
    auto info = graph::mojom::SharedGraphInfo::New();
    info->uri = uri;
    info->name = session->name;
    info->sync_state = session->state;
    info->peer_count = static_cast<uint32_t>(session->peer_dids.size());
    infos.push_back(std::move(info));
  }
  std::move(callback).Run(std::move(infos));
}

void SyncService::BindSharedGraph(
    const std::string& uri,
    mojo::PendingReceiver<graph::mojom::SharedGraphHost> receiver) {
  auto it = sessions_.find(uri);
  if (it == sessions_.end()) {
    LOG(WARNING) << "BindSharedGraph: no session for " << uri;
    return;
  }

  SyncSession* session = it->second.get();

  // Look up the underlying GraphStore if this was a shared local graph.
  GraphStore* store = nullptr;
  if (!session->graph_uuid.empty()) {
    store = GraphManager::GetInstance().GetStore(session->graph_uuid);
  }

  // Create governance engine for this shared graph.
  auto* governance = new GovernanceEngine();

  // TODO: get agent DID from DID credential service. For now, use a
  // placeholder derived from the session.
  std::string agent_did = "did:key:local-agent";

  auto host = std::make_unique<SharedGraphHostImpl>(
      session, store, governance, agent_did, std::move(receiver));
  shared_graph_hosts_.push_back(std::move(host));

  LOG(INFO) << "BindSharedGraph: bound host for " << uri;
}

SyncSession* SyncService::GetSession(const std::string& uri) {
  auto it = sessions_.find(uri);
  return it != sessions_.end() ? it->second.get() : nullptr;
}

}  // namespace content
