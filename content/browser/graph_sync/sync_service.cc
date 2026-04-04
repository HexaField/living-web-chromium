// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/sync_service.h"

#include "base/logging.h"
#include "base/uuid.h"
#include "crypto/sha2.h"

namespace content {

SyncService::SyncService() = default;
SyncService::~SyncService() = default;

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
  // In a real implementation, this would:
  // 1. Connect to the signalling server
  // 2. Discover peers
  // 3. Establish WebRTC DataChannel connections
  // 4. Sync the current graph state

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
  // TODO: Create SharedGraphHostImpl and bind.
  LOG(INFO) << "BindSharedGraph: " << uri << " (host binding pending)";
}

SyncSession* SyncService::GetSession(const std::string& uri) {
  auto it = sessions_.find(uri);
  return it != sessions_.end() ? it->second.get() : nullptr;
}

}  // namespace content
