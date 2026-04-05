// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/shared_graph_host.h"

#include "base/logging.h"
#include "base/time/time.h"

namespace content {

SharedGraphHostImpl::SharedGraphHostImpl(
    SyncSession* session,
    GraphStore* store,
    GovernanceEngine* governance,
    const std::string& agent_did,
    mojo::PendingReceiver<graph::mojom::SharedGraphHost> receiver)
    : session_(session),
      store_(store),
      governance_(std::unique_ptr<GovernanceEngine>(governance)),
      agent_did_(agent_did),
      receiver_(this, std::move(receiver)) {
  // Register ourselves as a peer in the session.
  if (!agent_did_.empty()) {
    session_->peer_dids.insert(agent_did_);
  }
}

SharedGraphHostImpl::~SharedGraphHostImpl() = default;

void SharedGraphHostImpl::GetPeers(GetPeersCallback callback) {
  std::vector<std::string> peers(session_->peer_dids.begin(),
                                  session_->peer_dids.end());
  std::move(callback).Run(std::move(peers));
}

void SharedGraphHostImpl::GetOnlinePeers(GetOnlinePeersCallback callback) {
  // For now, treat all known peers as online. A real implementation would
  // track heartbeats via the WebRTC DataChannel or signalling server.
  std::vector<graph::mojom::OnlinePeerPtr> online;
  double now_ms = base::Time::Now().InMillisecondsFSinceUnixEpoch();
  for (const auto& did : session_->peer_dids) {
    auto peer = graph::mojom::OnlinePeer::New();
    peer->did = did;
    peer->last_seen = now_ms;
    online.push_back(std::move(peer));
  }
  std::move(callback).Run(std::move(online));
}

void SharedGraphHostImpl::SendSignal(const std::string& remote_did,
                                      const std::string& payload_json,
                                      SendSignalCallback callback) {
  // Check the target peer exists.
  if (session_->peer_dids.find(remote_did) == session_->peer_dids.end()) {
    LOG(WARNING) << "SendSignal: unknown peer " << remote_did;
    std::move(callback).Run(false);
    return;
  }

  // In a real implementation this would route through WebRTC DataChannel.
  // For now we log and report success — the signalling path is in-process.
  LOG(INFO) << "SendSignal: " << agent_did_ << " -> " << remote_did
            << " payload=" << payload_json.substr(0, 100);

  // If we have a client on the receiving end (same-process scenario),
  // deliver inline.
  if (client_.is_bound()) {
    client_->OnSignalReceived(remote_did, payload_json);
  }
  std::move(callback).Run(true);
}

void SharedGraphHostImpl::Broadcast(const std::string& payload_json,
                                     BroadcastCallback callback) {
  LOG(INFO) << "Broadcast from " << agent_did_
            << " to " << session_->peer_dids.size() << " peers"
            << " payload=" << payload_json.substr(0, 100);

  // Notify our own client of the broadcast (for same-process peers).
  if (client_.is_bound()) {
    client_->OnSignalReceived(agent_did_, payload_json);
  }
  std::move(callback).Run(true);
}

void SharedGraphHostImpl::Sync(SyncCallback callback) {
  // CRDT sync round. In a real implementation this would:
  // 1. Exchange revision heads with peers
  // 2. Compute missing diffs
  // 3. Apply received diffs through GovernanceEngine validation
  // 4. Return the merged diff
  //
  // For now, report no diff received (already in sync).
  session_->state = graph::mojom::SyncState::kSynced;
  if (client_.is_bound()) {
    client_->OnSyncStateChanged(graph::mojom::SyncState::kSynced);
  }
  std::move(callback).Run(nullptr);
}

void SharedGraphHostImpl::Commit(graph::mojom::GraphDiffPtr diff,
                                  CommitCallback callback) {
  if (!diff) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  // Store the revision.
  std::string revision = diff->revision;
  session_->revision_dag.push_back(revision);
  session_->current_revision = revision;

  // Notify client.
  if (client_.is_bound()) {
    client_->OnDiffReceived(diff->Clone());
  }

  LOG(INFO) << "Commit: revision " << revision
            << " (" << diff->additions.size() << " additions, "
            << diff->removals.size() << " removals)";

  std::move(callback).Run(revision);
}

void SharedGraphHostImpl::GetCurrentRevision(
    GetCurrentRevisionCallback callback) {
  std::move(callback).Run(session_->current_revision);
}

void SharedGraphHostImpl::Subscribe(
    mojo::PendingRemote<graph::mojom::SharedGraphClient> client) {
  client_.Bind(std::move(client));
  LOG(INFO) << "SharedGraphHost: client subscribed for " << session_->uri;
}

}  // namespace content
