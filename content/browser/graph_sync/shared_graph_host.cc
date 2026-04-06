// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/shared_graph_host.h"

#include "base/logging.h"
#include "base/time/time.h"

#include <algorithm>
#include <sstream>

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
  std::vector<graph::mojom::PeerInfoPtr> peers;
  for (const auto& did : session_->peer_dids) {
    auto info = graph::mojom::PeerInfo::New();
    info->did = did;
    info->session_id = session_->uri;
    info->device_label = did.substr(0, std::min<size_t>(did.size(), 16));
    peers.push_back(std::move(info));
  }
  std::move(callback).Run(std::move(peers));
}

void SharedGraphHostImpl::GetOnlinePeers(GetOnlinePeersCallback callback) {
  std::vector<graph::mojom::OnlinePeerPtr> online;
  double now_ms = base::Time::Now().InMillisecondsFSinceUnixEpoch();
  for (const auto& did : session_->peer_dids) {
    auto peer = graph::mojom::OnlinePeer::New();
    peer->did = did;
    peer->session_id = session_->uri;
    peer->device_label = did.substr(0, std::min<size_t>(did.size(), 16));
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

void SharedGraphHostImpl::SendSignalToSession(
    const std::string& remote_did,
    const std::string& session_id,
    const std::string& payload_json,
    SendSignalToSessionCallback callback) {
  if (session_->peer_dids.find(remote_did) == session_->peer_dids.end()) {
    LOG(WARNING) << "SendSignalToSession: unknown peer " << remote_did;
    std::move(callback).Run(false);
    return;
  }

  LOG(INFO) << "SendSignalToSession: " << agent_did_ << " -> " << remote_did
            << " session=" << session_id
            << " payload=" << payload_json.substr(0, 100);

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

void SharedGraphHostImpl::CanAddTriple(const std::string& predicate,
                                        const std::string& scope_entity,
                                        CanAddTripleCallback callback) {
  if (!governance_ || !store_) {
    std::move(callback).Run(true, std::nullopt);
    return;
  }

  // Use the first peer DID as root authority (graph creator).
  std::string root_did;
  if (!session_->peer_dids.empty()) {
    root_did = *session_->peer_dids.begin();
  }

  std::string scope = scope_entity.empty() ? session_->uri : scope_entity;
  auto result = governance_->CanAddTriple(
      *store_, agent_did_, predicate, scope, root_did);

  std::optional<std::string> reason;
  if (!result.accepted && !result.reason.empty()) {
    reason = result.reason;
  }
  std::move(callback).Run(result.accepted, reason);
}

void SharedGraphHostImpl::ConstraintsFor(
    const std::optional<std::string>& scope_entity,
    ConstraintsForCallback callback) {
  if (!governance_ || !store_) {
    std::move(callback).Run("[]");
    return;
  }

  std::string scope = (scope_entity && !scope_entity->empty())
                           ? *scope_entity
                           : session_->uri;
  auto constraints = governance_->GetConstraintsFor(*store_, scope);

  // Serialize to JSON array of {kind, id} objects.
  std::string json = "[";
  bool first = true;
  auto append = [&](const std::string& kind, const std::string& id) {
    if (!first) json += ",";
    json += "{\"kind\":\"" + kind + "\",\"id\":\"" + id + "\"}";
    first = false;
  };
  for (const auto& c : constraints.capabilities)
    append("capability", c.constraint_id);
  for (const auto& c : constraints.temporals)
    append("temporal", c.constraint_id);
  for (const auto& c : constraints.contents)
    append("content", c.constraint_id);
  for (const auto& c : constraints.credentials)
    append("credential", c.constraint_id);
  json += "]";

  std::move(callback).Run(json);
}

void SharedGraphHostImpl::MyCapabilities(MyCapabilitiesCallback callback) {
  if (!governance_ || !store_) {
    // Permissive default.
    std::move(callback).Run(
        "{\"canAddTriples\":true,\"canRemoveTriples\":true,"
        "\"allowedPredicates\":[]}");
    return;
  }

  std::string root_did;
  if (!session_->peer_dids.empty()) {
    root_did = *session_->peer_dids.begin();
  }

  // Find all ZCAPs for this agent to determine allowed predicates.
  TripleQuery query;
  query.source = agent_did_;
  query.predicate = "governance://has_zcap";
  auto zcaps = store_->QueryTriples(query);

  std::vector<std::string> predicates;
  for (const auto& zcap_triple : zcaps) {
    auto preds_opt = [&]() -> std::optional<std::string> {
      TripleQuery pq;
      pq.source = zcap_triple.data.target;
      pq.predicate = "governance://capability_predicates";
      auto r = store_->QueryTriples(pq);
      if (r.empty()) return std::nullopt;
      return r[0].data.target;
    }();
    if (preds_opt) {
      std::istringstream ss(*preds_opt);
      std::string item;
      while (std::getline(ss, item, ',')) {
        size_t s = item.find_first_not_of(" \t");
        size_t e = item.find_last_not_of(" \t");
        if (s != std::string::npos)
          predicates.push_back(item.substr(s, e - s + 1));
      }
    }
  }

  // Check basic add/remove by testing a hypothetical triple.
  bool can_add = governance_->CanAddTriple(
      *store_, agent_did_, "", session_->uri, root_did).accepted;

  std::string json = "{\"canAddTriples\":" + std::string(can_add ? "true" : "false");
  json += ",\"canRemoveTriples\":" + std::string(can_add ? "true" : "false");
  json += ",\"allowedPredicates\":[";
  for (size_t i = 0; i < predicates.size(); i++) {
    if (i > 0) json += ",";
    json += "\"" + predicates[i] + "\"";
  }
  json += "]}";

  std::move(callback).Run(json);
}

}  // namespace content
