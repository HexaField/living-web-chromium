// Sync Service - standalone implementation with in-process transport
#ifndef LIVING_WEB_SYNC_SERVICE_H_
#define LIVING_WEB_SYNC_SERVICE_H_

#include "types.h"
#include "graph_store.h"
#include "base_shim.h"
#include "crypto_sha2.h"
#include <functional>
#include <unordered_map>
#include <unordered_set>

namespace living_web {

// SyncSession — tracks the sync state for one shared graph.
struct SyncSession {
  std::string graph_uuid;
  std::string uri;
  std::string name;
  SyncState state = SyncState::kIdle;
  std::unordered_set<std::string> peer_dids;
  std::vector<std::string> revision_dag;
  std::string current_revision;
};

// Callback types for sync events
using OnDiffReceived = std::function<void(const GraphDiff&)>;
using OnPeerJoined = std::function<void(const std::string&)>;
using OnPeerLeft = std::function<void(const std::string&)>;
using OnSignalReceived = std::function<void(const std::string&, const std::string&)>;

// PeerManager — manages peer connections
class PeerManager {
 public:
  void AddPeer(const std::string& did) {
    PeerInfo info;
    info.did = did;
    info.is_online = true;
    peers_[did] = info;
  }

  void RemovePeer(const std::string& did) { peers_.erase(did); }
  void SetOnline(const std::string& did, bool online) {
    auto it = peers_.find(did);
    if (it != peers_.end()) it->second.is_online = online;
  }

  std::vector<std::string> GetPeerDIDs() const {
    std::vector<std::string> result;
    for (const auto& [did, info] : peers_) result.push_back(did);
    return result;
  }

  std::vector<PeerInfo> GetOnlinePeers() const {
    std::vector<PeerInfo> result;
    for (const auto& [did, info] : peers_) {
      if (info.is_online) result.push_back(info);
    }
    return result;
  }

  bool HasPeer(const std::string& did) const { return peers_.count(did) > 0; }

 private:
  std::unordered_map<std::string, PeerInfo> peers_;
};

// CRDTEngine — OR-Set CRDT for triples
class CRDTEngine {
 public:
  CRDTEngine() : current_revision_("initial") {}

  GraphDiff CreateDiff(const std::vector<SignedTriple>& additions,
                       const std::vector<SignedTriple>& removals,
                       const std::string& author) {
    GraphDiff diff;
    diff.additions = additions;
    diff.removals = removals;
    diff.author = author;
    diff.timestamp = static_cast<double>(std::time(nullptr)) * 1000.0;
    diff.dependencies = {current_revision_};
    diff.revision = ComputeRevision(diff);
    current_revision_ = diff.revision;
    revision_dag_.push_back(diff.revision);
    return diff;
  }

  GraphDiff MergeDiff(const GraphDiff& remote_diff) {
    // In OR-Set: additions always win over removals
    // Just track the revision
    current_revision_ = remote_diff.revision;
    revision_dag_.push_back(remote_diff.revision);
    return remote_diff;
  }

  std::string ComputeRevision(const GraphDiff& diff) const {
    std::string input = diff.author;
    for (const auto& t : diff.additions)
      input += t.data.source + t.data.target;
    for (const auto& t : diff.removals)
      input += t.data.source + t.data.target;
    input += std::to_string(diff.timestamp);
    return crypto::SHA256HashString(input).substr(0, 16);
  }

  const std::string& current_revision() const { return current_revision_; }

 private:
  std::string current_revision_;
  std::vector<std::string> revision_dag_;
};

// InProcessTransport — connects two SyncService instances directly
class SyncService;

class InProcessTransport {
 public:
  void Connect(SyncService* a, SyncService* b, const std::string& uri);
  void SendDiff(SyncService* from, const std::string& uri, const GraphDiff& diff);
  void SendSignal(SyncService* from, const std::string& uri,
                   const std::string& sender_did, const std::string& payload);
 private:
  struct Link {
    SyncService* a = nullptr;
    SyncService* b = nullptr;
  };
  std::unordered_map<std::string, Link> links_;
};

// SyncService — manages P2P sync of shared graphs
class SyncService {
 public:
  SyncService() = default;
  ~SyncService() = default;

  std::string ShareGraph(const std::string& graph_uuid,
                          const std::string& name = "") {
    std::string uri = "living-web://" +
        base::Uuid::GenerateRandomV4().AsLowercaseString();

    auto session = std::make_unique<SyncSession>();
    session->graph_uuid = graph_uuid;
    session->uri = uri;
    session->name = name;
    session->state = SyncState::kIdle;
    session->current_revision = crypto::SHA256HashString(uri).substr(0, 16);

    sessions_[uri] = std::move(session);
    return uri;
  }

  bool JoinGraph(const std::string& uri) {
    if (sessions_.count(uri)) return false;
    auto session = std::make_unique<SyncSession>();
    session->uri = uri;
    session->state = SyncState::kSyncing;
    sessions_[uri] = std::move(session);
    return true;
  }

  std::vector<std::string> ListSharedGraphs() const {
    std::vector<std::string> result;
    for (const auto& [uri, _] : sessions_) result.push_back(uri);
    return result;
  }

  SyncSession* GetSession(const std::string& uri) {
    auto it = sessions_.find(uri);
    return it != sessions_.end() ? it->second.get() : nullptr;
  }

  // Apply a diff to the local graph store
  void ApplyDiff(const std::string& uri, GraphStore* store, const GraphDiff& diff) {
    auto session = GetSession(uri);
    if (!session) return;

    for (const auto& triple : diff.removals)
      store->RemoveTriple(triple);
    for (const auto& triple : diff.additions)
      store->AddTriple(triple);

    auto& crdt = GetOrCreateCRDT(uri);
    crdt.MergeDiff(diff);
    session->current_revision = crdt.current_revision();
    session->state = SyncState::kSynced;
  }

  // Create and broadcast a diff
  GraphDiff CommitDiff(const std::string& uri,
                        const std::vector<SignedTriple>& additions,
                        const std::vector<SignedTriple>& removals,
                        const std::string& author) {
    auto& crdt = GetOrCreateCRDT(uri);
    auto diff = crdt.CreateDiff(additions, removals, author);
    auto session = GetSession(uri);
    if (session) session->current_revision = crdt.current_revision();
    return diff;
  }

  // Peer management
  void AddPeer(const std::string& uri, const std::string& did) {
    auto session = GetSession(uri);
    if (session) {
      session->peer_dids.insert(did);
      peers_.AddPeer(did);
    }
    if (on_peer_joined_) on_peer_joined_(did);
  }

  void RemovePeer(const std::string& uri, const std::string& did) {
    auto session = GetSession(uri);
    if (session) session->peer_dids.erase(did);
    peers_.RemovePeer(did);
    if (on_peer_left_) on_peer_left_(did);
  }

  std::vector<std::string> GetPeers(const std::string& uri) const {
    auto it = sessions_.find(uri);
    if (it == sessions_.end()) return {};
    return std::vector<std::string>(it->second->peer_dids.begin(),
                                     it->second->peer_dids.end());
  }

  // Receive a diff from a remote peer (called by transport)
  void ReceiveDiff(const std::string& uri, GraphStore* store, const GraphDiff& diff) {
    ApplyDiff(uri, store, diff);
    if (on_diff_received_) on_diff_received_(diff);
  }

  // Receive a signal from a remote peer
  void ReceiveSignal(const std::string& sender_did, const std::string& payload) {
    if (on_signal_received_) on_signal_received_(sender_did, payload);
  }

  // Event handlers
  void SetOnDiffReceived(OnDiffReceived cb) { on_diff_received_ = std::move(cb); }
  void SetOnPeerJoined(OnPeerJoined cb) { on_peer_joined_ = std::move(cb); }
  void SetOnPeerLeft(OnPeerLeft cb) { on_peer_left_ = std::move(cb); }
  void SetOnSignalReceived(OnSignalReceived cb) { on_signal_received_ = std::move(cb); }

  size_t session_count() const { return sessions_.size(); }

 private:
  CRDTEngine& GetOrCreateCRDT(const std::string& uri) {
    if (!crdts_.count(uri)) crdts_[uri] = std::make_unique<CRDTEngine>();
    return *crdts_[uri];
  }

  std::unordered_map<std::string, std::unique_ptr<SyncSession>> sessions_;
  std::unordered_map<std::string, std::unique_ptr<CRDTEngine>> crdts_;
  PeerManager peers_;

  OnDiffReceived on_diff_received_;
  OnPeerJoined on_peer_joined_;
  OnPeerLeft on_peer_left_;
  OnSignalReceived on_signal_received_;
};

// InProcessTransport implementation
inline void InProcessTransport::Connect(SyncService* a, SyncService* b,
                                         const std::string& uri) {
  links_[uri] = {a, b};
}

inline void InProcessTransport::SendDiff(SyncService* from, const std::string& uri,
                                          const GraphDiff& diff) {
  auto it = links_.find(uri);
  if (it == links_.end()) return;
  auto* target = (from == it->second.a) ? it->second.b : it->second.a;
  // Note: target needs its own GraphStore; caller manages this
  target->ReceiveDiff(uri, nullptr, diff);
}

inline void InProcessTransport::SendSignal(SyncService* from, const std::string& uri,
                                             const std::string& sender_did,
                                             const std::string& payload) {
  auto it = links_.find(uri);
  if (it == links_.end()) return;
  auto* target = (from == it->second.a) ? it->second.b : it->second.a;
  target->ReceiveSignal(sender_did, payload);
}

// Graph Manager — manages graph instances
class GraphManager {
 public:
  GraphManager() = default;
  ~GraphManager() = default;

  std::string CreateGraph(const std::string& name = "") {
    std::string uuid = base::Uuid::GenerateRandomV4().AsLowercaseString();
    stores_[uuid] = std::make_unique<GraphStore>(uuid, name);
    return uuid;
  }

  std::vector<std::string> ListGraphs() const {
    std::vector<std::string> result;
    for (const auto& [uuid, _] : stores_) result.push_back(uuid);
    return result;
  }

  GraphStore* GetStore(const std::string& uuid) {
    auto it = stores_.find(uuid);
    return it != stores_.end() ? it->second.get() : nullptr;
  }

  bool RemoveGraph(const std::string& uuid) {
    return stores_.erase(uuid) > 0;
  }

  size_t graph_count() const { return stores_.size(); }

 private:
  std::unordered_map<std::string, std::unique_ptr<GraphStore>> stores_;
};

// Permission Service — data structures for permission management
struct PermissionRequest {
  std::string origin;
  std::string permission_type;  // "graph.read", "graph.write", "did.create", "did.sign"
  std::string resource_id;
  bool granted = false;
};

class PermissionService {
 public:
  bool RequestPermission(const std::string& origin, const std::string& type,
                          const std::string& resource = "") {
    PermissionRequest req;
    req.origin = origin;
    req.permission_type = type;
    req.resource_id = resource;
    // In browser: would show UI prompt. Here: auto-grant for same-origin.
    req.granted = true;
    permissions_.push_back(req);
    return true;
  }

  bool HasPermission(const std::string& origin, const std::string& type) const {
    for (const auto& p : permissions_) {
      if (p.origin == origin && p.permission_type == type && p.granted)
        return true;
    }
    return false;
  }

  void RevokePermission(const std::string& origin, const std::string& type) {
    for (auto& p : permissions_) {
      if (p.origin == origin && p.permission_type == type)
        p.granted = false;
    }
  }

  const std::vector<PermissionRequest>& permissions() const { return permissions_; }

 private:
  std::vector<PermissionRequest> permissions_;
};

}  // namespace living_web

#endif  // LIVING_WEB_SYNC_SERVICE_H_
