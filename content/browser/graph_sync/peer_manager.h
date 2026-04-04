// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_PEER_MANAGER_H_
#define CONTENT_BROWSER_GRAPH_SYNC_PEER_MANAGER_H_

#include <string>
#include <unordered_map>

namespace content {

// PeerInfo — information about a connected peer.
struct PeerInfo {
  std::string did;
  double last_seen = 0;  // milliseconds since epoch
  bool is_online = false;
};

// PeerManager — manages peer connections for shared graphs.
//
// In the full implementation, this would manage WebRTC DataChannel
// connections via Chromium's browser-process WebRTC stack.
class PeerManager {
 public:
  PeerManager();
  ~PeerManager();

  // Add a known peer.
  void AddPeer(const std::string& did);

  // Remove a peer.
  void RemovePeer(const std::string& did);

  // Mark a peer as online/offline.
  void SetOnline(const std::string& did, bool online);

  // Get all known peer DIDs.
  std::vector<std::string> GetPeerDIDs() const;

  // Get online peers.
  std::vector<PeerInfo> GetOnlinePeers() const;

  // Check if a peer is known.
  bool HasPeer(const std::string& did) const;

 private:
  std::unordered_map<std::string, PeerInfo> peers_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_PEER_MANAGER_H_
