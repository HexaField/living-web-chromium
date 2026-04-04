// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_SYNC_SERVICE_H_
#define CONTENT_BROWSER_GRAPH_SYNC_SYNC_SERVICE_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "content/browser/graph/triple.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/mojom/graph/graph_sync.mojom.h"

namespace content {

class GraphStore;

// SyncSession — tracks the sync state for one shared graph.
struct SyncSession {
  std::string graph_uuid;
  std::string uri;                              // Shared graph URI
  std::string name;
  graph::mojom::SyncState state = graph::mojom::SyncState::kIdle;
  std::unordered_set<std::string> peer_dids;    // Known peers
  std::vector<std::string> revision_dag;        // Revision history
  std::string current_revision;
};

// SyncService — manages P2P synchronisation of shared graphs.
//
// In this reference implementation, the transport layer (WebRTC
// DataChannel) is stubbed. The service maintains sync state and
// the revision DAG, with hooks for a real transport implementation.
class SyncService : public graph::mojom::GraphSyncService {
 public:
  SyncService();
  ~SyncService() override;

  void BindReceiver(
      mojo::PendingReceiver<graph::mojom::GraphSyncService> receiver);

  // mojom::GraphSyncService:
  void ShareGraph(const std::string& graph_uuid,
                  graph::mojom::SharedGraphOptionsPtr options,
                  ShareGraphCallback callback) override;
  void JoinGraph(const std::string& shared_graph_uri,
                 JoinGraphCallback callback) override;
  void ListSharedGraphs(ListSharedGraphsCallback callback) override;
  void BindSharedGraph(
      const std::string& uri,
      mojo::PendingReceiver<graph::mojom::SharedGraphHost> receiver) override;

  // Direct access for testing.
  SyncSession* GetSession(const std::string& uri);
  size_t session_count() const { return sessions_.size(); }

 private:
  std::unordered_map<std::string, std::unique_ptr<SyncSession>> sessions_;
  mojo::ReceiverSet<graph::mojom::GraphSyncService> receivers_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_SYNC_SERVICE_H_
