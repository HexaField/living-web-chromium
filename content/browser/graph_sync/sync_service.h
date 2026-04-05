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
  SyncSession();
  ~SyncSession();
  SyncSession(const SyncSession&) = delete;
  SyncSession& operator=(const SyncSession&) = delete;
  SyncSession(SyncSession&&);
  SyncSession& operator=(SyncSession&&);

  std::string graph_uuid;
  std::string uri;
  std::string name;
  graph::mojom::SyncState state = graph::mojom::SyncState::kIdle;
  std::unordered_set<std::string> peer_dids;
  std::vector<std::string> revision_dag;
  std::string current_revision;
};

// SyncService — manages P2P synchronisation of shared graphs.
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

  SyncSession* GetSession(const std::string& uri);
  size_t session_count() const { return sessions_.size(); }

 private:
  std::unordered_map<std::string, std::unique_ptr<SyncSession>> sessions_;
  std::vector<std::unique_ptr<class SharedGraphHostImpl>> shared_graph_hosts_;
  mojo::ReceiverSet<graph::mojom::GraphSyncService> receivers_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_SYNC_SERVICE_H_
