// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GRAPH_MANAGER_H_
#define CONTENT_BROWSER_GRAPH_GRAPH_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "content/browser/graph/graph_host.h"
#include "content/browser/graph/graph_store.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

// GraphManager — per-StoragePartition manager of personal graphs.
// Owns all GraphStore instances for an origin and implements the
// PersonalGraphService Mojo interface.
class GraphManager : public graph::mojom::PersonalGraphService {
 public:
  GraphManager();
  ~GraphManager() override;

  GraphManager(const GraphManager&) = delete;
  GraphManager& operator=(const GraphManager&) = delete;

  // Bind a new Mojo receiver.
  void BindReceiver(
      mojo::PendingReceiver<graph::mojom::PersonalGraphService> receiver);

  // Get the global GraphManager singleton.
  static GraphManager& GetInstance();

  // mojom::PersonalGraphService:
  void CreateGraph(const std::optional<std::string>& name,
                   CreateGraphCallback callback) override;
  void ListGraphs(ListGraphsCallback callback) override;
  void GetGraph(const std::string& uuid,
                GetGraphCallback callback) override;
  void RemoveGraph(const std::string& uuid,
                   RemoveGraphCallback callback) override;
  void BindGraph(
      const std::string& uuid,
      mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver) override;

  // Direct access for testing.
  GraphStore* GetStore(const std::string& uuid);
  size_t graph_count() const { return stores_.size(); }

 private:
  graph::mojom::GraphInfoPtr MakeGraphInfo(const GraphStore& store);

  std::unordered_map<std::string, std::unique_ptr<GraphStore>> stores_;
  // GraphHosts are owned here; keyed by a unique ID per binding.
  std::vector<std::unique_ptr<GraphHost>> hosts_;
  mojo::ReceiverSet<graph::mojom::PersonalGraphService> receivers_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GRAPH_MANAGER_H_
