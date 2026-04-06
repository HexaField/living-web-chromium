// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GRAPH_HOST_H_
#define CONTENT_BROWSER_GRAPH_GRAPH_HOST_H_

#include "content/browser/graph/graph_store.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

// GraphHost — implements PersonalGraphHost for a single graph.
// Delegates all operations to the underlying GraphStore.
// Owned by GraphManager; one per BindGraph() call.
class GraphHost : public graph::mojom::PersonalGraphHost {
 public:
  GraphHost(GraphStore* store,
            mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver);
  ~GraphHost() override;

  GraphHost(const GraphHost&) = delete;
  GraphHost& operator=(const GraphHost&) = delete;

  // mojom::PersonalGraphHost:
  void AddTriple(graph::mojom::SemanticTriplePtr triple,
                 AddTripleCallback callback) override;
  void AddTriples(std::vector<graph::mojom::SemanticTriplePtr> triples,
                  AddTriplesCallback callback) override;
  void RemoveTriple(graph::mojom::SignedTriplePtr triple,
                    RemoveTripleCallback callback) override;
  void QueryTriples(graph::mojom::TripleQueryPtr query,
                    QueryTriplesCallback callback) override;
  void QuerySparql(const std::string& sparql,
                   QuerySparqlCallback callback) override;
  void Snapshot(SnapshotCallback callback) override;
  void GrantAccess(const std::string& origin,
                   graph::mojom::GraphAccessLevel level,
                   GrantAccessCallback callback) override;
  void RevokeAccess(const std::string& origin,
                    RevokeAccessCallback callback) override;
  void AddShape(const std::string& name,
                const std::string& shacl_json,
                AddShapeCallback callback) override;
  void GetShapes(GetShapesCallback callback) override;
  void RemoveShape(const std::string& name,
                   RemoveShapeCallback callback) override;
  void GetShapeInstances(const std::string& shape_name,
                         GetShapeInstancesCallback callback) override;
  void CreateShapeInstance(const std::string& shape_name,
                           const std::string& data_json,
                           CreateShapeInstanceCallback callback) override;
  void GetShapeInstanceData(const std::string& shape_name,
                            const std::string& instance_uri,
                            GetShapeInstanceDataCallback callback) override;
  void Subscribe(
      mojo::PendingRemote<graph::mojom::PersonalGraphClient> client) override;

 private:
  // Convert between Mojo and content types.
  static content::SignedTriple ToContentSignedTriple(
      const graph::mojom::SemanticTriplePtr& mojo_triple);
  static graph::mojom::SignedTriplePtr ToMojoSignedTriple(
      const content::SignedTriple& triple);

  // Not owned — the GraphManager owns both GraphStore and GraphHost.
  raw_ptr<GraphStore> store_;
  mojo::Receiver<graph::mojom::PersonalGraphHost> receiver_;
  mojo::Remote<graph::mojom::PersonalGraphClient> client_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GRAPH_HOST_H_
