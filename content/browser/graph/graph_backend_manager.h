// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GraphBackendManager — the browser-process port of the §3.4/§4.1/§5.5
// `GraphManager` algorithms of Spec 02. A faithful port of living_web::
// GraphManager (standalone/graph_provider.h) onto content::DIDKeyProvider.
//
// Beyond creating and materialising graphs, it owns the set of live
// GraphBackends keyed by their internal id, so a graph's querySparql (§7.2) can
// resolve sibling graphs named by id into the SPARQL dataset. Backends live for
// as long as they are held here; PersonalGraphManager removes a backend when the
// renderer dissolves and drops its Graph.

#ifndef CONTENT_BROWSER_GRAPH_GRAPH_BACKEND_MANAGER_H_
#define CONTENT_BROWSER_GRAPH_GRAPH_BACKEND_MANAGER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/graph/graph_backend.h"

namespace content {

class GraphBackendManager {
 public:
  explicit GraphBackendManager(DIDKeyProvider* identity);

  GraphBackendManager(const GraphBackendManager&) = delete;
  GraphBackendManager& operator=(const GraphBackendManager&) = delete;

  ~GraphBackendManager();

  // §4.1 create: a fresh, empty, local graph. Its IRI is the empty-set IRI until
  // the first write; its did is null; its trustLevel is "local". The backend is
  // owned here and returned by borrow; look it up later with Find(id).
  GraphBackend* Create(std::optional<std::string> display_name = std::nullopt);

  // §5.5 fromSnapshot: verify and materialise a graph from a snapshot. On
  // success the backend is owned here and returned by borrow; on failure returns
  // nullptr and sets |*error| to the DOMException name.
  GraphBackend* FromSnapshot(const GraphSnapshot& snap,
                             GraphTrustLevel trust,
                             std::string* error);

  // §5.5 with the default "external" trust level.
  GraphBackend* FromSnapshot(const GraphSnapshot& snap, std::string* error);

  // §6.2 mount (Graph Synchronisation Protocol, Spec 05): allocate a fresh,
  // empty, "external"-trust backend that stands in for a remote graph named by
  // |graph_did|. Unlike Create(), the DID is bound up front (a mount is opened
  // by DID, not minted locally) and no display name is set; the backend starts
  // empty and is filled by the diffs the sync module delivers. The backend is
  // owned here and returned by borrow; look it up later with Find(id).
  GraphBackend* CreateMounted(const std::string& graph_did);

  // Resolves a live graph by its internal id (§7.2 named-graph resolution), or
  // nullptr if no such graph is owned here.
  GraphBackend* Find(const std::string& id);

  // Drops the graph with internal |id| (called when the renderer's Graph is gone
  // or dissolved). Returns true if a graph was removed.
  bool Remove(const std::string& id);

 private:
  raw_ptr<DIDKeyProvider> identity_;  // Not owned.
  std::map<std::string, std::unique_ptr<GraphBackend>> graphs_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GRAPH_BACKEND_MANAGER_H_
