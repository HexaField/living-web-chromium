// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// PersonalGraphHost — the Mojo host for a single graph (Spec 02 §4/§5/§7). A
// thin adapter that converts between the graph.mojom value types and the
// living_web core types and delegates every operation to a GraphBackend owned by
// the GraphBackendManager. One receiver is bound per Graph handed to a renderer.
//
// All cryptographic material (reifier signatures, snapshot proofs) is produced
// by the backend via the Spec 01 identity, never in the renderer. On failure a
// method runs its callback with a null value and the backend's DOMException-name
// last_error(); operations on a dissolved graph surface "InvalidStateError".

#ifndef CONTENT_BROWSER_GRAPH_PERSONAL_GRAPH_HOST_H_
#define CONTENT_BROWSER_GRAPH_PERSONAL_GRAPH_HOST_H_

#include <cstdint>
#include <string>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

class PersonalGraphHost : public graph::mojom::PersonalGraphHost {
 public:
  // |backend| is owned by |manager|; both outlive this host. The host binds
  // itself to |receiver| and pushes tripleadded/tripleremoved events to the
  // client supplied via Subscribe.
  PersonalGraphHost(
      GraphBackend* backend,
      GraphBackendManager* manager,
      mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver);

  PersonalGraphHost(const PersonalGraphHost&) = delete;
  PersonalGraphHost& operator=(const PersonalGraphHost&) = delete;

  ~PersonalGraphHost() override;

  // ---- mojom<->living_web converters (also used by PersonalGraphManager) ----
  static graph::mojom::TriplePtr ToMojo(const living_web::Triple& t);
  static living_web::Triple FromMojo(const graph::mojom::TriplePtr& t);
  static graph::mojom::ReifierPtr ToMojo(const living_web::Reifier& r);
  static graph::mojom::GraphSnapshotPtr ToMojo(const GraphSnapshot& s);
  static GraphSnapshot FromMojo(const graph::mojom::GraphSnapshotPtr& s);

  // Runs |handler| once the renderer drops its end of the pipe (the Graph is
  // gone). PersonalGraphManager uses this to destroy the host and release the
  // backend + its Oxigraph store, rather than leaking them for the realm's life.
  void set_disconnect_handler(base::OnceClosure handler);

  // graph::mojom::PersonalGraphHost:
  void GetIri(GetIriCallback callback) override;
  void AddTriple(graph::mojom::TriplePtr triple,
                 AddTripleCallback callback) override;
  void AddTriples(std::vector<graph::mojom::TriplePtr> triples,
                  AddTriplesCallback callback) override;
  void RemoveTriple(graph::mojom::TriplePtr triple,
                    RemoveTripleCallback callback) override;
  void QueryTriples(graph::mojom::TripleQueryPtr query,
                    QueryTriplesCallback callback) override;
  void Snapshot(SnapshotCallback callback) override;
  void Provenance(graph::mojom::TriplePtr triple,
                  ProvenanceCallback callback) override;
  void QuerySparql(const std::string& sparql,
                   const std::vector<std::string>& named_graph_ids,
                   std::optional<uint64_t> timeout_ms,
                   QuerySparqlCallback callback) override;
  void GetAsSnapshot(graph::mojom::SnapshotFormat format,
                     graph::mojom::GraphSignBy sign_by,
                     GetAsSnapshotCallback callback) override;
  void Dissolve(DissolveCallback callback) override;
  void Subscribe(mojo::PendingRemote<graph::mojom::PersonalGraphClient> client)
      override;

 private:
  // Converters between the union/enum shapes.
  static graph::mojom::LiteralValuePtr ToMojo(const living_web::LiteralValue& v);
  static living_web::LiteralValue FromMojo(
      const graph::mojom::LiteralValuePtr& v);
  static graph::mojom::TripleObjectPtr ToMojo(const living_web::ObjectTerm& o);
  static living_web::ObjectTerm FromMojo(
      const graph::mojom::TripleObjectPtr& o);
  static TripleQuery FromMojo(const graph::mojom::TripleQueryPtr& q);
  static graph::mojom::SnapshotFormat FormatToMojo(SnapshotFormat f);
  static SnapshotFormat FormatFromMojo(graph::mojom::SnapshotFormat f);
  static GraphSignBy SignByFromMojo(graph::mojom::GraphSignBy s);

  // Forwards backend commit events to the subscribed client. Bound weakly so a
  // backend that outlives this host never touches freed client state.
  void OnTripleAdded(const living_web::Triple& triple);
  void OnTripleRemoved(const living_web::Triple& triple);

  raw_ptr<GraphBackend> backend_;         // Owned by |manager_|.
  raw_ptr<GraphBackendManager> manager_;  // Not owned.
  mojo::Receiver<graph::mojom::PersonalGraphHost> receiver_;
  mojo::Remote<graph::mojom::PersonalGraphClient> client_;
  base::WeakPtrFactory<PersonalGraphHost> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_PERSONAL_GRAPH_HOST_H_
