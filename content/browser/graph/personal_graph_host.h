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
#include "content/browser/flows/flow_service.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph_sync/sync_backend.h"
#include "content/browser/shapes/shape_service.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

class PersonalGraphHost : public graph::mojom::PersonalGraphHost {
 public:
  // |backend| is owned by |manager|; both outlive this host, as do the per-realm
  // |governance| (Spec 04), |sync| (Spec 05), |shapes| (Spec 07), and |flows|
  // (Spec 10) backends — owned by PersonalGraphManager and shared with the Spec 03
  // GroupService. The host binds itself to |receiver| and pushes tripleadded/
  // tripleremoved and the §6.3 sync events to the client supplied via Subscribe.
  PersonalGraphHost(
      GraphBackend* backend,
      GraphBackendManager* manager,
      GovernanceBackend* governance,
      SyncBackend* sync,
      ShapeService* shapes,
      FlowService* flows,
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

  // ---- Spec 04 §11 governance API (folded into this host) ----
  void CanAddTriple(graph::mojom::TriplePtr triple,
                    CanAddTripleCallback callback) override;
  void CanPerformAction(const std::string& action,
                        const std::string& author_did,
                        graph::mojom::CapabilityProofInputPtr proof,
                        CanPerformActionCallback callback) override;
  void ConstraintsFor(const std::string& context_did,
                      ConstraintsForCallback callback) override;
  void MyCapabilities(MyCapabilitiesCallback callback) override;
  void GetEnforcementMode(GetEnforcementModeCallback callback) override;
  void SetEnforcementMode(graph::mojom::EnforcementMode mode,
                          SetEnforcementModeCallback callback) override;

  // ---- Spec 05 §6 sync surface (folded into this host) ----
  void Publish(graph::mojom::PublishOptionsPtr options,
               PublishCallback callback) override;
  void Unpublish(UnpublishCallback callback) override;
  void SyncState(SyncStateCallback callback) override;
  void Peers(PeersCallback callback) override;
  void OnlinePeers(OnlinePeersCallback callback) override;
  void CurrentRevision(CurrentRevisionCallback callback) override;
  void PendingDiffs(PendingDiffsCallback callback) override;
  void SendSignal(const std::string& remote_did,
                  const std::vector<uint8_t>& payload,
                  SendSignalCallback callback) override;
  void SendSignalToSession(const std::string& remote_did,
                           const std::string& session_id,
                           const std::vector<uint8_t>& payload,
                           SendSignalToSessionCallback callback) override;
  void Broadcast(const std::vector<uint8_t>& payload,
                 BroadcastCallback callback) override;

  // ---- Spec 07 §5 shape API (folded into this host) ----
  void AddShape(const std::string& name,
                const std::string& shape_json,
                AddShapeCallback callback) override;
  void RemoveShape(const std::string& name,
                   RemoveShapeCallback callback) override;
  void GetShapes(bool include_inherited, GetShapesCallback callback) override;
  void CreateShapeInstance(
      const std::string& shape_name,
      const std::string& address,
      std::vector<graph::mojom::ShapeInitialValuePtr> initial_values,
      CreateShapeInstanceCallback callback) override;
  void GetShapeInstances(const std::string& shape_name,
                         GetShapeInstancesCallback callback) override;
  void GetShapeInstanceData(const std::string& shape_name,
                            const std::string& address,
                            GetShapeInstanceDataCallback callback) override;
  void SetShapeProperty(const std::string& shape_name,
                        const std::string& address,
                        const std::string& property,
                        const std::string& value,
                        SetShapePropertyCallback callback) override;
  void AddToShapeCollection(const std::string& shape_name,
                            const std::string& address,
                            const std::string& collection,
                            const std::string& value,
                            AddToShapeCollectionCallback callback) override;
  void RemoveFromShapeCollection(
      const std::string& shape_name,
      const std::string& address,
      const std::string& collection,
      const std::string& value,
      RemoveFromShapeCollectionCallback callback) override;

  // ---- Spec 10 §5–§11 flow API (folded into this host) ----
  void AddFlow(const std::string& name,
               const std::string& flow_json,
               AddFlowCallback callback) override;
  void RemoveFlow(const std::string& name,
                  RemoveFlowCallback callback) override;
  void GetFlows(GetFlowsCallback callback) override;
  void GetFlowState(const std::string& flow_name,
                    const std::string& instance_uri,
                    GetFlowStateCallback callback) override;
  void ExecuteFlowTransition(const std::string& flow_name,
                             const std::string& instance_uri,
                             const std::string& transition_name,
                             ExecuteFlowTransitionCallback callback) override;
  void AvailableTransitions(const std::string& flow_name,
                            const std::string& instance_uri,
                            AvailableTransitionsCallback callback) override;

  // §6.2 mount initialisation. Called by PersonalGraphManager::Mount right after
  // the host is bound to open the graph as a live sync session: records the
  // resolved space + module addressing, marks the session active (and writable
  // for a write/governance mount), and moves to the synced state. Live peer
  // transport is supplied later by the graph's sync module (Spec 06); until then
  // the session is trivially converged with zero peers.
  void InitAsMount(const std::string& space_uri,
                   const std::string& module_hash,
                   bool writable);

  // §6.4 published-space inventory. PersonalGraphManager::ListSpaces aggregates
  // the realm's active sync spaces from both its mount table and the local graphs
  // its hosts have published; these accessors expose the latter without a
  // host→manager backpointer (the manager owns every host in |hosts_|).
  // |published()| is false for an idle or mounted host, so iterating hosts for
  // published() cleanly yields only published local graphs — mounts are
  // inventoried via the mount table, and the two never double-count.
  bool published() const { return published_; }
  const std::string& space_uri() const { return space_uri_; }
  const std::string& module_hash() const { return module_hash_; }

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

  // ---- Spec 04 §11 result converters ----
  static graph::mojom::EnforcementMode ModeToMojo(EnforcementMode m);
  static EnforcementMode ModeFromMojo(graph::mojom::EnforcementMode m);
  static graph::mojom::GovernanceValidationResultPtr ToMojo(
      const GovernanceValidationResult& r);
  static graph::mojom::GraphConstraintPtr ToMojo(const GraphConstraint& c);
  static graph::mojom::CapabilityInfoPtr ToMojo(const CapabilityInfo& c);

  // Forwards backend commit events to the subscribed client. Bound weakly so a
  // backend that outlives this host never touches freed client state.
  void OnTripleAdded(const living_web::Triple& triple);
  void OnTripleRemoved(const living_web::Triple& triple);

  // ---- Spec 05 §6 sync helpers ----

  // content::sync <-> mojom converters for the durable-queue readout (§6.3
  // pendingDiffs). |presentations| have no content:: representation (a browser/VC
  // concern layered above §5.3) and stay empty.
  static graph::mojom::DiffTriplePtr ToMojo(const DiffTriple& dt);
  static graph::mojom::CapabilityProofPtr ToMojo(const CapabilityProof& p);
  static graph::mojom::GraphDiffPtr ToMojo(const GraphDiff& d);

  // Updates the cached sync state and, if a client is subscribed, pushes
  // onsyncstatechange (§6.3).
  void SetSyncState(graph::mojom::GraphSyncState state);

  // ---- Spec 07 §5 result converters ----
  static graph::mojom::ShapePropertyInfoPtr ToMojo(const ShapePropertyInfo& p);
  static graph::mojom::ShapeInfoPtr ToMojo(const ShapeInfo& s);

  // ---- Spec 10 §11.1 result converters ----
  static graph::mojom::FlowInfoPtr ToMojo(const FlowInfo& f);
  static graph::mojom::FlowTransitionResultPtr ToMojo(
      const FlowTransitionResult& r);

  // §6.3 signalling gate: "InvalidStateError" when the graph is not
  // published/mounted, else nullopt (a no-op success — the payload is dropped
  // until a sync module supplies transport, Spec 06).
  std::optional<std::string> SignalGate() const;

  // §6.1 step 1: the authoritative sync-module hash bound to the graph's DID by
  // <graphDid> group://syncModule (Spec 03 §4.5), or "" when the graph is not yet
  // groupified.
  std::string ResolveGroupSyncModule();

  // §5.2.2 commit hook. When the graph holds a writable sync session (published,
  // or write/governance-mounted), turns a committed local mutation into a signed
  // GraphDiff, advances the local DAG head, and enqueues it in the durable queue
  // (§13.1) for the sync module to gossip. A no-op outside a writable session
  // (ordinary Spec 02 mutations are not gossiped).
  void EmitDiff(const std::vector<living_web::Triple>& additions,
                const std::vector<living_web::Triple>& removals);

  raw_ptr<GraphBackend> backend_;          // Owned by |manager_|.
  raw_ptr<GraphBackendManager> manager_;   // Not owned.
  raw_ptr<GovernanceBackend> governance_;  // Per-realm; owned by the manager.
  raw_ptr<SyncBackend> sync_;              // Per-realm; owned by the manager.
  raw_ptr<ShapeService> shapes_;           // Per-realm; owned by the manager.
  raw_ptr<FlowService> flows_;             // Per-realm; owned by the manager.
  mojo::Receiver<graph::mojom::PersonalGraphHost> receiver_;
  mojo::Remote<graph::mojom::PersonalGraphClient> client_;

  // §6 sync-session state. A graph is idle until published (a local graph made
  // shareable) or mounted (a remote graph opened into this realm). |session_|
  // gates signalling; |writable_| additionally gates diff emission.
  bool published_ = false;
  bool session_active_ = false;
  bool session_writable_ = false;
  graph::mojom::GraphSyncState sync_state_ = graph::mojom::GraphSyncState::kIdle;
  std::string space_uri_;
  std::string module_hash_;
  std::vector<std::string> relays_;
  DiffQueue diff_queue_;            // §13.1 durable local diff queue
  std::string current_revision_;   // local DAG head (§5.2.1); "" until first commit
  uint32_t diffs_since_snapshot_ = 0;  // §5.2.3

  base::WeakPtrFactory<PersonalGraphHost> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_PERSONAL_GRAPH_HOST_H_
