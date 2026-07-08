// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Graph — a named, persistent, content-addressed set of RDF 1.2 triples
// (Personal Linked Data Graphs spec §3.3). The renderer object is a thin
// EventTarget over a browser-owned PersonalGraphHost: triple operations,
// SPARQL, snapshots, provenance, and dissolution all round-trip to the browser,
// which owns the Oxigraph store and produces all cryptographic material. The
// object also binds a PersonalGraphClient receiver so the browser can push
// tripleadded / tripleremoved events (§4.2, §4.4).

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_H_

#include <utility>

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_enforcement_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_sync_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_trust_level.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/graph/graph_snapshot.h"
#include "third_party/blink/renderer/modules/graph/reifier.h"
#include "third_party/blink/renderer/modules/graph/triple.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class CapabilityInfo;
class CapabilityProofInput;
class ExecutionContext;
class GetShapesOptions;
class GovernanceValidationResult;
class GraphConstraint;
class GraphDiff;
class GraphSnapshotOptions;
class Peer;
class PublishedGraph;
class PublishOptions;
class ScriptPromiseResolverBase;
class ScriptState;
class ScriptValue;
class ShapeInfo;
class SparqlQueryOptions;
class TripleQuery;
class V8BufferSource;

class Graph final : public EventTarget,
                    public graph::mojom::blink::PersonalGraphClient {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // |read_only| gates the mutating operations synchronously (§6.3): only
  // GraphManager::mount() with MountOptions.mode = "read" passes true. Every
  // other construction path (create / fromSnapshot / groupify) leaves it false.
  Graph(ExecutionContext*,
        const graph::mojom::blink::GraphInfoPtr& info,
        mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host,
        bool read_only = false);

  // §3.3 attributes, cached from the GraphInfo at construction. The IRI is
  // refreshed after each mutation by GetIri() on the host.
  const String& id() const { return id_; }
  const String& iri() const { return iri_; }
  const String& did() const { return did_; }            // null when none
  const String& displayName() const { return display_name_; }  // null when none
  V8GraphTrustLevel trustLevel() const;

  // Internal id used to key this graph as a SPARQL named graph (§7.2).
  const String& InternalId() const { return id_; }

  // §4.2 triple operations.
  ScriptPromise<Triple> addTriple(ScriptState*, Triple* triple);
  ScriptPromise<IDLSequence<Triple>> addTriples(ScriptState*,
                                                const HeapVector<Member<Triple>>&);
  ScriptPromise<IDLBoolean> removeTriple(ScriptState*, Triple* triple);
  ScriptPromise<IDLSequence<Triple>> queryTriples(ScriptState*,
                                                  const TripleQuery* query);
  ScriptPromise<IDLAny> querySparql(ScriptState*,
                                    const String& sparql,
                                    const SparqlQueryOptions* options);
  ScriptPromise<IDLSequence<Triple>> snapshot(ScriptState*);
  ScriptPromise<IDLSequence<Reifier>> provenance(ScriptState*, Triple* triple);
  ScriptPromise<GraphSnapshot> getAsSnapshot(ScriptState*,
                                             const GraphSnapshotOptions* options);
  ScriptPromise<IDLUndefined> dissolve(ScriptState*);

  // §11 governance API — added by the Graph Capability Framework (Spec 04).
  // Advisory helpers; the mandatory enforcement point is the data-layer check in
  // addTriple()/addTriples(). Each round-trips to the per-realm GovernanceBackend
  // over the graph's own host.
  ScriptPromise<GovernanceValidationResult> canAddTriple(ScriptState*,
                                                         Triple* triple);
  ScriptPromise<GovernanceValidationResult> canPerformAction(
      ScriptState*,
      const String& action,
      const String& author_did,
      const CapabilityProofInput* proof);
  ScriptPromise<IDLSequence<GraphConstraint>> constraintsFor(
      ScriptState*,
      const String& context_did);
  ScriptPromise<IDLSequence<CapabilityInfo>> myCapabilities(ScriptState*);
  ScriptPromise<V8EnforcementMode> enforcementMode(ScriptState*);
  ScriptPromise<IDLUndefined> setEnforcementMode(ScriptState*,
                                                 const V8EnforcementMode& mode);

  // §6 synchronisation API — added by the Graph Synchronisation Protocol
  // (Spec 05). Each round-trips to the graph's own host, which owns the sync
  // backend, diff queue, and peer/session table.
  ScriptPromise<PublishedGraph> publish(ScriptState*,
                                        const PublishOptions* options);
  ScriptPromise<IDLUndefined> unpublish(ScriptState*);
  ScriptPromise<V8GraphSyncState> syncState(ScriptState*);
  ScriptPromise<IDLSequence<Peer>> peers(ScriptState*);
  ScriptPromise<IDLSequence<Peer>> onlinePeers(ScriptState*);
  ScriptPromise<IDLUSVString> currentRevision(ScriptState*);
  ScriptPromise<IDLSequence<GraphDiff>> pendingDiffs(ScriptState*);
  ScriptPromise<IDLUndefined> sendSignal(ScriptState*,
                                         const String& remote_did,
                                         const V8BufferSource* payload);
  ScriptPromise<IDLUndefined> sendSignalToSession(ScriptState*,
                                                  const String& remote_did,
                                                  const String& session_id,
                                                  const V8BufferSource* payload);
  ScriptPromise<IDLUndefined> broadcast(ScriptState*,
                                        const V8BufferSource* payload);

  // §5 shape API — added by Dynamic Graph Shape Validation (Spec 07). Each
  // round-trips to the graph's own host, which runs the per-realm ShapeService
  // against the graph's identity, governance, and store. Registration and
  // instance writes author as the browser's current identity, never named by the
  // renderer.
  ScriptPromise<IDLUndefined> addShape(ScriptState*,
                                       const String& name,
                                       const ScriptValue& shape_definition);
  ScriptPromise<IDLUndefined> removeShape(ScriptState*, const String& name);
  ScriptPromise<IDLSequence<ShapeInfo>> getShapes(ScriptState*,
                                                  const GetShapesOptions* options);
  ScriptPromise<IDLUSVString> createShapeInstance(
      ScriptState*,
      const String& shape_name,
      const String& address,
      const Vector<std::pair<String, String>>& initial_values);
  ScriptPromise<IDLSequence<IDLUSVString>> getShapeInstances(
      ScriptState*,
      const String& shape_name);
  ScriptPromise<IDLRecord<IDLString, IDLSequence<IDLString>>>
  getShapeInstanceData(ScriptState*,
                       const String& shape_name,
                       const String& address);
  ScriptPromise<IDLUndefined> setShapeProperty(ScriptState*,
                                               const String& shape_name,
                                               const String& address,
                                               const String& property,
                                               const String& value);
  ScriptPromise<IDLUndefined> addToShapeCollection(ScriptState*,
                                                   const String& shape_name,
                                                   const String& address,
                                                   const String& collection,
                                                   const String& value);
  ScriptPromise<IDLUndefined> removeFromShapeCollection(ScriptState*,
                                                        const String& shape_name,
                                                        const String& address,
                                                        const String& collection,
                                                        const String& value);

  // EventTarget overrides.
  const AtomicString& InterfaceName() const override;
  ExecutionContext* GetExecutionContext() const override;

  // §4.2 event handlers.
  DEFINE_ATTRIBUTE_EVENT_LISTENER(tripleadded, kTripleadded)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(tripleremoved, kTripleremoved)

  // §6.3 sync event handlers.
  DEFINE_ATTRIBUTE_EVENT_LISTENER(peerjoined, kPeerjoined)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(peerleft, kPeerleft)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(syncstatechange, kSyncstatechange)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(signal, kSignal)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(diff, kDiff)

  // graph::mojom::blink::PersonalGraphClient — pushed by the browser in commit
  // order (§4.2, §4.4).
  void OnTripleAdded(graph::mojom::blink::TriplePtr triple) override;
  void OnTripleRemoved(graph::mojom::blink::TriplePtr triple) override;

  // §6.3 sync events, pushed in the browser's observation order.
  void OnPeerJoined(graph::mojom::blink::PeerPtr peer) override;
  void OnPeerLeft(graph::mojom::blink::PeerPtr peer) override;
  void OnSyncStateChange(graph::mojom::blink::GraphSyncState state) override;
  void OnSignal(graph::mojom::blink::PeerPtr from,
                const Vector<uint8_t>& payload) override;
  void OnDiff(graph::mojom::blink::GraphDiffPtr diff) override;

  // Maps a browser-returned DOMException name to the matching code and rejects
  // |resolver|. Empty/unknown names reject with a generic error. Shared with
  // GraphManager::fromSnapshot(), which surfaces the same error vocabulary.
  static void RejectWithName(ScriptPromiseResolverBase* resolver,
                             const String& name);

  void Trace(Visitor*) const override;

 private:
  // Refresh the cached IRI from a successful mutation reply.
  void OnMutationSettled();

  HeapMojoRemote<graph::mojom::blink::PersonalGraphHost>& GetHost() {
    return host_;
  }

  String id_;
  String iri_;
  String did_;
  String display_name_;
  String trust_level_;
  bool dissolved_ = false;
  // §6.3: set when mounted with MountOptions.mode = "read"; gates addTriple /
  // addTriples / removeTriple with a synchronous InvalidStateError.
  bool read_only_ = false;

  Member<ExecutionContext> execution_context_;
  HeapMojoRemote<graph::mojom::blink::PersonalGraphHost> host_;
  HeapMojoReceiver<graph::mojom::blink::PersonalGraphClient, Graph> client_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_H_
