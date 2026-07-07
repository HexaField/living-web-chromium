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

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_enforcement_mode.h"
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

namespace blink {

class CapabilityInfo;
class CapabilityProofInput;
class ExecutionContext;
class GovernanceValidationResult;
class GraphConstraint;
class GraphSnapshotOptions;
class ScriptPromiseResolverBase;
class ScriptState;
class SparqlQueryOptions;
class TripleQuery;

class Graph final : public EventTarget,
                    public graph::mojom::blink::PersonalGraphClient {
  DEFINE_WRAPPERTYPEINFO();

 public:
  Graph(ExecutionContext*,
        const graph::mojom::blink::GraphInfoPtr& info,
        mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host);

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

  // EventTarget overrides.
  const AtomicString& InterfaceName() const override;
  ExecutionContext* GetExecutionContext() const override;

  // §4.2 event handlers.
  DEFINE_ATTRIBUTE_EVENT_LISTENER(tripleadded, kTripleadded)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(tripleremoved, kTripleremoved)

  // graph::mojom::blink::PersonalGraphClient — pushed by the browser in commit
  // order (§4.2, §4.4).
  void OnTripleAdded(graph::mojom::blink::TriplePtr triple) override;
  void OnTripleRemoved(graph::mojom::blink::TriplePtr triple) override;

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

  Member<ExecutionContext> execution_context_;
  HeapMojoRemote<graph::mojom::blink::PersonalGraphHost> host_;
  HeapMojoReceiver<graph::mojom::blink::PersonalGraphClient, Graph> client_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_H_
