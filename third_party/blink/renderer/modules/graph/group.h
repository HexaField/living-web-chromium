// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Group — the renderer handle over a browser-owned GroupHost (Decentralised
// Group Identity spec §8.1). A group is a groupified Graph plus a did:graph
// signing identity; every participation, delegate-management, assertion, and
// resolution operation round-trips to the browser, which owns the host graph's
// Oxigraph store, the group's private keys, and all governance authoring. The
// object caches its immutable-ish identity attributes from the GroupInfo it was
// built from and holds the inner Graph (`graph`) plus the GraphManager it was
// minted by (so parentGroups()/childGroups()/materialisation can re-open related
// groups).

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GROUP_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GROUP_H_

#include <optional>

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_did_capability_section.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class DelegateOptions;
class DIDDocumentMethod;
class ExecutionContext;
class Graph;
class GraphManager;
class Participant;
class ScriptState;
class SignedContent;

class Group final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  Group(ExecutionContext*,
        const graph::mojom::blink::GroupInfoPtr& info,
        mojo::PendingRemote<graph::mojom::blink::GroupHost> host,
        Graph* graph,
        GraphManager* manager);

  // §8.1 attributes, cached from the GroupInfo at construction.
  const String& did() const { return did_; }
  const String& iri() const { return iri_; }
  Graph* graph() const { return graph_.Get(); }
  const String& name() const { return name_; }              // null when none
  const String& description() const { return description_; }  // null when none
  const String& created() const { return created_; }
  const String& creator() const { return creator_; }

  // Participation — §8.1.1–8.1.3.
  ScriptPromise<IDLSequence<Participant>> participants(ScriptState*);
  ScriptPromise<IDLSequence<Participant>> transitiveParticipants(ScriptState*);
  ScriptPromise<IDLSequence<Group>> parentGroups(ScriptState*);
  ScriptPromise<IDLSequence<Group>> childGroups(ScriptState*);
  ScriptPromise<IDLUndefined> invite(ScriptState*, const String& participant_did);
  ScriptPromise<IDLUndefined> revokeParticipation(ScriptState*,
                                                  const String& participant_did);
  ScriptPromise<IDLBoolean> hasParticipant(ScriptState*, const String& did);

  // Signing authority / delegate management — §8.1.4, §5.4.
  ScriptPromise<IDLSequence<DIDDocumentMethod>> signers(
      ScriptState*,
      std::optional<V8DIDCapabilitySection> section);
  ScriptPromise<IDLUndefined> addSigner(
      ScriptState*,
      const DIDDocumentMethod* method,
      const Vector<V8DIDCapabilitySection>& sections);
  ScriptPromise<IDLUndefined> removeSigner(ScriptState*, const String& method_id);
  ScriptPromise<IDLUndefined> replaceSigner(
      ScriptState*,
      const String& old_method_id,
      const DIDDocumentMethod* new_method,
      const Vector<V8DIDCapabilitySection>& sections);
  ScriptPromise<IDLBoolean> isSigner(ScriptState*,
                                     const String& did,
                                     std::optional<V8DIDCapabilitySection> section);
  ScriptPromise<IDLUndefined> grantSection(ScriptState*,
                                           const String& method_id,
                                           const V8DIDCapabilitySection& section);
  ScriptPromise<IDLUndefined> revokeSection(ScriptState*,
                                            const String& method_id,
                                            const V8DIDCapabilitySection& section);

  // Assertion / acting delegate / deactivation — §5.4, §4.9.
  ScriptPromise<SignedContent> signGraph(ScriptState*, const String& target);
  ScriptPromise<IDLUndefined> setActingCredential(ScriptState*,
                                                  const String& credential_id);
  ScriptPromise<IDLUndefined> deactivate(ScriptState*);

  // Capability delegation — §8.1.5 (Graph Capability Framework, Spec 04).
  ScriptPromise<SignedContent> delegateCapability(ScriptState*,
                                                  const DelegateOptions* options);

  // Identity resolution — §4.7.
  ScriptPromise<IDLAny> resolve(ScriptState*);

  // Opens each did/iri in |dids| into a Group via |manager| (each a fresh
  // GroupHost + host-graph PersonalGraphHost binding) and resolves |resolver|
  // with the collected sequence. Order is preserved; entries that fail to open
  // are dropped. Shared by parentGroups()/childGroups() and
  // GraphManager.listGroups().
  static void ResolveGroupList(
      GraphManager* manager,
      ScriptPromiseResolver<IDLSequence<Group>>* resolver,
      const Vector<String>& dids);

  void Trace(Visitor*) const override;

 private:
  String did_;
  String iri_;
  String name_;
  String description_;
  String created_;
  String creator_;

  Member<ExecutionContext> execution_context_;
  Member<Graph> graph_;
  Member<GraphManager> manager_;
  HeapMojoRemote<graph::mojom::blink::GroupHost> host_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GROUP_H_
