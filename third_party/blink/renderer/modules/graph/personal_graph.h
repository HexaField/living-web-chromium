// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_H_

#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/semantic_triple.h"
#include "third_party/blink/renderer/modules/graph/signed_triple.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"

namespace blink {

class ExecutionContext;
class ScriptPromiseResolverBase;
class ScriptState;
class SharedGraph;

// PersonalGraphManager implements the navigator.graph interface.
class PersonalGraphManager final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  PersonalGraphManager(
      ExecutionContext*,
      mojo::Remote<graph::mojom::blink::PersonalGraphService>);
  ~PersonalGraphManager() override;

  // Web IDL methods
  ScriptPromise<PersonalGraph> create(ScriptState*, const String& name);
  ScriptPromise<IDLSequence<PersonalGraph>> list(ScriptState*);
  ScriptPromise<PersonalGraph> get(ScriptState*, const String& uuid);
  ScriptPromise<IDLBoolean> remove(ScriptState*, const String& uuid);
  ScriptPromise<SharedGraph> join(ScriptState*, const String& uri);

  void Trace(Visitor*) const override;

 private:
  Member<ExecutionContext> execution_context_;
  mojo::Remote<graph::mojom::blink::PersonalGraphService> service_;
};

// Forward declare for return types used in templates.
class PersonalGraph;

// PersonalGraph implements the PersonalGraph Web IDL interface.
class PersonalGraph : public EventTarget {
  DEFINE_WRAPPERTYPEINFO();

 public:
  PersonalGraph(ExecutionContext*,
                const String& uuid,
                const String& name,
                mojo::Remote<graph::mojom::blink::PersonalGraphHost>);
  ~PersonalGraph() override;

  // Attributes
  const String& uuid() const { return uuid_; }
  const String& name() const { return name_; }
  String state() const;

  // Triple operations
  ScriptPromise<SignedTriple> addTriple(ScriptState*, SemanticTriple*);
  ScriptPromise<IDLSequence<SignedTriple>> addTriples(
      ScriptState*, const HeapVector<Member<SemanticTriple>>&);
  ScriptPromise<IDLBoolean> removeTriple(ScriptState*, SignedTriple*);
  ScriptPromise<IDLSequence<SignedTriple>> queryTriples(
      ScriptState*, const ScriptValue& query);
  ScriptPromise<IDLAny> querySparql(ScriptState*, const String& sparql);
  ScriptPromise<IDLSequence<SignedTriple>> snapshot(ScriptState*);

  // Cross-origin sharing
  ScriptPromise<IDLUndefined> grantAccess(ScriptState*,
                                           const String& origin,
                                           const String& level);
  ScriptPromise<IDLUndefined> revokeAccess(ScriptState*, const String& origin);

  // Shape operations
  ScriptPromise<IDLUndefined> addShape(ScriptState*,
                                        const String& name,
                                        const String& shacl_json);
  ScriptPromise<IDLSequence<IDLString>> getShapeInstances(
      ScriptState*, const String& shape_name);
  ScriptPromise<IDLString> createShapeInstance(ScriptState*,
                                                const String& shape_name,
                                                const ScriptValue& data);
  ScriptPromise<IDLAny> getShapeInstanceData(ScriptState*,
                                                    const String& shape_name,
                                                    const String& instance_uri);

  // Sharing
  ScriptPromise<SharedGraph> share(ScriptState*, const ScriptValue& options);

  // EventTarget
  const AtomicString& InterfaceName() const override;
  ExecutionContext* GetExecutionContext() const override;

  void Trace(Visitor*) const override;

 protected:
  String uuid_;
  String name_;
  graph::mojom::blink::GraphSyncState state_ =
      graph::mojom::blink::GraphSyncState::kPrivate;
  Member<ExecutionContext> execution_context_;
  mojo::Remote<graph::mojom::blink::PersonalGraphHost> host_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_H_
