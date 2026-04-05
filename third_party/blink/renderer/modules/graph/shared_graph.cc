// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/shared_graph.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"

namespace blink {

SharedGraph::SharedGraph(
    ExecutionContext* context,
    const String& uuid,
    const String& uri,
    mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host)
    : PersonalGraph(context, uuid, String(), std::move(host)), uri_(uri) {}

V8SyncState SharedGraph::syncState() const {
  return V8SyncState(V8SyncState::Enum::kIdle);
}

ScriptPromise<IDLAny> SharedGraph::peers(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  // Return empty array — sync not yet wired
  HeapVector<Member<ScriptWrappable>> empty;
  resolver->Resolve(empty);
  return resolver->Promise();
}

ScriptPromise<IDLAny> SharedGraph::onlinePeers(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  HeapVector<Member<ScriptWrappable>> empty;
  resolver->Resolve(empty);
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> SharedGraph::sendSignal(ScriptState* script_state,
                                                     const String&,
                                                     ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  resolver->Resolve();
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> SharedGraph::broadcast(ScriptState* script_state,
                                                    ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  resolver->Resolve();
  return resolver->Promise();
}

ScriptPromise<IDLAny> SharedGraph::canAddTriple(ScriptState* script_state,
                                                 ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  // Default: allowed
  resolver->Resolve(true);
  return resolver->Promise();
}

ScriptPromise<IDLAny> SharedGraph::constraintsFor(ScriptState* script_state,
                                                    const String&) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  HeapVector<Member<ScriptWrappable>> empty;
  resolver->Resolve(empty);
  return resolver->Promise();
}

ScriptPromise<IDLAny> SharedGraph::myCapabilities(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  HeapVector<Member<ScriptWrappable>> empty;
  resolver->Resolve(empty);
  return resolver->Promise();
}

const AtomicString& SharedGraph::InterfaceName() const {
  DEFINE_STATIC_LOCAL(const AtomicString, kSharedGraph, ("SharedGraph"));
  return kSharedGraph;
}

void SharedGraph::Trace(Visitor* visitor) const {
  PersonalGraph::Trace(visitor);
}

}  // namespace blink
