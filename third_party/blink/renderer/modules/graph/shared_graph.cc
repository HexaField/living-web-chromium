// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/shared_graph.h"

#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"

namespace blink {

namespace {

template <typename T>
ScriptPromise<T> RejectNotImplemented(ScriptState* script_state) {
  return ScriptPromise<T>::RejectWithDOMException(
      script_state,
      MakeGarbageCollected<DOMException>(DOMExceptionCode::kNotSupportedError,
                                         "Not yet implemented"));
}

}  // namespace

SharedGraph::SharedGraph(ExecutionContext* context,
                         const String& uuid,
                         const String& uri)
    : PersonalGraph(context, uuid), uri_(uri) {}

String SharedGraph::syncState() const {
  return "idle";
}

ScriptPromise<IDLAny> SharedGraph::peers(ScriptState* script_state) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> SharedGraph::onlinePeers(ScriptState* script_state) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> SharedGraph::sendSignal(ScriptState* script_state,
                                               const String&,
                                               ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> SharedGraph::broadcast(ScriptState* script_state,
                                              ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> SharedGraph::canAddTriple(ScriptState* script_state,
                                                 const String&,
                                                 const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> SharedGraph::constraintsFor(ScriptState* script_state,
                                                    const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> SharedGraph::myCapabilities(ScriptState* script_state) {
  return RejectNotImplemented<IDLAny>(script_state);
}

const AtomicString& SharedGraph::InterfaceName() const {
  DEFINE_STATIC_LOCAL(const AtomicString, kSharedGraph, ("SharedGraph"));
  return kSharedGraph;
}

void SharedGraph::Trace(Visitor* visitor) const {
  PersonalGraph::Trace(visitor);
}

}  // namespace blink
