// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/personal_graph.h"

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

// --- PersonalGraphManager ---

PersonalGraphManager::PersonalGraphManager(ExecutionContext* context)
    : execution_context_(context) {}

ScriptPromise<IDLAny> PersonalGraphManager::create(ScriptState* script_state,
                                                    const String& name) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraphManager::list(ScriptState* script_state) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraphManager::listShared(
    ScriptState* script_state) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraphManager::get(ScriptState* script_state,
                                                 const String& uuid) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraphManager::remove(ScriptState* script_state,
                                                    const String& uuid) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraphManager::join(ScriptState* script_state,
                                                  const String& uri) {
  return RejectNotImplemented<IDLAny>(script_state);
}

void PersonalGraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  ScriptWrappable::Trace(visitor);
}

// --- PersonalGraph ---

PersonalGraph::PersonalGraph(ExecutionContext* context, const String& uuid)
    : EventTarget(context), uuid_(uuid), execution_context_(context) {}

String PersonalGraph::state() const {
  return "private";
}

ScriptPromise<IDLAny> PersonalGraph::addTriple(ScriptState* script_state,
                                                ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::addTriples(ScriptState* script_state,
                                                 ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::removeTriple(ScriptState* script_state,
                                                   ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::queryTriples(ScriptState* script_state,
                                                   ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::querySparql(ScriptState* script_state,
                                                  const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::snapshot(ScriptState* script_state) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::grantAccess(ScriptState* script_state,
                                                   const String&,
                                                   const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::revokeAccess(ScriptState* script_state,
                                                    const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::addShape(ScriptState* script_state,
                                               const String&,
                                               const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::getShapeInstances(
    ScriptState* script_state, const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::createShapeInstance(
    ScriptState* script_state, const String&, ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::getShapeInstanceData(
    ScriptState* script_state, const String&, const String&) {
  return RejectNotImplemented<IDLAny>(script_state);
}

ScriptPromise<IDLAny> PersonalGraph::share(ScriptState* script_state,
                                            ScriptValue) {
  return RejectNotImplemented<IDLAny>(script_state);
}

const AtomicString& PersonalGraph::InterfaceName() const {
  DEFINE_STATIC_LOCAL(const AtomicString, kPersonalGraph, ("PersonalGraph"));
  return kPersonalGraph;
}

ExecutionContext* PersonalGraph::GetExecutionContext() const {
  return execution_context_.Get();
}

void PersonalGraph::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  EventTarget::Trace(visitor);
}

}  // namespace blink
