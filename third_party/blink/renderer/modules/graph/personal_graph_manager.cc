// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/personal_graph_manager.h"

#include "third_party/blink/renderer/core/dom/dom_exception.h"
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

}  // namespace blink
