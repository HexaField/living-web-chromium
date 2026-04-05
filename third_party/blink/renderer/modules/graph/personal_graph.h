// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_H_

#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_sync_state.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class PersonalGraph : public EventTarget {
  DEFINE_WRAPPERTYPEINFO();

 public:
  PersonalGraph(ExecutionContext*, const String& uuid);

  // Attributes
  const String& uuid() const { return uuid_; }
  const String& name() const { return name_; }
  V8GraphSyncState state() const;

  // Triple operations (Spec 01 §4.2)
  ScriptPromise<IDLAny> addTriple(ScriptState*, ScriptValue);
  ScriptPromise<IDLAny> addTriples(ScriptState*, ScriptValue);
  ScriptPromise<IDLAny> removeTriple(ScriptState*, ScriptValue);
  ScriptPromise<IDLAny> queryTriples(ScriptState*, ScriptValue);
  ScriptPromise<IDLAny> querySparql(ScriptState*, const String&);
  ScriptPromise<IDLAny> snapshot(ScriptState*);

  // Access control (Spec 01 §6.3)
  ScriptPromise<IDLUndefined> grantAccess(ScriptState*, const String&, const String&);
  ScriptPromise<IDLUndefined> revokeAccess(ScriptState*, const String&);

  // Shape operations (Spec 01 §5 + Spec 04 §5)
  ScriptPromise<IDLUndefined> addShape(ScriptState*, const String&, const String&);
  ScriptPromise<IDLAny> getShapes(ScriptState*);
  ScriptPromise<IDLAny> getShapeInstances(ScriptState*, const String&);
  ScriptPromise<IDLUSVString> createShapeInstance(ScriptState*, const String&, const String&, ScriptValue);
  ScriptPromise<IDLAny> getShapeInstanceData(ScriptState*, const String&, const String&);
  ScriptPromise<IDLUndefined> setShapeProperty(ScriptState*, const String&, const String&, const String&, ScriptValue);
  ScriptPromise<IDLUndefined> addToShapeCollection(ScriptState*, const String&, const String&, const String&, ScriptValue);
  ScriptPromise<IDLUndefined> removeFromShapeCollection(ScriptState*, const String&, const String&, const String&, ScriptValue);

  // Sharing (Spec 03 §5.1)
  ScriptPromise<IDLAny> share(ScriptState*, ScriptValue);

  // EventTarget overrides
  const AtomicString& InterfaceName() const override;
  ExecutionContext* GetExecutionContext() const override;

  void Trace(Visitor*) const override;

 protected:
  String uuid_;
  String name_;
  Member<ExecutionContext> execution_context_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_H_
