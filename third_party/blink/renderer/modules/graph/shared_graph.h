// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_

#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sync_state.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/modules/graph/personal_graph.h"

namespace blink {

class SharedGraph final : public PersonalGraph {
  DEFINE_WRAPPERTYPEINFO();

 public:
  SharedGraph(ExecutionContext*, const String& uuid, const String& uri);

  const String& uri() const { return uri_; }
  V8SyncState syncState() const { return V8SyncState(V8SyncState::Enum::kIdle); }

  ScriptPromise<IDLAny> peers(ScriptState*);
  ScriptPromise<IDLAny> onlinePeers(ScriptState*);
  ScriptPromise<IDLAny> sendSignal(ScriptState*, const String&, ScriptValue);
  ScriptPromise<IDLAny> broadcast(ScriptState*, ScriptValue);
  ScriptPromise<IDLAny> canAddTriple(ScriptState*, const String&, const String&);
  ScriptPromise<IDLAny> constraintsFor(ScriptState*, const String&);
  ScriptPromise<IDLAny> myCapabilities(ScriptState*);


  const AtomicString& InterfaceName() const override;
  void Trace(Visitor*) const override;

 private:
  String uri_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_
