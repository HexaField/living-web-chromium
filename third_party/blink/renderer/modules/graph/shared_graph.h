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
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "mojo/public/mojom/graph/graph_sync.mojom-blink.h"

namespace blink {

class SharedGraph final : public PersonalGraph {
  DEFINE_WRAPPERTYPEINFO();

 public:
  SharedGraph(ExecutionContext*, const String& uuid, const String& uri,
              mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host,
              mojo::PendingRemote<graph::mojom::blink::SharedGraphHost> shared_host);

  const String& uri() const { return uri_; }
  V8SyncState syncState() const;

  // Peer operations (Spec 03 §5.2)
  ScriptPromise<IDLAny> peers(ScriptState*);
  ScriptPromise<IDLAny> onlinePeers(ScriptState*);

  // Signalling (Spec 03 §9)
  ScriptPromise<IDLUndefined> sendSignal(ScriptState*, const String&, ScriptValue);
  ScriptPromise<IDLUndefined> broadcast(ScriptState*, ScriptValue);

  // Governance (Spec 05 §9)
  ScriptPromise<IDLAny> canAddTriple(ScriptState*, ScriptValue);
  ScriptPromise<IDLAny> constraintsFor(ScriptState*, const String& = String());
  ScriptPromise<IDLAny> myCapabilities(ScriptState*);

  const AtomicString& InterfaceName() const override;
  void Trace(Visitor*) const override;

 private:
  String uri_;
  HeapMojoRemote<graph::mojom::blink::SharedGraphHost> shared_host_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_
