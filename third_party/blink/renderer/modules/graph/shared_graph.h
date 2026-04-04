// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_

#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph_governance.mojom-blink.h"
#include "mojo/public/mojom/graph/graph_sync.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/modules/graph/personal_graph.h"

namespace blink {

// SharedGraph extends PersonalGraph with P2P sync and governance.
class SharedGraph final : public PersonalGraph {
  DEFINE_WRAPPERTYPEINFO();

 public:
  SharedGraph(ExecutionContext*,
              const String& uuid,
              const String& name,
              const String& uri,
              mojo::Remote<graph::mojom::blink::PersonalGraphHost>,
              mojo::Remote<graph::mojom::blink::SharedGraphHost>,
              mojo::Remote<graph::mojom::blink::GovernanceService>);
  ~SharedGraph() override;

  // Attributes
  const String& uri() const { return uri_; }
  String syncState() const;

  // Peer operations
  ScriptPromise<IDLSequence<IDLString>> peers(ScriptState*);
  ScriptPromise<IDLAny> onlinePeers(ScriptState*);

  // Signalling
  ScriptPromise<IDLUndefined> sendSignal(ScriptState*,
                                          const String& remote_did,
                                          const ScriptValue& payload);
  ScriptPromise<IDLUndefined> broadcast(ScriptState*,
                                         const ScriptValue& payload);

  // Governance queries
  ScriptPromise<IDLBoolean> canAddTriple(ScriptState*,
                                          const String& predicate,
                                          const String& scope_entity);
  ScriptPromise<IDLAny> constraintsFor(ScriptState*,
                                              const String& scope_entity);
  ScriptPromise<IDLAny> myCapabilities(ScriptState*);

  void Trace(Visitor*) const override;

 private:
  String uri_;
  graph::mojom::blink::SyncState sync_state_ =
      graph::mojom::blink::SyncState::kIdle;
  mojo::Remote<graph::mojom::blink::SharedGraphHost> sync_host_;
  mojo::Remote<graph::mojom::blink::GovernanceService> governance_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_
