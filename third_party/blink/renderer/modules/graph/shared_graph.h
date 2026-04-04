// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SHARED_GRAPH_H_

#include "third_party/blink/renderer/modules/graph/personal_graph.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph_sync.mojom-blink.h"
#include "mojo/public/mojom/graph/graph_governance.mojom-blink.h"

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
  ScriptPromise<IDLSequence<OnlinePeer>> onlinePeers(ScriptState*);

  // Signalling
  ScriptPromise<IDLUndefined> sendSignal(ScriptState*,
                                          const String& remote_did,
                                          ScriptValue payload);
  ScriptPromise<IDLUndefined> broadcast(ScriptState*, ScriptValue payload);

  // Governance queries
  ScriptPromise<IDLBoolean> canAddTriple(ScriptState*,
                                          const String& predicate,
                                          const String& scope_entity);
  ScriptPromise<ScriptValue> constraintsFor(ScriptState*,
                                              const String& scope_entity);
  ScriptPromise<ScriptValue> myCapabilities(ScriptState*);

  // Events
  DEFINE_ATTRIBUTE_EVENT_LISTENER(peerjoined, kPeerjoined)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(peerleft, kPeerleft)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(syncstatechange, kSyncstatechange)
  DEFINE_ATTRIBUTE_EVENT_LISTENER(signal, kSignal)

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
