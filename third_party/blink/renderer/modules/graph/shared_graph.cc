// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/shared_graph.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"

namespace blink {

SharedGraph::SharedGraph(
    ExecutionContext* context,
    const String& uuid,
    const String& name,
    const String& uri,
    mojo::Remote<graph::mojom::blink::PersonalGraphHost> graph_host,
    mojo::Remote<graph::mojom::blink::SharedGraphHost> sync_host,
    mojo::Remote<graph::mojom::blink::GovernanceService> governance)
    : PersonalGraph(context, uuid, name, std::move(graph_host)),
      uri_(uri),
      sync_host_(std::move(sync_host)),
      governance_(std::move(governance)) {}

SharedGraph::~SharedGraph() = default;

String SharedGraph::syncState() const {
  switch (sync_state_) {
    case graph::mojom::blink::SyncState::kIdle:
      return "idle";
    case graph::mojom::blink::SyncState::kSyncing:
      return "syncing";
    case graph::mojom::blink::SyncState::kSynced:
      return "synced";
    case graph::mojom::blink::SyncState::kError:
      return "error";
  }
}

ScriptPromise<IDLSequence<IDLString>> SharedGraph::peers(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<
          ScriptPromiseResolver<IDLSequence<IDLString>>>(script_state);
  auto promise = resolver->Promise();

  sync_host_->GetPeers(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<IDLString>>* resolver,
         WTF::Vector<String> dids) {
        resolver->Resolve(dids);
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> SharedGraph::sendSignal(
    ScriptState* script_state,
    const String& remote_did,
    ScriptValue payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  // Serialize payload to JSON string.
  // In full implementation: V8ValueConverter to JSON.
  String payload_json = "{}";  // TODO: proper serialization

  sync_host_->SendSignal(
      remote_did, payload_json,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool success) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> SharedGraph::broadcast(
    ScriptState* script_state,
    ScriptValue payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  sync_host_->Broadcast(
      "{}",  // TODO: serialize payload
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool success) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLBoolean> SharedGraph::canAddTriple(
    ScriptState* script_state,
    const String& predicate,
    const String& scope_entity) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  // Get active DID from the DID credential service.
  // For now, use empty string — real impl would query DIDCredentialService.
  String agent_did = "";

  governance_->CanAddTriple(
      uri_, agent_did, predicate, scope_entity,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver,
             graph::mojom::blink::ValidationResultPtr result) {
            resolver->Resolve(result->accepted);
          },
          WrapPersistent(resolver)));

  return promise;
}

void SharedGraph::Trace(Visitor* visitor) const {
  PersonalGraph::Trace(visitor);
}

}  // namespace blink
