// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/personal_graph.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/content_proof.h"
#include "third_party/blink/renderer/modules/graph/semantic_triple.h"
#include "third_party/blink/renderer/modules/graph/signed_triple.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {

// Helper to convert mojo SignedTriple to blink SignedTriple.
SignedTriple* ConvertSignedTriple(
    const graph::mojom::blink::SignedTriplePtr& mojo_triple) {
  if (!mojo_triple)
    return nullptr;
  auto* data = MakeGarbageCollected<SemanticTriple>(
      mojo_triple->data->source,
      mojo_triple->data->target,
      mojo_triple->data->predicate.has_value() ? *mojo_triple->data->predicate : String());
  auto* proof = MakeGarbageCollected<ContentProof>(
      mojo_triple->proof->key, mojo_triple->proof->signature);
  return MakeGarbageCollected<SignedTriple>(
      data, mojo_triple->author, mojo_triple->timestamp, proof);
}

}  // namespace

// =============================================================
// PersonalGraphManager
// =============================================================

PersonalGraphManager::PersonalGraphManager(
    ExecutionContext* context,
    mojo::Remote<graph::mojom::blink::PersonalGraphService> service)
    : execution_context_(context), service_(std::move(service)) {}

PersonalGraphManager::~PersonalGraphManager() = default;

ScriptPromise<IDLAny> PersonalGraphManager::create(
    ScriptState* script_state,
    const String& name) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<PersonalGraph>>(
      script_state);
  auto promise = resolver->Promise();
  // TODO: wire to service_->CreateGraph
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::list(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<PersonalGraph>>>(
          script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::get(
    ScriptState* script_state,
    const String& uuid) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<PersonalGraph>>(
      script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLBoolean> PersonalGraphManager::remove(
    ScriptState* script_state,
    const String& uuid) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::join(
    ScriptState* script_state,
    const String& uri) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SharedGraph>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

void PersonalGraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  ScriptWrappable::Trace(visitor);
}

// =============================================================
// PersonalGraph
// =============================================================

PersonalGraph::PersonalGraph(
    ExecutionContext* context,
    const String& uuid,
    const String& name,
    mojo::Remote<graph::mojom::blink::PersonalGraphHost> host)
    : uuid_(uuid),
      uuid_(uuid),
      name_(name),
      execution_context_(context),
      host_(std::move(host)) {}

PersonalGraph::~PersonalGraph() = default;

String PersonalGraph::state() const {
  switch (state_) {
    case graph::mojom::blink::GraphSyncState::kPrivate:
      return "private";
    case graph::mojom::blink::GraphSyncState::kSyncing:
      return "syncing";
    case graph::mojom::blink::GraphSyncState::kSynced:
      return "synced";
    case graph::mojom::blink::GraphSyncState::kError:
      return "error";
  }
}

ScriptPromise<IDLAny> PersonalGraph::addTriple(
    ScriptState* script_state,
    SemanticTriple* triple) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SignedTriple>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::addTriples(
    ScriptState* script_state,
    const HeapVector<Member<SemanticTriple>>& triples) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<SignedTriple>>>(
          script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLBoolean> PersonalGraph::removeTriple(
    ScriptState* script_state,
    SignedTriple* triple) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::queryTriples(
    ScriptState* script_state,
    const ScriptValue& query) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<SignedTriple>>>(
          script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::querySparql(
    ScriptState* script_state,
    const String& sparql) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::snapshot(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<SignedTriple>>>(
          script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::grantAccess(
    ScriptState* script_state,
    const String& origin,
    const String& level) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::revokeAccess(
    ScriptState* script_state,
    const String& origin) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::addShape(
    ScriptState* script_state,
    const String& name,
    const String& shacl_json) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLSequence<IDLString>> PersonalGraph::getShapeInstances(
    ScriptState* script_state,
    const String& shape_name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<IDLString>>>(
          script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLString> PersonalGraph::createShapeInstance(
    ScriptState* script_state,
    const String& shape_name,
    const ScriptValue& data) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::getShapeInstanceData(
    ScriptState* script_state,
    const String& shape_name,
    const String& instance_uri) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::share(
    ScriptState* script_state,
    const ScriptValue& options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SharedGraph>>(script_state);
  auto promise = resolver->Promise();
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError, "Not yet implemented"));
  return promise;
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
