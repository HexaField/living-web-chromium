// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/personal_graph.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

// =============================================================
// PersonalGraphManager
// =============================================================

PersonalGraphManager::PersonalGraphManager(
    ExecutionContext* context,
    mojo::Remote<graph::mojom::blink::PersonalGraphService> service)
    : execution_context_(context), service_(std::move(service)) {}

PersonalGraphManager::~PersonalGraphManager() = default;

ScriptPromise<PersonalGraph> PersonalGraphManager::create(
    ScriptState* script_state,
    const String& name) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<PersonalGraph>>(
      script_state);
  auto promise = resolver->Promise();

  service_->CreateGraph(
      name,
      WTF::BindOnce(
          [](ScriptPromiseResolver<PersonalGraph>* resolver,
             ExecutionContext* context,
             mojo::Remote<graph::mojom::blink::PersonalGraphService>& service,
             graph::mojom::blink::GraphInfoPtr info) {
            if (!info) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kOperationError,
                  "Failed to create graph"));
              return;
            }
            // Bind a PersonalGraphHost for this graph.
            mojo::Remote<graph::mojom::blink::PersonalGraphHost> host;
            service->BindGraph(info->uuid,
                               host.BindNewPipeAndPassReceiver());

            auto* graph = MakeGarbageCollected<PersonalGraph>(
                context, info->uuid, info->name, std::move(host));
            resolver->Resolve(graph);
          },
          WrapPersistent(resolver),
          WrapPersistent(execution_context_.Get()),
          std::ref(service_)));

  return promise;
}

ScriptPromise<IDLSequence<PersonalGraph>> PersonalGraphManager::list(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<PersonalGraph>>>(
          script_state);
  auto promise = resolver->Promise();

  service_->ListGraphs(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<PersonalGraph>>* resolver,
         ExecutionContext* context,
         WTF::Vector<graph::mojom::blink::GraphInfoPtr> infos) {
        HeapVector<Member<PersonalGraph>> graphs;
        for (auto& info : infos) {
          // Note: In production, each would need its own BindGraph call.
          // Simplified here — real impl would batch-bind.
          graphs.push_back(MakeGarbageCollected<PersonalGraph>(
              context, info->uuid, info->name,
              mojo::Remote<graph::mojom::blink::PersonalGraphHost>()));
        }
        resolver->Resolve(graphs);
      },
      WrapPersistent(resolver),
      WrapPersistent(execution_context_.Get())));

  return promise;
}

ScriptPromise<PersonalGraph> PersonalGraphManager::get(
    ScriptState* script_state,
    const String& uuid) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<PersonalGraph>>(
      script_state);
  auto promise = resolver->Promise();

  service_->GetGraph(
      uuid,
      WTF::BindOnce(
          [](ScriptPromiseResolver<PersonalGraph>* resolver,
             ExecutionContext* context,
             graph::mojom::blink::GraphInfoPtr info) {
            if (!info) {
              resolver->Resolve(nullptr);
              return;
            }
            resolver->Resolve(MakeGarbageCollected<PersonalGraph>(
                context, info->uuid, info->name,
                mojo::Remote<graph::mojom::blink::PersonalGraphHost>()));
          },
          WrapPersistent(resolver),
          WrapPersistent(execution_context_.Get())));

  return promise;
}

ScriptPromise<IDLBoolean> PersonalGraphManager::remove(
    ScriptState* script_state,
    const String& uuid) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  service_->RemoveGraph(
      uuid,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver, bool success) {
            resolver->Resolve(success);
          },
          WrapPersistent(resolver)));

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
    : EventTarget(context),
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

ScriptPromise<SignedTriple> PersonalGraph::addTriple(
    ScriptState* script_state,
    SemanticTriple* triple) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SignedTriple>>(script_state);
  auto promise = resolver->Promise();

  auto mojo_triple = graph::mojom::blink::SemanticTriple::New();
  mojo_triple->source = triple->source();
  mojo_triple->target = triple->target();
  mojo_triple->predicate = triple->predicate();

  host_->AddTriple(
      std::move(mojo_triple),
      WTF::BindOnce(
          [](ScriptPromiseResolver<SignedTriple>* resolver,
             graph::mojom::blink::SignedTriplePtr result) {
            if (!result) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kInvalidStateError,
                  "Failed to add triple — no active identity?"));
              return;
            }
            // Convert Mojo SignedTriple to Blink SignedTriple.
            // In full implementation, this creates the Blink wrapper objects.
            // Simplified: resolver->Resolve(ConvertSignedTriple(result));
            resolver->Resolve(nullptr);  // TODO: proper conversion
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<SignedTriple>> PersonalGraph::addTriples(
    ScriptState* script_state,
    const HeapVector<Member<SemanticTriple>>& triples) {
  auto* resolver =
      MakeGarbageCollected<
          ScriptPromiseResolver<IDLSequence<SignedTriple>>>(script_state);
  auto promise = resolver->Promise();

  WTF::Vector<graph::mojom::blink::SemanticTriplePtr> mojo_triples;
  for (const auto& triple : triples) {
    auto mt = graph::mojom::blink::SemanticTriple::New();
    mt->source = triple->source();
    mt->target = triple->target();
    mt->predicate = triple->predicate();
    mojo_triples.push_back(std::move(mt));
  }

  host_->AddTriples(
      std::move(mojo_triples),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<SignedTriple>>* resolver,
             WTF::Vector<graph::mojom::blink::SignedTriplePtr> results) {
            // TODO: convert and resolve
            HeapVector<Member<SignedTriple>> converted;
            resolver->Resolve(converted);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLBoolean> PersonalGraph::removeTriple(
    ScriptState* script_state,
    SignedTriple* triple) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  // TODO: convert Blink SignedTriple to Mojo and call host_->RemoveTriple
  host_->RemoveTriple(
      graph::mojom::blink::SignedTriplePtr(),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver, bool success) {
            resolver->Resolve(success);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<SignedTriple>> PersonalGraph::queryTriples(
    ScriptState* script_state,
    const TripleQuery* query) {
  auto* resolver =
      MakeGarbageCollected<
          ScriptPromiseResolver<IDLSequence<SignedTriple>>>(script_state);
  auto promise = resolver->Promise();

  auto mojo_query = graph::mojom::blink::TripleQuery::New();
  // Map TripleQuery fields to mojo struct.
  // In full implementation, each field is mapped.

  host_->QueryTriples(
      std::move(mojo_query),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<SignedTriple>>* resolver,
             WTF::Vector<graph::mojom::blink::SignedTriplePtr> results) {
            HeapVector<Member<SignedTriple>> converted;
            // TODO: convert each result
            resolver->Resolve(converted);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<SparqlResult> PersonalGraph::querySparql(
    ScriptState* script_state,
    const String& sparql) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SparqlResult>>(script_state);
  auto promise = resolver->Promise();

  host_->QuerySparql(
      sparql,
      WTF::BindOnce(
          [](ScriptPromiseResolver<SparqlResult>* resolver,
             graph::mojom::blink::SparqlResultPtr result) {
            // TODO: convert to Blink SparqlResult
            resolver->Resolve(nullptr);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<SignedTriple>> PersonalGraph::snapshot(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<
          ScriptPromiseResolver<IDLSequence<SignedTriple>>>(script_state);
  auto promise = resolver->Promise();

  host_->Snapshot(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<SignedTriple>>* resolver,
         WTF::Vector<graph::mojom::blink::SignedTriplePtr> triples) {
        HeapVector<Member<SignedTriple>> converted;
        resolver->Resolve(converted);
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::grantAccess(
    ScriptState* script_state,
    const String& origin,
    const String& level) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  auto access_level = (level == "readwrite")
      ? graph::mojom::blink::GraphAccessLevel::kReadWrite
      : graph::mojom::blink::GraphAccessLevel::kRead;

  host_->GrantAccess(
      origin, access_level,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool success) {
            if (success)
              resolver->Resolve();
            else
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kNotAllowedError,
                  "Access grant denied"));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::revokeAccess(
    ScriptState* script_state,
    const String& origin) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  host_->RevokeAccess(
      origin,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool success) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::addShape(
    ScriptState* script_state,
    const String& name,
    const String& shacl_json) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  host_->AddShape(
      name, shacl_json,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool success) {
            if (success)
              resolver->Resolve();
            else
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kSyntaxError,
                  "Invalid shape definition"));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<IDLString>> PersonalGraph::getShapeInstances(
    ScriptState* script_state,
    const String& shape_name) {
  auto* resolver =
      MakeGarbageCollected<
          ScriptPromiseResolver<IDLSequence<IDLString>>>(script_state);
  auto promise = resolver->Promise();

  host_->GetShapeInstances(
      shape_name,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<IDLString>>* resolver,
             WTF::Vector<String> uris) {
            resolver->Resolve(uris);
          },
          WrapPersistent(resolver)));

  return promise;
}

const AtomicString& PersonalGraph::InterfaceName() const {
  return event_target_names::kPersonalGraph;
}

ExecutionContext* PersonalGraph::GetExecutionContext() const {
  return execution_context_.Get();
}

void PersonalGraph::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  EventTarget::Trace(visitor);
}

}  // namespace blink
