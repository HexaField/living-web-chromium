// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph.h"

#include <utility>

#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_snapshot_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sparql_query_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_triple_query.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_usvstring_literalvalue.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/graph_triple_event.h"
#include "third_party/blink/renderer/modules/graph/literal_value.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

scoped_refptr<base::SequencedTaskRunner> GetTaskRunner(
    ExecutionContext* context) {
  // SingleThreadTaskRunner IS-A SequencedTaskRunner; explicit cast needed.
  return static_cast<scoped_refptr<base::SequencedTaskRunner>>(
      context->GetTaskRunner(TaskType::kMiscPlatformAPI));
}

// §3.1: the Triple.object union crosses the boundary as a TripleObject: either
// an IRI / blank node, or a LiteralValue.
graph::mojom::blink::TripleObjectPtr ObjectToMojo(
    const V8UnionUSVStringOrLiteralValue* object) {
  if (object->IsLiteralValue()) {
    LiteralValue* literal = object->GetAsLiteralValue();
    auto mojo_literal = graph::mojom::blink::LiteralValue::New();
    mojo_literal->lexical = literal->lexicalValue();
    mojo_literal->datatype = literal->datatype();
    // Nullable string? — a null WTF::String means "no language tag".
    mojo_literal->language = literal->language();
    return graph::mojom::blink::TripleObject::NewLiteral(
        std::move(mojo_literal));
  }
  return graph::mojom::blink::TripleObject::NewIriOrBnode(
      object->GetAsUSVString());
}

V8UnionUSVStringOrLiteralValue* ObjectFromMojo(
    const graph::mojom::blink::TripleObjectPtr& object) {
  if (object->is_literal()) {
    const auto& literal = object->get_literal();
    // literal->language is a nullable WTF::String (null when absent).
    auto* value = MakeGarbageCollected<LiteralValue>(
        literal->lexical, literal->datatype, literal->language);
    return MakeGarbageCollected<V8UnionUSVStringOrLiteralValue>(value);
  }
  return MakeGarbageCollected<V8UnionUSVStringOrLiteralValue>(
      object->get_iri_or_bnode());
}

graph::mojom::blink::TriplePtr TripleToMojo(const Triple* triple) {
  auto mojo_triple = graph::mojom::blink::Triple::New();
  mojo_triple->subject = triple->subject();
  mojo_triple->predicate = triple->predicate();
  mojo_triple->object = ObjectToMojo(triple->object());
  return mojo_triple;
}

Triple* TripleFromMojo(const graph::mojom::blink::TriplePtr& triple) {
  return MakeGarbageCollected<Triple>(triple->subject, triple->predicate,
                                      ObjectFromMojo(triple->object));
}

HeapVector<Member<Triple>> TriplesFromMojo(
    const Vector<graph::mojom::blink::TriplePtr>& triples) {
  HeapVector<Member<Triple>> out;
  out.ReserveInitialCapacity(triples.size());
  for (const auto& triple : triples)
    out.push_back(TripleFromMojo(triple));
  return out;
}

Reifier* ReifierFromMojo(const graph::mojom::blink::ReifierPtr& reifier) {
  return MakeGarbageCollected<Reifier>(
      reifier->id, TripleFromMojo(reifier->triple), reifier->author,
      reifier->timestamp, reifier->method, reifier->signature);
}

// §3.5 TripleQuery -> Mojo. Absent fields stay null so the browser treats them
// as unconstrained; all supplied fields combine with logical AND.
graph::mojom::blink::TripleQueryPtr QueryToMojo(const TripleQuery* query) {
  auto out = graph::mojom::blink::TripleQuery::New();
  if (query->hasSubject())
    out->subject = query->subject();
  if (query->hasPredicate())
    out->predicate = query->predicate();
  if (query->hasObject())
    out->object = ObjectToMojo(query->object());
  if (query->hasAuthor())
    out->author = query->author();
  if (query->hasFromDate())
    out->from_date = query->fromDate();
  if (query->hasUntilDate())
    out->until_date = query->untilDate();
  if (query->hasOffset())
    out->offset = query->offset();
  if (query->hasLimit())
    out->limit = query->limit();
  return out;
}

}  // namespace

Graph::Graph(ExecutionContext* context,
             const graph::mojom::blink::GraphInfoPtr& info,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host)
    : id_(info->id),
      iri_(info->iri),
      did_(info->did),
      display_name_(info->display_name),
      trust_level_(info->trust_level ==
                           graph::mojom::blink::GraphTrustLevel::kLocal
                       ? "local"
                       : "external"),
      execution_context_(context),
      host_(context),
      client_(this, context) {
  host_.Bind(std::move(host), GetTaskRunner(context));
  // §4.2/§4.4: subscribe for tripleadded / tripleremoved pushes.
  host_->Subscribe(client_.BindNewPipeAndPassRemote(GetTaskRunner(context)));
}

V8GraphTrustLevel Graph::trustLevel() const {
  return trust_level_ == "local"
             ? V8GraphTrustLevel(V8GraphTrustLevel::Enum::kLocal)
             : V8GraphTrustLevel(V8GraphTrustLevel::Enum::kExternal);
}

// static
void Graph::RejectWithName(ScriptPromiseResolverBase* resolver,
                           const String& name) {
  struct {
    const char* name;
    DOMExceptionCode code;
  } static constexpr kMap[] = {
      {"InvalidStateError", DOMExceptionCode::kInvalidStateError},
      {"NotAllowedError", DOMExceptionCode::kNotAllowedError},
      {"DataError", DOMExceptionCode::kDataError},
      {"NotSupportedError", DOMExceptionCode::kNotSupportedError},
      {"QuotaExceededError", DOMExceptionCode::kQuotaExceededError},
      {"TimeoutError", DOMExceptionCode::kTimeoutError},
      {"NotFoundError", DOMExceptionCode::kNotFoundError},
  };
  for (const auto& entry : kMap) {
    if (name == entry.name) {
      resolver->RejectWithDOMException(entry.code, name);
      return;
    }
  }
  resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                   name.empty() ? "Graph operation failed"
                                                : name);
}

ScriptPromise<Triple> Graph::addTriple(ScriptState* script_state,
                                       Triple* triple) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Triple>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->AddTriple(
      TripleToMojo(triple),
      WTF::BindOnce(
          [](ScriptPromiseResolver<Triple>* resolver, Graph* graph,
             graph::mojom::blink::TriplePtr added, const String& iri,
             const String& error) {
            if (!added || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            // §4.2 step 6/8: the IRI is current the moment the promise settles.
            if (!iri.IsNull())
              graph->iri_ = iri;
            resolver->Resolve(TripleFromMojo(added));
          },
          WrapPersistent(resolver), WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLSequence<Triple>> Graph::addTriples(
    ScriptState* script_state,
    const HeapVector<Member<Triple>>& triples) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Triple>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  Vector<graph::mojom::blink::TriplePtr> mojo_triples;
  mojo_triples.reserve(triples.size());
  for (const auto& triple : triples)
    mojo_triples.push_back(TripleToMojo(triple));

  host_->AddTriples(
      std::move(mojo_triples),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<Triple>>* resolver, Graph* graph,
             std::optional<Vector<graph::mojom::blink::TriplePtr>> added,
             const String& iri, const String& error) {
            if (!added || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            if (!iri.IsNull())
              graph->iri_ = iri;
            resolver->Resolve(TriplesFromMojo(*added));
          },
          WrapPersistent(resolver), WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLBoolean> Graph::removeTriple(ScriptState* script_state,
                                              Triple* triple) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->RemoveTriple(
      TripleToMojo(triple),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver, Graph* graph,
             bool removed, const String& iri, const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            if (!iri.IsNull())
              graph->iri_ = iri;
            resolver->Resolve(removed);
          },
          WrapPersistent(resolver), WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLSequence<Triple>> Graph::queryTriples(
    ScriptState* script_state,
    const TripleQuery* query) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Triple>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->QueryTriples(
      QueryToMojo(query),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<Triple>>* resolver,
             std::optional<Vector<graph::mojom::blink::TriplePtr>> triples,
             const String& error) {
            if (!triples || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(TriplesFromMojo(*triples));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> Graph::querySparql(ScriptState* script_state,
                                         const String& sparql,
                                         const SparqlQueryOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  // §7.2: named graphs are keyed by their internal id; the browser resolves
  // them against the graphs it owns.
  Vector<String> named_graph_ids;
  if (options->hasNamedGraphs()) {
    named_graph_ids.reserve(options->namedGraphs().size());
    for (const auto& named : options->namedGraphs())
      named_graph_ids.push_back(named->InternalId());
  }

  std::optional<uint64_t> timeout_ms;
  if (options->hasTimeout())
    timeout_ms = options->timeout();

  host_->QuerySparql(
      sparql, std::move(named_graph_ids), timeout_ms,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             graph::mojom::blink::SparqlQueryResultPtr result) {
            ScriptState* ss = resolver->GetScriptState();
            if (!ss->ContextIsValid())
              return;
            if (!result->ok) {
              RejectWithName(resolver, result->error);
              return;
            }
            ScriptState::Scope scope(ss);
            v8::Isolate* isolate = ss->GetIsolate();
            // kind 0 (Solutions) / 1 (Boolean): SPARQL 1.1 JSON Results.
            // kind 2 (Graph): RDF 1.2 N-Triples — resolve the raw string.
            if (result->kind == 2) {
              resolver->Resolve(
                  ScriptValue(isolate, V8String(isolate, result->payload)));
              return;
            }
            v8::Local<v8::String> json = V8String(isolate, result->payload);
            v8::Local<v8::Value> parsed;
            if (v8::JSON::Parse(ss->GetContext(), json).ToLocal(&parsed)) {
              resolver->Resolve(ScriptValue(isolate, parsed));
            } else {
              resolver->Resolve(ScriptValue(isolate, json));
            }
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<Triple>> Graph::snapshot(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Triple>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->Snapshot(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Triple>>* resolver,
         std::optional<Vector<graph::mojom::blink::TriplePtr>> triples,
         const String& error) {
        if (!triples || !error.IsNull()) {
          RejectWithName(resolver, error);
          return;
        }
        resolver->Resolve(TriplesFromMojo(*triples));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<Reifier>> Graph::provenance(ScriptState* script_state,
                                                      Triple* triple) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Reifier>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->Provenance(
      TripleToMojo(triple),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<Reifier>>* resolver,
             std::optional<Vector<graph::mojom::blink::ReifierPtr>> reifiers,
             const String& error) {
            if (!reifiers || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            HeapVector<Member<Reifier>> out;
            out.ReserveInitialCapacity(reifiers->size());
            for (const auto& reifier : *reifiers)
              out.push_back(ReifierFromMojo(reifier));
            resolver->Resolve(std::move(out));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<GraphSnapshot> Graph::getAsSnapshot(
    ScriptState* script_state,
    const GraphSnapshotOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<GraphSnapshot>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  graph::mojom::blink::SnapshotFormat format =
      GraphSnapshot::FormatFromString(options->format().AsString());
  graph::mojom::blink::GraphSignBy sign_by =
      GraphSnapshot::SignByFromString(options->signBy().AsString());

  host_->GetAsSnapshot(
      format, sign_by,
      WTF::BindOnce(
          [](ScriptPromiseResolver<GraphSnapshot>* resolver,
             graph::mojom::blink::GraphSnapshotPtr snapshot,
             const String& error) {
            if (!snapshot || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(GraphSnapshot::FromMojo(snapshot));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::dissolve(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  // §4.3: dissolve is idempotent — resolve immediately if already dissolved.
  if (dissolved_ || !host_.is_bound()) {
    dissolved_ = true;
    resolver->Resolve();
    return promise;
  }

  host_->Dissolve(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLUndefined>* resolver, Graph* graph) {
        graph->dissolved_ = true;
        graph->host_.reset();
        if (graph->client_.is_bound())
          graph->client_.reset();
        resolver->Resolve();
      },
      WrapPersistent(resolver), WrapPersistent(this)));

  return promise;
}

void Graph::OnTripleAdded(graph::mojom::blink::TriplePtr triple) {
  // §5.2: the IRI advanced with this write; refresh the cached value.
  OnMutationSettled();
  DispatchEvent(*GraphTripleEvent::Create(event_type_names::kTripleadded,
                                          TripleFromMojo(triple)));
}

void Graph::OnTripleRemoved(graph::mojom::blink::TriplePtr triple) {
  OnMutationSettled();
  DispatchEvent(*GraphTripleEvent::Create(event_type_names::kTripleremoved,
                                          TripleFromMojo(triple)));
}

void Graph::OnMutationSettled() {
  if (!host_.is_bound())
    return;
  host_->GetIri(WTF::BindOnce(
      [](Graph* graph, const String& iri, const String& error) {
        if (error.IsNull() && !iri.IsNull())
          graph->iri_ = iri;
      },
      WrapPersistent(this)));
}

const AtomicString& Graph::InterfaceName() const {
  return event_target_names::kGraph;
}

ExecutionContext* Graph::GetExecutionContext() const {
  return execution_context_.Get();
}

void Graph::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(host_);
  visitor->Trace(client_);
  EventTarget::Trace(visitor);
}

}  // namespace blink
