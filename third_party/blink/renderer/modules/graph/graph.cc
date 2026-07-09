// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph.h"

#include <utility>

#include "base/containers/span.h"
#include "base/notreached.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_capability_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_capability_proof_input.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_flow_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_flow_transition_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_get_shapes_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_governance_validation_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_constraint.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_snapshot_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_sync_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_publish_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shape_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_shape_property_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sparql_query_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_triple_query.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_usvstring_literalvalue.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/graph/diff_event.h"
#include "third_party/blink/renderer/modules/graph/flow_transition_event.h"
#include "third_party/blink/renderer/modules/graph/graph_diff.h"
#include "third_party/blink/renderer/modules/graph/graph_triple_event.h"
#include "third_party/blink/renderer/modules/graph/literal_value.h"
#include "third_party/blink/renderer/modules/graph/peer.h"
#include "third_party/blink/renderer/modules/graph/peer_event.h"
#include "third_party/blink/renderer/modules/graph/published_graph.h"
#include "third_party/blink/renderer/modules/graph/signal_event.h"
#include "third_party/blink/renderer/modules/graph/sync_state_event.h"
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

// §11 EnforcementMode: Mojo enum <-> V8 enum.
V8EnforcementMode EnforcementModeToV8(graph::mojom::blink::EnforcementMode mode) {
  switch (mode) {
    case graph::mojom::blink::EnforcementMode::kOpen:
      return V8EnforcementMode(V8EnforcementMode::Enum::kOpen);
    case graph::mojom::blink::EnforcementMode::kAnnounced:
      return V8EnforcementMode(V8EnforcementMode::Enum::kAnnounced);
    case graph::mojom::blink::EnforcementMode::kEnforced:
      return V8EnforcementMode(V8EnforcementMode::Enum::kEnforced);
  }
  NOTREACHED();
}

graph::mojom::blink::EnforcementMode EnforcementModeFromV8(
    const V8EnforcementMode& mode) {
  switch (mode.AsEnum()) {
    case V8EnforcementMode::Enum::kOpen:
      return graph::mojom::blink::EnforcementMode::kOpen;
    case V8EnforcementMode::Enum::kAnnounced:
      return graph::mojom::blink::EnforcementMode::kAnnounced;
    case V8EnforcementMode::Enum::kEnforced:
      return graph::mojom::blink::EnforcementMode::kEnforced;
  }
  NOTREACHED();
}

// §5.5 GraphSyncState: Mojo enum -> V8 enum.
V8GraphSyncState SyncStateToV8(graph::mojom::blink::GraphSyncState state) {
  switch (state) {
    case graph::mojom::blink::GraphSyncState::kIdle:
      return V8GraphSyncState(V8GraphSyncState::Enum::kIdle);
    case graph::mojom::blink::GraphSyncState::kResolving:
      return V8GraphSyncState(V8GraphSyncState::Enum::kResolving);
    case graph::mojom::blink::GraphSyncState::kConnecting:
      return V8GraphSyncState(V8GraphSyncState::Enum::kConnecting);
    case graph::mojom::blink::GraphSyncState::kSyncing:
      return V8GraphSyncState(V8GraphSyncState::Enum::kSyncing);
    case graph::mojom::blink::GraphSyncState::kSynced:
      return V8GraphSyncState(V8GraphSyncState::Enum::kSynced);
    case graph::mojom::blink::GraphSyncState::kError:
      return V8GraphSyncState(V8GraphSyncState::Enum::kError);
  }
  NOTREACHED();
}

// JSON-serialise a script object to its canonical string — the verbatim caveat /
// presentation JSON the browser stores and round-trips. Returns false when the
// value cannot be stringified (e.g. it contains a cycle).
bool SerializeToJson(ScriptState* script_state,
                     const ScriptValue& value,
                     String& out_json) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Value> v8_value = value.V8Value();
  if (v8_value.IsEmpty()) {
    out_json = "null";
    return true;
  }
  v8::Local<v8::String> json;
  if (!v8::JSON::Stringify(script_state->GetContext(), v8_value).ToLocal(&json))
    return false;
  out_json = ToCoreString(isolate, json);
  return true;
}

// Parse a JSON array literal into a sequence<object>. A non-array or invalid
// payload yields an empty sequence. |script_state|'s context MUST be in scope.
HeapVector<ScriptValue> ParseJsonArray(ScriptState* script_state,
                                       const String& json) {
  HeapVector<ScriptValue> out;
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();
  v8::Local<v8::Value> parsed;
  if (!v8::JSON::Parse(context, V8String(isolate, json)).ToLocal(&parsed))
    return out;
  if (!parsed->IsArray())
    return out;
  v8::Local<v8::Array> array = parsed.As<v8::Array>();
  out.ReserveInitialCapacity(array->Length());
  for (uint32_t i = 0; i < array->Length(); ++i) {
    v8::Local<v8::Value> element;
    if (array->Get(context, i).ToLocal(&element))
      out.emplace_back(isolate, element);
  }
  return out;
}

// §11 GovernanceValidationResult (Mojo -> IDL dictionary). The reject fields are
// empty strings in Mojo when the operation was allowed; leave them unset then.
GovernanceValidationResult* ValidationResultFromMojo(
    const graph::mojom::blink::GovernanceValidationResultPtr& result) {
  auto* out = MakeGarbageCollected<GovernanceValidationResult>();
  out->setAllowed(result->allowed);
  if (!result->rejected_by.empty())
    out->setRejectedBy(result->rejected_by);
  if (!result->constraint_kind.empty())
    out->setConstraintKind(result->constraint_kind);
  if (!result->reason.empty())
    out->setReason(result->reason);
  if (!result->mode.empty())
    out->setMode(result->mode);
  return out;
}

// §11 GraphConstraint (Mojo -> IDL dictionary). Mojo carries the record as an
// ordered vector of pairs so duplicate predicates survive.
GraphConstraint* ConstraintFromMojo(
    const graph::mojom::blink::GraphConstraintPtr& constraint) {
  auto* out = MakeGarbageCollected<GraphConstraint>();
  out->setId(constraint->id);
  out->setKind(constraint->kind);
  out->setScope(constraint->scope);
  Vector<std::pair<String, String>> properties;
  properties.ReserveInitialCapacity(constraint->properties.size());
  for (const auto& property : constraint->properties)
    properties.emplace_back(property->predicate, property->value);
  out->setProperties(std::move(properties));
  return out;
}

// §11 CapabilityInfo (Mojo -> IDL dictionary). |caveats| is a JSON array literal
// the browser round-trips verbatim; it is re-parsed here into the sequence<object>
// the dictionary exposes. |script_state|'s context MUST be in scope.
CapabilityInfo* CapabilityInfoFromMojo(
    ScriptState* script_state,
    const graph::mojom::blink::CapabilityInfoPtr& capability) {
  auto* out = MakeGarbageCollected<CapabilityInfo>();
  out->setId(capability->id);
  out->setActions(capability->actions);
  out->setResource(capability->resource);
  if (!capability->caveats.empty()) {
    HeapVector<ScriptValue> caveats =
        ParseJsonArray(script_state, capability->caveats);
    if (!caveats.empty())
      out->setCaveats(std::move(caveats));
  }
  if (capability->expires && !capability->expires->empty())
    out->setExpires(*capability->expires);
  return out;
}

// §5.1 ShapePropertyInfo (Mojo -> IDL dictionary). |datatype| is absent in Mojo
// (null) when the property carries no datatype constraint; |max_count| is absent
// when the property is unbounded (the IDL `unsigned long?`).
ShapePropertyInfo* ShapePropertyInfoFromMojo(
    const graph::mojom::blink::ShapePropertyInfoPtr& property) {
  auto* out = MakeGarbageCollected<ShapePropertyInfo>();
  out->setName(property->name);
  out->setPath(property->path);
  if (property->datatype && !property->datatype->empty())
    out->setDatatype(*property->datatype);
  out->setMinCount(property->min_count);
  if (property->max_count)
    out->setMaxCount(*property->max_count);
  out->setWritable(property->writable);
  out->setReadOnly(property->read_only);
  return out;
}

// §5.1 ShapeInfo (Mojo -> IDL dictionary).
ShapeInfo* ShapeInfoFromMojo(
    const graph::mojom::blink::ShapeInfoPtr& shape) {
  auto* out = MakeGarbageCollected<ShapeInfo>();
  out->setName(shape->name);
  out->setTargetClass(shape->target_class);
  out->setDefinitionAddress(shape->definition_address);
  out->setSourceGraphDid(shape->source_graph_did);
  HeapVector<Member<ShapePropertyInfo>> properties;
  properties.ReserveInitialCapacity(shape->properties.size());
  for (const auto& property : shape->properties)
    properties.push_back(ShapePropertyInfoFromMojo(property));
  out->setProperties(std::move(properties));
  return out;
}

// §11.1 FlowInfo (Mojo -> IDL dictionary).
FlowInfo* FlowInfoFromMojo(const graph::mojom::blink::FlowInfoPtr& flow) {
  auto* out = MakeGarbageCollected<FlowInfo>();
  out->setName(flow->name);
  out->setAppliesTo(flow->applies_to);
  out->setInitialState(flow->initial_state);
  out->setStates(flow->states);
  out->setTransitions(flow->transitions);
  return out;
}

// §11.1 FlowTransitionResult (Mojo -> IDL dictionary). The nullable reject fields
// are absent in Mojo (null) when they do not apply; leave the member unset then so
// the dictionary reports them as absent.
FlowTransitionResult* FlowTransitionResultFromMojo(
    const graph::mojom::blink::FlowTransitionResultPtr& result) {
  auto* out = MakeGarbageCollected<FlowTransitionResult>();
  out->setSuccess(result->success);
  if (result->new_state && !result->new_state->empty())
    out->setNewState(*result->new_state);
  if (result->reason && !result->reason->empty())
    out->setReason(*result->reason);
  if (result->guard_description && !result->guard_description->empty())
    out->setGuardDescription(*result->guard_description);
  if (result->seconds_until_allowed && !result->seconds_until_allowed->empty())
    out->setSecondsUntilAllowed(*result->seconds_until_allowed);
  return out;
}

}  // namespace

Graph::Graph(ExecutionContext* context,
             const graph::mojom::blink::GraphInfoPtr& info,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host,
             bool read_only)
    : id_(info->id),
      iri_(info->iri),
      did_(info->did),
      display_name_(info->display_name),
      trust_level_(info->trust_level ==
                           graph::mojom::blink::GraphTrustLevel::kLocal
                       ? "local"
                       : "external"),
      read_only_(read_only),
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
      // Spec 07 §5 shape API error vocabulary. SyntaxError and TypeError are
      // ECMAScript-native errors rather than DOMExceptions, so they are rejected
      // separately below; the remaining names map to their DOMException codes.
      {"ConstraintError", DOMExceptionCode::kConstraintError},
      {"NoModificationAllowedError",
       DOMExceptionCode::kNoModificationAllowedError},
      {"InvalidAccessError", DOMExceptionCode::kInvalidAccessError},
  };
  // SyntaxError / TypeError are ECMAScript-native (not DOMException); reject with
  // the matching native error so `err instanceof SyntaxError` / `TypeError`
  // holds, exactly as the Spec 07 algorithms specify (§5.2/§5.5/§5.7).
  if (name == "SyntaxError") {
    resolver->RejectWithDOMException(DOMExceptionCode::kSyntaxError, name);
    return;
  }
  if (name == "TypeError") {
    resolver->RejectWithTypeError("Shape property type mismatch");
    return;
  }
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

  // §6.3/§9.2.2: a read-mounted graph rejects every mutating operation
  // synchronously, before any diff is constructed.
  if (read_only_) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph is mounted read-only");
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

  // §6.3/§9.2.2: a read-mounted graph rejects every mutating operation
  // synchronously, before any diff is constructed.
  if (read_only_) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph is mounted read-only");
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

  // §6.3/§9.2.2: a read-mounted graph rejects every mutating operation
  // synchronously, before any diff is constructed.
  if (read_only_) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph is mounted read-only");
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

ScriptPromise<GovernanceValidationResult> Graph::canAddTriple(
    ScriptState* script_state,
    Triple* triple) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<GovernanceValidationResult>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->CanAddTriple(
      TripleToMojo(triple),
      WTF::BindOnce(
          [](ScriptPromiseResolver<GovernanceValidationResult>* resolver,
             graph::mojom::blink::GovernanceValidationResultPtr result,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(ValidationResultFromMojo(result));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<GovernanceValidationResult> Graph::canPerformAction(
    ScriptState* script_state,
    const String& action,
    const String& author_did,
    const CapabilityProofInput* proof) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<GovernanceValidationResult>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  // Stringify the explicit proof (if any) synchronously — the ScriptValues hold
  // v8 handles that are only valid on this stack, before the async host call.
  graph::mojom::blink::CapabilityProofInputPtr mojo_proof;
  if (proof) {
    mojo_proof = graph::mojom::blink::CapabilityProofInput::New();
    mojo_proof->chain = proof->chain();
    if (proof->hasPresentations()) {
      for (const auto& presentation : proof->presentations()) {
        String json;
        if (SerializeToJson(script_state, presentation, json))
          mojo_proof->presentations.push_back(json);
      }
    }
  }

  host_->CanPerformAction(
      action, author_did, std::move(mojo_proof),
      WTF::BindOnce(
          [](ScriptPromiseResolver<GovernanceValidationResult>* resolver,
             graph::mojom::blink::GovernanceValidationResultPtr result,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(ValidationResultFromMojo(result));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<GraphConstraint>> Graph::constraintsFor(
    ScriptState* script_state,
    const String& context_did) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<GraphConstraint>>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->ConstraintsFor(
      context_did,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<GraphConstraint>>* resolver,
             std::optional<Vector<graph::mojom::blink::GraphConstraintPtr>>
                 constraints,
             const String& error) {
            if (!constraints || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            HeapVector<Member<GraphConstraint>> out;
            out.ReserveInitialCapacity(constraints->size());
            for (const auto& constraint : *constraints)
              out.push_back(ConstraintFromMojo(constraint));
            resolver->Resolve(std::move(out));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<CapabilityInfo>> Graph::myCapabilities(
    ScriptState* script_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<CapabilityInfo>>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->MyCapabilities(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<CapabilityInfo>>* resolver,
         std::optional<Vector<graph::mojom::blink::CapabilityInfoPtr>>
             capabilities,
         const String& error) {
        if (!capabilities || !error.IsNull()) {
          RejectWithName(resolver, error);
          return;
        }
        ScriptState* ss = resolver->GetScriptState();
        if (!ss->ContextIsValid())
          return;
        // The caveat sequence<object> is rebuilt from JSON, so a live v8 scope
        // is required.
        ScriptState::Scope scope(ss);
        HeapVector<Member<CapabilityInfo>> out;
        out.ReserveInitialCapacity(capabilities->size());
        for (const auto& capability : *capabilities)
          out.push_back(CapabilityInfoFromMojo(ss, capability));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<V8EnforcementMode> Graph::enforcementMode(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8EnforcementMode>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->GetEnforcementMode(WTF::BindOnce(
      [](ScriptPromiseResolver<V8EnforcementMode>* resolver,
         graph::mojom::blink::EnforcementMode mode, const String& error) {
        if (!error.IsNull()) {
          RejectWithName(resolver, error);
          return;
        }
        resolver->Resolve(EnforcementModeToV8(mode));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::setEnforcementMode(
    ScriptState* script_state,
    const V8EnforcementMode& mode) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->SetEnforcementMode(
      EnforcementModeFromV8(mode),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<PublishedGraph> Graph::publish(ScriptState* script_state,
                                             const PublishOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<PublishedGraph>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  // §6.1: absent optional members ride the wire as empty strings; the browser
  // treats "" as unset and reads the authoritative module hash from the group.
  auto mojo_options = graph::mojom::blink::PublishOptions::New();
  mojo_options->module_hash =
      options->hasModuleHash() ? options->moduleHash() : g_empty_string;
  if (options->hasRelays())
    mojo_options->relays = options->relays();
  mojo_options->space_topology =
      options->hasSpaceTopology() ? options->spaceTopology() : g_empty_string;
  mojo_options->custom_space =
      options->hasCustomSpace() ? options->customSpace() : g_empty_string;

  host_->Publish(
      std::move(mojo_options),
      WTF::BindOnce(
          [](ScriptPromiseResolver<PublishedGraph>* resolver,
             graph::mojom::blink::PublishedGraphInfoPtr published,
             const String& error) {
            if (!published || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(PublishedGraph::FromMojo(published));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::unpublish(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->Unpublish(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLUndefined>* resolver, const String& error) {
        if (!error.IsNull()) {
          RejectWithName(resolver, error);
          return;
        }
        resolver->Resolve();
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<V8GraphSyncState> Graph::syncState(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8GraphSyncState>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->SyncState(WTF::BindOnce(
      [](ScriptPromiseResolver<V8GraphSyncState>* resolver,
         graph::mojom::blink::GraphSyncState state) {
        resolver->Resolve(SyncStateToV8(state));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<Peer>> Graph::peers(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Peer>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->Peers(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Peer>>* resolver,
         Vector<graph::mojom::blink::PeerPtr> peers) {
        HeapVector<Member<Peer>> out;
        out.ReserveInitialCapacity(peers.size());
        for (const auto& peer : peers)
          out.push_back(Peer::FromMojo(peer));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<Peer>> Graph::onlinePeers(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Peer>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->OnlinePeers(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Peer>>* resolver,
         Vector<graph::mojom::blink::PeerPtr> peers) {
        HeapVector<Member<Peer>> out;
        out.ReserveInitialCapacity(peers.size());
        for (const auto& peer : peers)
          out.push_back(Peer::FromMojo(peer));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUSVString> Graph::currentRevision(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUSVString>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->CurrentRevision(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLUSVString>* resolver, const String& revision,
         const String& error) {
        if (!error.IsNull()) {
          RejectWithName(resolver, error);
          return;
        }
        resolver->Resolve(revision);
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<GraphDiff>> Graph::pendingDiffs(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<GraphDiff>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->PendingDiffs(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<GraphDiff>>* resolver,
         Vector<graph::mojom::blink::GraphDiffPtr> diffs) {
        HeapVector<Member<GraphDiff>> out;
        out.ReserveInitialCapacity(diffs.size());
        for (const auto& diff : diffs)
          out.push_back(GraphDiff::FromMojo(diff));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::sendSignal(ScriptState* script_state,
                                              const String& remote_did,
                                              const V8BufferSource* payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  DOMArrayPiece piece(payload);
  Vector<uint8_t> bytes;
  bytes.AppendSpan(base::span(piece.Bytes(), piece.ByteLength()));

  host_->SendSignal(
      remote_did, std::move(bytes),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::sendSignalToSession(
    ScriptState* script_state,
    const String& remote_did,
    const String& session_id,
    const V8BufferSource* payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  DOMArrayPiece piece(payload);
  Vector<uint8_t> bytes;
  bytes.AppendSpan(base::span(piece.Bytes(), piece.ByteLength()));

  host_->SendSignalToSession(
      remote_did, session_id, std::move(bytes),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::broadcast(ScriptState* script_state,
                                             const V8BufferSource* payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  DOMArrayPiece piece(payload);
  Vector<uint8_t> bytes;
  bytes.AppendSpan(base::span(piece.Bytes(), piece.ByteLength()));

  host_->Broadcast(
      std::move(bytes),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::addShape(
    ScriptState* script_state,
    const String& name,
    const ScriptValue& shape_definition) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  // §5.2: serialise the shape definition to its JSON text synchronously — the
  // v8 handle is only valid on this stack, before the async host call. The
  // browser re-parses and JCS-canonicalises it (§6.3). A value that cannot be
  // stringified (e.g. a cycle) is a malformed definition -> SyntaxError.
  String shape_json;
  if (!SerializeToJson(script_state, shape_definition, shape_json)) {
    resolver->RejectWithDOMException(DOMExceptionCode::kSyntaxError,
                                     "The shape definition is not serialisable");
    return promise;
  }

  host_->AddShape(
      name, shape_json,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::removeShape(ScriptState* script_state,
                                               const String& name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->RemoveShape(
      name, WTF::BindOnce(
                [](ScriptPromiseResolver<IDLUndefined>* resolver,
                   const String& error) {
                  if (!error.IsNull()) {
                    RejectWithName(resolver, error);
                    return;
                  }
                  resolver->Resolve();
                },
                WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<ShapeInfo>> Graph::getShapes(
    ScriptState* script_state,
    const GetShapesOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<ShapeInfo>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  // §5.4: includeInherited defaults to true (the IDL supplies the default, so a
  // present dictionary always carries the member).
  host_->GetShapes(
      options->includeInherited(),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<ShapeInfo>>* resolver,
             Vector<graph::mojom::blink::ShapeInfoPtr> shapes) {
            HeapVector<Member<ShapeInfo>> out;
            out.ReserveInitialCapacity(shapes.size());
            for (const auto& shape : shapes)
              out.push_back(ShapeInfoFromMojo(shape));
            resolver->Resolve(std::move(out));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUSVString> Graph::createShapeInstance(
    ScriptState* script_state,
    const String& shape_name,
    const String& address,
    const Vector<std::pair<String, String>>& initial_values) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUSVString>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  // §5.5: the record<DOMString, DOMString> crosses the boundary as an ordered
  // array of name->value entries (Mojo has no record type).
  Vector<graph::mojom::blink::ShapeInitialValuePtr> mojo_values;
  mojo_values.reserve(initial_values.size());
  for (const auto& entry : initial_values) {
    auto value = graph::mojom::blink::ShapeInitialValue::New();
    value->name = entry.first;
    value->value = entry.second;
    mojo_values.push_back(std::move(value));
  }

  host_->CreateShapeInstance(
      shape_name, address, std::move(mojo_values),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUSVString>* resolver,
             const String& address_out, const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(address_out);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<IDLUSVString>> Graph::getShapeInstances(
    ScriptState* script_state,
    const String& shape_name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<IDLUSVString>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->GetShapeInstances(
      shape_name,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<IDLUSVString>>* resolver,
             std::optional<Vector<String>> addresses, const String& error) {
            if (!addresses || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(*addresses);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLRecord<IDLString, IDLSequence<IDLString>>>
Graph::getShapeInstanceData(ScriptState* script_state,
                            const String& shape_name,
                            const String& address) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLRecord<IDLString, IDLSequence<IDLString>>>>(
      script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->GetShapeInstanceData(
      shape_name, address,
      WTF::BindOnce(
          [](ScriptPromiseResolver<
                 IDLRecord<IDLString, IDLSequence<IDLString>>>* resolver,
             std::optional<Vector<graph::mojom::blink::ShapeInstanceEntryPtr>>
                 data,
             const String& error) {
            if (!data || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            // §5.6: the record<DOMString, sequence<DOMString>> is rebuilt from
            // the ordered name->values entries the browser returned.
            Vector<std::pair<String, Vector<String>>> out;
            out.ReserveInitialCapacity(data->size());
            for (const auto& entry : *data)
              out.emplace_back(entry->name, entry->values);
            resolver->Resolve(std::move(out));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::setShapeProperty(ScriptState* script_state,
                                                    const String& shape_name,
                                                    const String& address,
                                                    const String& property,
                                                    const String& value) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->SetShapeProperty(
      shape_name, address, property, value,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::addToShapeCollection(
    ScriptState* script_state,
    const String& shape_name,
    const String& address,
    const String& collection,
    const String& value) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->AddToShapeCollection(
      shape_name, address, collection, value,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::removeFromShapeCollection(
    ScriptState* script_state,
    const String& shape_name,
    const String& address,
    const String& collection,
    const String& value) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->RemoveFromShapeCollection(
      shape_name, address, collection, value,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::addFlow(ScriptState* script_state,
                                           const String& name,
                                           const String& flow_json) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->AddFlow(
      name, flow_json,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Graph::removeFlow(ScriptState* script_state,
                                              const String& name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->RemoveFlow(
      name, WTF::BindOnce(
                [](ScriptPromiseResolver<IDLUndefined>* resolver,
                   const String& error) {
                  if (!error.IsNull()) {
                    RejectWithName(resolver, error);
                    return;
                  }
                  resolver->Resolve();
                },
                WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<FlowInfo>> Graph::getFlows(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<FlowInfo>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->GetFlows(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<FlowInfo>>* resolver,
         Vector<graph::mojom::blink::FlowInfoPtr> flows) {
        HeapVector<Member<FlowInfo>> out;
        out.ReserveInitialCapacity(flows.size());
        for (const auto& flow : flows)
          out.push_back(FlowInfoFromMojo(flow));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLString> Graph::getFlowState(ScriptState* script_state,
                                             const String& flow_name,
                                             const String& instance_uri) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->GetFlowState(
      flow_name, instance_uri,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLString>* resolver, const String& state,
             const String& error) {
            if (!error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(state);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<FlowTransitionResult> Graph::executeFlowTransition(
    ScriptState* script_state,
    const String& flow_name,
    const String& instance_uri,
    const String& transition_name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FlowTransitionResult>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  // §6.2 / §11.3: the transition attempt always resolves with a
  // FlowTransitionResult — a business rejection (wrong state, guard, temporal,
  // role) carries success == false and a reason; a programming error (unknown
  // flow / transition / uninitialised instance) surfaces the DOMException name in
  // the result's reason with success == false. The browser fires `transitionfired`
  // out-of-band on success.
  host_->ExecuteFlowTransition(
      flow_name, instance_uri, transition_name,
      WTF::BindOnce(
          [](ScriptPromiseResolver<FlowTransitionResult>* resolver,
             graph::mojom::blink::FlowTransitionResultPtr result) {
            resolver->Resolve(FlowTransitionResultFromMojo(result));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<IDLString>> Graph::availableTransitions(
    ScriptState* script_state,
    const String& flow_name,
    const String& instance_uri) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<IDLString>>>(
          script_state);
  auto promise = resolver->Promise();

  if (dissolved_ || !host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The graph has been dissolved");
    return promise;
  }

  host_->AvailableTransitions(
      flow_name, instance_uri,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLSequence<IDLString>>* resolver,
             std::optional<Vector<String>> transitions, const String& error) {
            if (!transitions || !error.IsNull()) {
              RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(*transitions);
          },
          WrapPersistent(resolver)));

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

void Graph::OnPeerJoined(graph::mojom::blink::PeerPtr peer) {
  DispatchEvent(
      *PeerEvent::Create(event_type_names::kPeerjoined, Peer::FromMojo(peer)));
}

void Graph::OnPeerLeft(graph::mojom::blink::PeerPtr peer) {
  DispatchEvent(
      *PeerEvent::Create(event_type_names::kPeerleft, Peer::FromMojo(peer)));
}

void Graph::OnSyncStateChange(graph::mojom::blink::GraphSyncState state) {
  DispatchEvent(*SyncStateEvent::Create(event_type_names::kSyncstatechange,
                                        SyncStateToV8(state)));
}

void Graph::OnSignal(graph::mojom::blink::PeerPtr from,
                     const Vector<uint8_t>& payload) {
  DOMUint8Array* bytes =
      DOMUint8Array::Create(base::span(payload.data(), payload.size()));
  DispatchEvent(*SignalEvent::Create(event_type_names::kSignal,
                                     Peer::FromMojo(from), bytes));
}

void Graph::OnDiff(graph::mojom::blink::GraphDiffPtr diff) {
  DispatchEvent(
      *DiffEvent::Create(event_type_names::kDiff, GraphDiff::FromMojo(diff)));
}

// Graph Flows §6.2 step 8 / §13.4 — fire ontransitionfired / ontransitiondeadline.
// |type| is event_type_names::kTransitionfired or kTransitiondeadline; |new_state|
// is a null String for a deadline notification (surfaced as IDL null).
void Graph::DispatchFlowTransition(const AtomicString& type,
                                   const String& flow_name,
                                   const String& instance_uri,
                                   const String& transition_name,
                                   const String& new_state) {
  DispatchEvent(*FlowTransitionEvent::Create(type, flow_name, instance_uri,
                                             transition_name, new_state));
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
