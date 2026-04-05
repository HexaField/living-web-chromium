// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/personal_graph.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/modules/graph/content_proof.h"
#include "third_party/blink/renderer/modules/graph/semantic_triple.h"
#include "third_party/blink/renderer/modules/graph/signed_triple.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

String GetStringProperty(ScriptState* script_state,
                         const ScriptValue& obj,
                         const char* prop) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();
  v8::Local<v8::Value> val = obj.V8Value();
  if (!val->IsObject())
    return String();
  v8::Local<v8::Object> v8_obj = val.As<v8::Object>();
  v8::Local<v8::Value> result;
  if (!v8_obj->Get(context, v8::String::NewFromUtf8(isolate, prop)
                                .ToLocalChecked())
           .ToLocal(&result) ||
      !result->IsString()) {
    return String();
  }
  return ToCoreString(isolate, result.As<v8::String>());
}

SignedTriple* ToBlinkSignedTriple(
    const graph::mojom::blink::SignedTriplePtr& mojo) {
  String predicate;
  if (mojo->data->predicate.has_value())
    predicate = mojo->data->predicate.value();
  auto* data = MakeGarbageCollected<SemanticTriple>(
      mojo->data->source, mojo->data->target, predicate);
  auto* proof = MakeGarbageCollected<ContentProof>(
      mojo->proof->key, mojo->proof->signature);
  return MakeGarbageCollected<SignedTriple>(
      data, mojo->author, mojo->timestamp, proof);
}

}  // namespace

PersonalGraph::PersonalGraph(
    ExecutionContext* context,
    const String& uuid,
    const String& name,
    mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host)
    : uuid_(uuid), name_(name), execution_context_(context),
      host_(context) {
  if (host.is_valid()) {
    host_.Bind(std::move(host),
               context->GetTaskRunner(TaskType::kMiscPlatformAPI));
  }
}

V8GraphSyncState PersonalGraph::state() const {
  return V8GraphSyncState(V8GraphSyncState::Enum::kPrivate);
}

// Triple operations

ScriptPromise<IDLAny> PersonalGraph::addTriple(ScriptState* script_state,
                                                ScriptValue triple_val) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  auto mojo_triple = graph::mojom::blink::SemanticTriple::New();
  mojo_triple->source = GetStringProperty(script_state, triple_val, "source");
  mojo_triple->target = GetStringProperty(script_state, triple_val, "target");
  String pred = GetStringProperty(script_state, triple_val, "predicate");
  if (!pred.IsNull() && !pred.empty())
    mojo_triple->predicate = pred;

  host_->AddTriple(
      std::move(mojo_triple),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             graph::mojom::blink::SignedTriplePtr result) {
            if (!result) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kOperationError,
                  "Failed to add triple"));
              return;
            }
            resolver->Resolve(ToBlinkSignedTriple(result));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::addTriples(ScriptState* script_state,
                                                 ScriptValue triples_val) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();
  v8::Local<v8::Value> val = triples_val.V8Value();

  Vector<graph::mojom::blink::SemanticTriplePtr> mojo_triples;
  if (val->IsArray()) {
    v8::Local<v8::Array> arr = val.As<v8::Array>();
    for (uint32_t i = 0; i < arr->Length(); i++) {
      v8::Local<v8::Value> elem;
      if (!arr->Get(context, i).ToLocal(&elem))
        continue;
      ScriptValue sv(isolate, elem);
      auto t = graph::mojom::blink::SemanticTriple::New();
      t->source = GetStringProperty(script_state, sv, "source");
      t->target = GetStringProperty(script_state, sv, "target");
      String pred = GetStringProperty(script_state, sv, "predicate");
      if (!pred.IsNull() && !pred.empty())
        t->predicate = pred;
      mojo_triples.push_back(std::move(t));
    }
  }

  host_->AddTriples(
      std::move(mojo_triples),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             Vector<graph::mojom::blink::SignedTriplePtr> results) {
            HeapVector<Member<SignedTriple>> blink_results;
            for (const auto& r : results) {
              blink_results.push_back(ToBlinkSignedTriple(r));
            }
            resolver->Resolve(blink_results);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::removeTriple(ScriptState* script_state,
                                                   ScriptValue triple_val) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  auto mojo_st = graph::mojom::blink::SignedTriple::New();
  mojo_st->data = graph::mojom::blink::SemanticTriple::New();
  mojo_st->data->source = GetStringProperty(script_state, triple_val, "source");
  mojo_st->data->target = GetStringProperty(script_state, triple_val, "target");
  String pred = GetStringProperty(script_state, triple_val, "predicate");
  if (!pred.IsNull() && !pred.empty())
    mojo_st->data->predicate = pred;
  mojo_st->author = GetStringProperty(script_state, triple_val, "author");
  mojo_st->timestamp = GetStringProperty(script_state, triple_val, "timestamp");
  mojo_st->proof = graph::mojom::blink::ContentProof::New();
  mojo_st->proof->key = String();
  mojo_st->proof->signature = String();

  host_->RemoveTriple(
      std::move(mojo_st),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver, bool success) {
            resolver->Resolve(success);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::queryTriples(ScriptState* script_state,
                                                   ScriptValue query_val) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  auto mojo_query = graph::mojom::blink::TripleQuery::New();
  String source = GetStringProperty(script_state, query_val, "source");
  if (!source.IsNull() && !source.empty())
    mojo_query->source = source;
  String target = GetStringProperty(script_state, query_val, "target");
  if (!target.IsNull() && !target.empty())
    mojo_query->target = target;
  String pred = GetStringProperty(script_state, query_val, "predicate");
  if (!pred.IsNull() && !pred.empty())
    mojo_query->predicate = pred;

  host_->QueryTriples(
      std::move(mojo_query),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             Vector<graph::mojom::blink::SignedTriplePtr> results) {
            HeapVector<Member<SignedTriple>> blink_results;
            for (const auto& r : results) {
              blink_results.push_back(ToBlinkSignedTriple(r));
            }
            resolver->Resolve(blink_results);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::querySparql(ScriptState* script_state,
                                                  const String& sparql) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  host_->QuerySparql(
      sparql,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             graph::mojom::blink::SparqlResultPtr result) {
            if (!result) {
              resolver->Resolve(
                  ScriptValue::CreateNull(resolver->GetScriptState()));
              return;
            }
            resolver->Resolve(result->bindings_json);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::snapshot(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  host_->Snapshot(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         Vector<graph::mojom::blink::SignedTriplePtr> triples) {
        HeapVector<Member<SignedTriple>> blink_triples;
        for (const auto& t : triples) {
          blink_triples.push_back(ToBlinkSignedTriple(t));
        }
        resolver->Resolve(blink_triples);
      },
      WrapPersistent(resolver)));

  return promise;
}

// Access control

ScriptPromise<IDLUndefined> PersonalGraph::grantAccess(
    ScriptState* script_state, const String& origin, const String& level) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  auto access_level = graph::mojom::blink::GraphAccessLevel::kRead;
  if (level == "readwrite" || level == "read-write")
    access_level = graph::mojom::blink::GraphAccessLevel::kReadWrite;

  host_->GrantAccess(
      origin, access_level,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::revokeAccess(
    ScriptState* script_state, const String& origin) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  host_->RevokeAccess(
      origin,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

// Shape operations

ScriptPromise<IDLUndefined> PersonalGraph::addShape(
    ScriptState* script_state, const String& name, const String& shacl_json) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  host_->AddShape(
      name, shacl_json,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::getShapes(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  HeapVector<Member<SignedTriple>> empty;
  resolver->Resolve(empty);
  return resolver->Promise();
}

ScriptPromise<IDLAny> PersonalGraph::getShapeInstances(
    ScriptState* script_state, const String& shape_name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  host_->GetShapeInstances(
      shape_name,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             const Vector<String>& instances) {
            resolver->Resolve(instances);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUSVString> PersonalGraph::createShapeInstance(
    ScriptState* script_state, const String& shape_name,
    const String& data_json, ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUSVString>>(script_state);
  auto promise = resolver->Promise();

  host_->CreateShapeInstance(
      shape_name, data_json,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUSVString>* resolver,
             const std::optional<String>& uri) {
            if (!uri) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kOperationError,
                  "Failed to create shape instance"));
              return;
            }
            resolver->Resolve(*uri);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraph::getShapeInstanceData(
    ScriptState* script_state, const String& shape_name,
    const String& instance_uri) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  host_->GetShapeInstanceData(
      shape_name, instance_uri,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             const std::optional<String>& data_json) {
            if (!data_json) {
              resolver->Resolve(
                  ScriptValue::CreateNull(resolver->GetScriptState()));
              return;
            }
            resolver->Resolve(*data_json);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::setShapeProperty(
    ScriptState* script_state, const String&, const String&, const String&,
    ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  resolver->Resolve();
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> PersonalGraph::addToShapeCollection(
    ScriptState* script_state, const String&, const String&, const String&,
    ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  resolver->Resolve();
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> PersonalGraph::removeFromShapeCollection(
    ScriptState* script_state, const String&, const String&, const String&,
    ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  resolver->Resolve();
  return resolver->Promise();
}

// Sharing

ScriptPromise<IDLAny> PersonalGraph::share(ScriptState* script_state,
                                            ScriptValue) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  resolver->Resolve(ScriptValue::CreateNull(script_state));
  return resolver->Promise();
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
  visitor->Trace(host_);
  EventTarget::Trace(visitor);
}

}  // namespace blink
