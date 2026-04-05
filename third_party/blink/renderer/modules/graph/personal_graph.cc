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

using WTF::BindOnce;
using WTF::WrapPersistent;

namespace blink {

namespace {

String GetStringProp(ScriptState* script_state,
                     const ScriptValue& obj,
                     const char* prop) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> ctx = script_state->GetContext();
  v8::Local<v8::Value> val = obj.V8Value();
  if (!val->IsObject())
    return String();
  v8::Local<v8::Object> v8_obj = val.As<v8::Object>();
  v8::Local<v8::Value> result;
  if (!v8_obj->Get(ctx, v8::String::NewFromUtf8(isolate, prop)
                            .ToLocalChecked())
           .ToLocal(&result) ||
      !result->IsString()) {
    return String();
  }
  return ToCoreString(isolate, result.As<v8::String>());
}

SignedTriple* ToBlinkSignedTriple(
    const graph::mojom::blink::SignedTriplePtr& m) {
  // In blink mojo bindings, string? is just String — null means absent
  String predicate = m->data->predicate;
  auto* data = MakeGarbageCollected<SemanticTriple>(
      m->data->source, m->data->target,
      predicate.IsNull() ? g_empty_string : predicate);
  auto* proof = MakeGarbageCollected<ContentProof>(
      m->proof->key, m->proof->signature);
  return MakeGarbageCollected<SignedTriple>(
      data, m->author, m->timestamp, proof);
}

graph::mojom::blink::SemanticTriplePtr MakeMojoTriple(
    ScriptState* script_state, const ScriptValue& triple_val) {
  auto t = graph::mojom::blink::SemanticTriple::New();
  t->source = GetStringProp(script_state, triple_val, "source");
  t->target = GetStringProp(script_state, triple_val, "target");
  t->predicate = GetStringProp(script_state, triple_val, "predicate");
  return t;
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
    host_.Bind(std::move(host));
  }
}

V8GraphSyncState PersonalGraph::state() const {
  return V8GraphSyncState(V8GraphSyncState::Enum::kPrivate);
}

ScriptPromise<IDLAny> PersonalGraph::addTriple(ScriptState* script_state,
                                                ScriptValue triple_val) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  host_->AddTriple(
      MakeMojoTriple(script_state, triple_val),
      BindOnce(
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

  v8::Local<v8::Context> ctx = script_state->GetContext();
  v8::Local<v8::Value> val = triples_val.V8Value();

  Vector<graph::mojom::blink::SemanticTriplePtr> mojo_triples;
  if (val->IsArray()) {
    v8::Local<v8::Array> arr = val.As<v8::Array>();
    for (uint32_t i = 0; i < arr->Length(); i++) {
      v8::Local<v8::Value> elem;
      if (!arr->Get(ctx, i).ToLocal(&elem))
        continue;
      ScriptValue sv(script_state->GetIsolate(), elem);
      mojo_triples.push_back(MakeMojoTriple(script_state, sv));
    }
  }

  host_->AddTriples(
      std::move(mojo_triples),
      BindOnce(
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
  mojo_st->data = MakeMojoTriple(script_state, triple_val);
  mojo_st->author = GetStringProp(script_state, triple_val, "author");
  mojo_st->timestamp = GetStringProp(script_state, triple_val, "timestamp");
  mojo_st->proof = graph::mojom::blink::ContentProof::New();
  mojo_st->proof->key = String("");
  mojo_st->proof->signature = String("");

  host_->RemoveTriple(
      std::move(mojo_st),
      BindOnce(
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
  mojo_query->source = GetStringProp(script_state, query_val, "source");
  mojo_query->target = GetStringProp(script_state, query_val, "target");
  mojo_query->predicate = GetStringProp(script_state, query_val, "predicate");

  host_->QueryTriples(
      std::move(mojo_query),
      BindOnce(
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
      BindOnce(
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

  host_->Snapshot(BindOnce(
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
      BindOnce(
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
      BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> PersonalGraph::addShape(
    ScriptState* script_state, const String& name, const String& shacl_json) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  host_->AddShape(
      name, shacl_json,
      BindOnce(
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
      BindOnce(
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
      BindOnce(
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
      BindOnce(
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
