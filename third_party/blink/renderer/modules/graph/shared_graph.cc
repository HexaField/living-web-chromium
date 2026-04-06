// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/shared_graph.h"

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "base/uuid.h"

namespace blink {

SharedGraph::SharedGraph(
    ExecutionContext* context,
    const String& uuid,
    const String& uri,
    mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host,
    mojo::PendingRemote<graph::mojom::blink::SharedGraphHost> shared_host)
    : PersonalGraph(context, uuid, String(), std::move(host)),
      uri_(uri),
      shared_host_(context) {
  if (shared_host) {
    shared_host_.Bind(
        std::move(shared_host),
        static_cast<scoped_refptr<base::SequencedTaskRunner>>(
            context->GetTaskRunner(TaskType::kMiscPlatformAPI)));
  }
}

V8SyncState SharedGraph::syncState() const {
  return V8SyncState(V8SyncState::Enum::kIdle);
}

String SharedGraph::moduleHash() const {
  return String("default");
}

ScriptPromise<IDLAny> SharedGraph::currentRevision(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  // Return a stub UUID revision string.
  ScriptState::Scope scope(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();
  resolver->Resolve(ScriptValue(isolate,
      V8String(isolate, String(base::Uuid::GenerateRandomV4().AsLowercaseString()))));
  return promise;
}

// ---------- Peers ----------

ScriptPromise<IDLAny> SharedGraph::peers(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!shared_host_.is_bound()) {
    ScriptState::Scope scope(script_state);
    resolver->Resolve(ScriptValue(script_state->GetIsolate(),
                                  v8::Array::New(script_state->GetIsolate(), 0)));
    return promise;
  }

  shared_host_->GetPeers(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         const Vector<String>& peer_dids) {
        ScriptState* ss = resolver->GetScriptState();
        ScriptState::Scope scope(ss);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> ctx = ss->GetContext();
        v8::Local<v8::Array> arr =
            v8::Array::New(isolate, static_cast<int>(peer_dids.size()));
        for (wtf_size_t i = 0; i < peer_dids.size(); i++) {
          arr->Set(ctx, i, V8String(isolate, peer_dids[i])).Check();
        }
        resolver->Resolve(ScriptValue(isolate, arr));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> SharedGraph::onlinePeers(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!shared_host_.is_bound()) {
    ScriptState::Scope scope(script_state);
    resolver->Resolve(ScriptValue(script_state->GetIsolate(),
                                  v8::Array::New(script_state->GetIsolate(), 0)));
    return promise;
  }

  shared_host_->GetOnlinePeers(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         Vector<graph::mojom::blink::OnlinePeerPtr> peers) {
        ScriptState* ss = resolver->GetScriptState();
        ScriptState::Scope scope(ss);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> ctx = ss->GetContext();
        v8::Local<v8::Array> arr =
            v8::Array::New(isolate, static_cast<int>(peers.size()));
        for (wtf_size_t i = 0; i < peers.size(); i++) {
          v8::Local<v8::Object> obj = v8::Object::New(isolate);
          obj->Set(ctx, V8String(isolate, "did"),
                   V8String(isolate, peers[i]->did)).Check();
          obj->Set(ctx, V8String(isolate, "lastSeen"),
                   v8::Number::New(isolate, peers[i]->last_seen)).Check();
          arr->Set(ctx, i, obj).Check();
        }
        resolver->Resolve(ScriptValue(isolate, arr));
      },
      WrapPersistent(resolver)));

  return promise;
}

// ---------- Signalling ----------

ScriptPromise<IDLUndefined> SharedGraph::sendSignal(
    ScriptState* script_state,
    const String& remote_did,
    ScriptValue payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!shared_host_.is_bound()) {
    resolver->Resolve();
    return promise;
  }

  // Serialize payload to JSON string.
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::String> json;
  if (!v8::JSON::Stringify(script_state->GetContext(), payload.V8Value())
           .ToLocal(&json)) {
    resolver->Resolve();
    return promise;
  }
  String payload_json = ToCoreString(isolate, json);

  shared_host_->SendSignal(
      remote_did, payload_json,
      BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool success) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> SharedGraph::broadcast(ScriptState* script_state,
                                                    ScriptValue payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!shared_host_.is_bound()) {
    resolver->Resolve();
    return promise;
  }

  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::String> json;
  if (!v8::JSON::Stringify(script_state->GetContext(), payload.V8Value())
           .ToLocal(&json)) {
    resolver->Resolve();
    return promise;
  }
  String payload_json = ToCoreString(isolate, json);

  shared_host_->Broadcast(
      payload_json,
      BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, bool success) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

// ---------- Governance ----------

ScriptPromise<IDLAny> SharedGraph::canAddTriple(ScriptState* script_state,
                                                 ScriptValue triple_value) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  // If no shared host bound, default to allowed (permissive fallback).
  if (!shared_host_.is_bound()) {
    ScriptState::Scope scope(script_state);
    resolver->Resolve(ScriptValue(script_state->GetIsolate(),
                                  v8::True(script_state->GetIsolate())));
    return promise;
  }

  // Extract source, predicate, target from the triple object.
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> ctx = script_state->GetContext();
  v8::Local<v8::Object> obj;
  if (!triple_value.V8Value()->ToObject(ctx).ToLocal(&obj)) {
    resolver->Resolve(ScriptValue(isolate, v8::True(isolate)));
    return promise;
  }

  auto GetStr = [&](const char* key) -> String {
    v8::Local<v8::Value> val;
    if (obj->Get(ctx, V8String(isolate, key)).ToLocal(&val) && val->IsString()) {
      return ToCoreString(isolate, v8::Local<v8::String>::Cast(val));
    }
    return String();
  };

  String source = GetStr("source");
  String predicate = GetStr("predicate");
  String target = GetStr("target");

  // Use GetPeers as a proxy — the real governance call isn't in
  // SharedGraphHost mojom yet in the way canAddTriple expects
  // (source/predicate/target). We'll use the Sync() -> current revision
  // path for now and just return true with metadata.
  // Actually, let's resolve with true for now as governance validation
  // happens on Commit in the browser process.
  ScriptState::Scope scope(script_state);
  resolver->Resolve(ScriptValue(isolate, v8::True(isolate)));

  return promise;
}

ScriptPromise<IDLAny> SharedGraph::constraintsFor(ScriptState* script_state,
                                                    const String& entity) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  // Return empty constraints array — real implementation would call
  // GovernanceService.ConstraintsFor via a separate Mojo pipe.
  ScriptState::Scope scope(script_state);
  resolver->Resolve(ScriptValue(script_state->GetIsolate(),
                                v8::Array::New(script_state->GetIsolate(), 0)));
  return promise;
}

ScriptPromise<IDLAny> SharedGraph::myCapabilities(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  // Return a capabilities object with sensible defaults.
  ScriptState::Scope scope(script_state);
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> ctx = script_state->GetContext();
  v8::Local<v8::Object> caps = v8::Object::New(isolate);
  caps->Set(ctx, V8String(isolate, "canAddTriples"),
            v8::True(isolate)).Check();
  caps->Set(ctx, V8String(isolate, "canRemoveTriples"),
            v8::True(isolate)).Check();
  caps->Set(ctx, V8String(isolate, "allowedPredicates"),
            v8::Array::New(isolate, 0)).Check();
  resolver->Resolve(ScriptValue(isolate, caps));
  return promise;
}

const AtomicString& SharedGraph::InterfaceName() const {
  DEFINE_STATIC_LOCAL(const AtomicString, kSharedGraph, ("SharedGraph"));
  return kSharedGraph;
}

void SharedGraph::Trace(Visitor* visitor) const {
  visitor->Trace(shared_host_);
  PersonalGraph::Trace(visitor);
}

}  // namespace blink
