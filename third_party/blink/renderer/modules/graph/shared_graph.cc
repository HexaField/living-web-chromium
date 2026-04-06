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

#include <fstream>

namespace {
void BlinkLog(const char* msg) {
  std::ofstream f("/tmp/blink_debug.log", std::ios::app);
  f << msg << std::endl;
}
void BlinkLog2(const std::string& msg) {
  std::ofstream f("/tmp/blink_debug.log", std::ios::app);
  f << msg << std::endl;
}
}  // namespace


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
    shared_host_.set_disconnect_handler(BindOnce([]() {
      LOG(ERROR) << "BLINK: SharedGraphHost remote DISCONNECTED";
    }));
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

  if (!shared_host_.is_bound()) {
    ScriptState::Scope scope(script_state);
    v8::Isolate* isolate = script_state->GetIsolate();
    resolver->Resolve(ScriptValue(isolate, v8::Null(isolate)));
    return promise;
  }

  shared_host_->GetCurrentRevision(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         const String& revision) {
        ScriptState* ss = resolver->GetScriptState();
        ScriptState::Scope scope(ss);
        v8::Isolate* isolate = ss->GetIsolate();
        if (revision.empty()) {
          resolver->Resolve(ScriptValue(isolate, v8::Null(isolate)));
        } else {
          resolver->Resolve(ScriptValue(isolate, V8String(isolate, revision)));
        }
      },
      WrapPersistent(resolver)));

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
         Vector<graph::mojom::blink::PeerInfoPtr> peers) {
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
          obj->Set(ctx, V8String(isolate, "sessionId"),
                   V8String(isolate, peers[i]->session_id)).Check();
          obj->Set(ctx, V8String(isolate, "deviceLabel"),
                   V8String(isolate, peers[i]->device_label)).Check();
          arr->Set(ctx, i, obj).Check();
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
          obj->Set(ctx, V8String(isolate, "sessionId"),
                   V8String(isolate, peers[i]->session_id)).Check();
          obj->Set(ctx, V8String(isolate, "deviceLabel"),
                   V8String(isolate, peers[i]->device_label)).Check();
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

ScriptPromise<IDLUndefined> SharedGraph::sendSignalToSession(
    ScriptState* script_state,
    const String& remote_did,
    const String& session_id,
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

  shared_host_->SendSignalToSession(
      remote_did, session_id, payload_json,
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
  BlinkLog("canAddTriple: entered");
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  BlinkLog2("canAddTriple: shared_host_.is_bound()=" + std::to_string(shared_host_.is_bound()));
  if (!shared_host_.is_bound()) {
    ScriptState::Scope scope(script_state);
    resolver->Resolve(ScriptValue(script_state->GetIsolate(),
                                  v8::True(script_state->GetIsolate())));
    return promise;
  }

  // Extract predicate and source (scope) from the triple object.
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

  String predicate = GetStr("predicate");
  String source = GetStr("source");

  // Mojo string parameters are non-nullable; ensure empty rather than null.
  if (predicate.IsNull()) predicate = g_empty_string;
  if (source.IsNull()) source = g_empty_string;

  BlinkLog2("canAddTriple: predicate=" + std::string(predicate.Utf8().c_str()) +
            " source=" + std::string(source.Utf8().c_str()) +
            " predicate.IsNull()=" + std::to_string(predicate.IsNull()) +
            " source.IsNull()=" + std::to_string(source.IsNull()));
  BlinkLog("canAddTriple: about to call shared_host_->CanAddTriple");

  shared_host_->CanAddTriple(
      predicate, source,
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             bool accepted, const String& reason) {
            BlinkLog2("canAddTriple CALLBACK: accepted=" + std::to_string(accepted));
            ScriptState* ss = resolver->GetScriptState();
            BlinkLog2("canAddTriple CALLBACK: got ScriptState=" + std::to_string(ss != nullptr));
            if (!ss || !ss->ContextIsValid()) {
              BlinkLog("canAddTriple CALLBACK: ScriptState invalid!");
              return;
            }
            ScriptState::Scope scope(ss);
            BlinkLog("canAddTriple CALLBACK: entered scope");
            v8::Isolate* isolate = ss->GetIsolate();
            BlinkLog2("canAddTriple CALLBACK: got isolate=" + std::to_string(isolate != nullptr));
            v8::Local<v8::Context> ctx = ss->GetContext();
            BlinkLog2("canAddTriple CALLBACK: got context, empty=" + std::to_string(ctx.IsEmpty()));
            BlinkLog("canAddTriple CALLBACK: about to create Object::New");
            v8::Local<v8::Object> result = v8::Object::New(isolate);
            BlinkLog("canAddTriple CALLBACK: object created");
            result->Set(ctx, V8String(isolate, "accepted"),
                        v8::Boolean::New(isolate, accepted)).Check();
            if (!reason.IsNull() && !reason.empty()) {
              result->Set(ctx, V8String(isolate, "reason"),
                          V8String(isolate, reason)).Check();
            }
            BlinkLog("canAddTriple CALLBACK: resolving promise");
            resolver->Resolve(ScriptValue(isolate, result));
            BlinkLog("canAddTriple CALLBACK: promise resolved!");
          },
          WrapPersistent(resolver)));

  BlinkLog("canAddTriple: call dispatched, returning promise");
  return promise;
}

ScriptPromise<IDLAny> SharedGraph::constraintsFor(ScriptState* script_state,
                                                    const String& entity) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!shared_host_.is_bound()) {
    ScriptState::Scope scope(script_state);
    resolver->Resolve(ScriptValue(script_state->GetIsolate(),
                                  v8::Array::New(script_state->GetIsolate(), 0)));
    return promise;
  }

  String scope_entity;
  if (!entity.IsNull() && !entity.empty()) {
    scope_entity = entity;
  }

  shared_host_->ConstraintsFor(
      scope_entity,
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             const String& constraints_json) {
            ScriptState* ss = resolver->GetScriptState();
            ScriptState::Scope scope(ss);
            v8::Isolate* isolate = ss->GetIsolate();
            v8::Local<v8::Context> ctx = ss->GetContext();
            v8::Local<v8::Value> parsed;
            v8::Local<v8::String> json_str = V8String(isolate, constraints_json);
            if (v8::JSON::Parse(ctx, json_str).ToLocal(&parsed)) {
              resolver->Resolve(ScriptValue(isolate, parsed));
            } else {
              resolver->Resolve(ScriptValue(isolate,
                  v8::Array::New(isolate, 0)));
            }
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> SharedGraph::myCapabilities(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!shared_host_.is_bound()) {
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

  shared_host_->MyCapabilities(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         const String& capabilities_json) {
        ScriptState* ss = resolver->GetScriptState();
        ScriptState::Scope scope(ss);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> ctx = ss->GetContext();
        v8::Local<v8::Value> parsed;
        v8::Local<v8::String> json_str = V8String(isolate, capabilities_json);
        if (v8::JSON::Parse(ctx, json_str).ToLocal(&parsed)) {
          resolver->Resolve(ScriptValue(isolate, parsed));
        } else {
          // Fallback to permissive defaults if JSON parse fails.
          v8::Local<v8::Object> caps = v8::Object::New(isolate);
          caps->Set(ctx, V8String(isolate, "canAddTriples"),
                    v8::True(isolate)).Check();
          caps->Set(ctx, V8String(isolate, "canRemoveTriples"),
                    v8::True(isolate)).Check();
          caps->Set(ctx, V8String(isolate, "allowedPredicates"),
                    v8::Array::New(isolate, 0)).Check();
          resolver->Resolve(ScriptValue(isolate, caps));
        }
      },
      WrapPersistent(resolver)));

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
