// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/personal_graph_manager.h"

#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/shared_graph.h"
#include "third_party/blink/renderer/modules/graph/personal_graph.h"
#include "mojo/public/mojom/graph/graph_sync.mojom-blink.h"
#include "third_party/blink/renderer/modules/graph/did_credential.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "v8/include/v8-microtask-queue.h"

namespace blink {

namespace {

scoped_refptr<base::SequencedTaskRunner> GetTaskRunner(
    ExecutionContext* context) {
  // SingleThreadTaskRunner IS-A SequencedTaskRunner; explicit cast needed.
  return static_cast<scoped_refptr<base::SequencedTaskRunner>>(
      context->GetTaskRunner(TaskType::kMiscPlatformAPI));
}

}  // namespace

PersonalGraphManager::PersonalGraphManager(ExecutionContext* context)
    : execution_context_(context),
      service_(context),
      sync_service_(context),
      did_service_(context) {}

void PersonalGraphManager::EnsureServiceConnected() {
  if (service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(GetTaskRunner(execution_context_)));
}

// Helper: create a real PersonalGraph object backed by a Mojo remote.
namespace {

PersonalGraph* CreatePersonalGraphObject(
    ExecutionContext* context,
    PersonalGraphManager* manager,
    const String& uuid,
    const String& name) {
  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host_remote;
  auto host_receiver = host_remote.InitWithNewPipeAndPassReceiver();
  manager->GetGraphService()->BindGraph(uuid, std::move(host_receiver));
  return MakeGarbageCollected<PersonalGraph>(
      context, uuid, name, std::move(host_remote), manager);
}

void ResolveWithPersonalGraph(
    ScriptPromiseResolver<IDLAny>* resolver,
    ExecutionContext* context,
    PersonalGraphManager* manager,
    const String& uuid,
    const String& name) {
  ScriptState* ss = resolver->GetScriptState();
  if (!ss->ContextIsValid()) return;
  ScriptState::Scope scope(ss);
  v8::MicrotasksScope microtasks(ss->GetIsolate(),
      ss->GetContext()->GetMicrotaskQueue(),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  auto* graph = CreatePersonalGraphObject(context, manager, uuid, name);
  v8::Local<v8::Value> v8_graph = ToV8Traits<PersonalGraph>::ToV8(ss, graph);
  resolver->Resolve(ScriptValue(ss->GetIsolate(), v8_graph));
}

v8::Local<v8::Object> MakeDIDCredentialObject(
    v8::Isolate* isolate,
    v8::Local<v8::Context> ctx,
    const graph::mojom::blink::DIDCredentialInfoPtr& info) {
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  obj->Set(ctx, V8String(isolate, "id"), V8String(isolate, info->id)).Check();
  obj->Set(ctx, V8String(isolate, "did"), V8String(isolate, info->did)).Check();
  obj->Set(ctx, V8String(isolate, "algorithm"), V8String(isolate, info->algorithm)).Check();
  obj->Set(ctx, V8String(isolate, "displayName"), V8String(isolate, info->display_name)).Check();
  obj->Set(ctx, V8String(isolate, "createdAt"), V8String(isolate, info->created_at)).Check();
  obj->Set(ctx, V8String(isolate, "isLocked"), v8::Boolean::New(isolate, info->is_locked)).Check();
  return obj;
}

}  // namespace

ScriptPromise<IDLAny> PersonalGraphManager::create(ScriptState* script_state,
                                                    const String& name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureServiceConnected();

  service_->CreateGraph(
      name,
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             ExecutionContext* context,
             PersonalGraphManager* manager,
             graph::mojom::blink::GraphInfoPtr info) {
            if (!info) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kOperationError,
                  "Failed to create graph"));
              return;
            }
            ResolveWithPersonalGraph(resolver, context, manager, info->uuid, info->name);
          },
          WrapPersistent(resolver),
          WrapPersistent(execution_context_.Get()),
          WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::list(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureServiceConnected();

  service_->ListGraphs(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         ExecutionContext* context,
         PersonalGraphManager* manager,
         Vector<graph::mojom::blink::GraphInfoPtr> infos) {
        ScriptState* ss = resolver->GetScriptState();
        if (!ss->ContextIsValid()) return;
        ScriptState::Scope scope(ss);
        v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> v8_ctx = ss->GetContext();
        v8::Local<v8::Array> arr =
            v8::Array::New(isolate, static_cast<int>(infos.size()));
        for (wtf_size_t i = 0; i < infos.size(); i++) {
          auto* graph = CreatePersonalGraphObject(context, manager, infos[i]->uuid, infos[i]->name);
          v8::Local<v8::Value> v8_graph = ToV8Traits<PersonalGraph>::ToV8(ss, graph);
          arr->Set(v8_ctx, i, v8_graph).Check();
        }
        resolver->Resolve(ScriptValue(isolate, arr));
      },
      WrapPersistent(resolver),
      WrapPersistent(execution_context_.Get()),
      WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::get(ScriptState* script_state,
                                                 const String& uuid) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureServiceConnected();

  service_->GetGraph(
      uuid,
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             ExecutionContext* context,
             PersonalGraphManager* manager,
             graph::mojom::blink::GraphInfoPtr info) {
            if (!info) {
              resolver->Resolve(
                  ScriptValue::CreateNull(resolver->GetScriptState()->GetIsolate()));
              return;
            }
            ResolveWithPersonalGraph(resolver, context, manager, info->uuid, info->name);
          },
          WrapPersistent(resolver),
          WrapPersistent(execution_context_.Get()),
          WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::remove(ScriptState* script_state,
                                                    const String& uuid) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureServiceConnected();

  service_->RemoveGraph(
      uuid,
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver, bool success) {
            ScriptState* ss = resolver->GetScriptState();
            if (!ss->ContextIsValid()) return;
            ScriptState::Scope scope(ss);
        v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
            resolver->Resolve(ScriptValue(
                ss->GetIsolate(),
                v8::Boolean::New(ss->GetIsolate(), success)));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::join(ScriptState* script_state,
                                                  const String& uri) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureSyncServiceConnected();

  sync_service_->JoinGraph(
      uri,
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             PersonalGraphManager* manager,
             const String& uri,
             graph::mojom::blink::SharedGraphInfoPtr info) {
            if (!info) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kOperationError,
                  "Failed to join shared graph"));
              return;
            }

            ExecutionContext* context = manager->GetExecutionContext();

            // For a joined graph, we don't have a local graph UUID yet.
            // Create an unbound PersonalGraphHost (no triple ops until synced).
            mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost>
                host_remote;

            // Bind SharedGraphHost for sync/governance.
            mojo::PendingRemote<graph::mojom::blink::SharedGraphHost>
                shared_remote;
            auto shared_receiver =
                shared_remote.InitWithNewPipeAndPassReceiver();
            manager->GetSyncService()->BindSharedGraph(
                uri, std::move(shared_receiver));

            ScriptState* ss = resolver->GetScriptState();
            if (!ss->ContextIsValid()) return;
            ScriptState::Scope scope(ss);
        v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);

            // For joined graphs, uuid is empty until synced locally.
            String joined_uuid = "";
            auto* shared = MakeGarbageCollected<SharedGraph>(
                context, joined_uuid, uri,
                std::move(host_remote), std::move(shared_remote));
            v8::Local<v8::Value> v8_shared =
                ToV8Traits<SharedGraph>::ToV8(ss, shared);
            resolver->Resolve(
                ScriptValue(ss->GetIsolate(), v8_shared));
          },
          WrapPersistent(resolver),
          WrapPersistent(this),
          uri));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::listShared(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureSyncServiceConnected();

  sync_service_->ListSharedGraphs(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         Vector<graph::mojom::blink::SharedGraphInfoPtr> infos) {
        ScriptState* ss = resolver->GetScriptState();
        if (!ss->ContextIsValid()) return;
        ScriptState::Scope scope(ss);
        v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> ctx = ss->GetContext();
        v8::Local<v8::Array> arr =
            v8::Array::New(isolate, static_cast<int>(infos.size()));
        for (wtf_size_t i = 0; i < infos.size(); i++) {
          v8::Local<v8::Object> obj = v8::Object::New(isolate);
          obj->Set(ctx, V8String(isolate, "uri"),
                   V8String(isolate, infos[i]->uri)).Check();
          obj->Set(ctx, V8String(isolate, "name"),
                   V8String(isolate, infos[i]->name)).Check();
          obj->Set(ctx, V8String(isolate, "peerCount"),
                   v8::Number::New(isolate, infos[i]->peer_count)).Check();
          arr->Set(ctx, i, obj).Check();
        }
        resolver->Resolve(ScriptValue(isolate, arr));
      },
      WrapPersistent(resolver)));

  return promise;
}

void PersonalGraphManager::EnsureSyncServiceConnected() {
  if (sync_service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      sync_service_.BindNewPipeAndPassReceiver(GetTaskRunner(execution_context_)));
}

void PersonalGraphManager::EnsureDIDServiceConnected() {
  if (did_service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      did_service_.BindNewPipeAndPassReceiver(GetTaskRunner(execution_context_)));
}

ScriptPromise<IDLAny> PersonalGraphManager::createIdentity(
    ScriptState* script_state,
    const String& display_name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureDIDServiceConnected();

  did_service_->CreateCredential(
      display_name, "Ed25519",
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             ExecutionContext* context,
             PersonalGraphManager* manager,
             graph::mojom::blink::DIDCredentialInfoPtr info) {
            if (!info) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kOperationError,
                  "Failed to create identity"));
              return;
            }
            ScriptState* ss = resolver->GetScriptState();
            if (!ss->ContextIsValid()) return;
            ScriptState::Scope scope(ss);
        v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
            v8::Isolate* isolate = ss->GetIsolate();
            v8::Local<v8::Context> v8_ctx = ss->GetContext();
            resolver->Resolve(ScriptValue(isolate, MakeDIDCredentialObject(isolate, v8_ctx, info)));
          },
          WrapPersistent(resolver),
          WrapPersistent(execution_context_.Get()),
          WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::listIdentities(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureDIDServiceConnected();

  did_service_->ListCredentials(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         ExecutionContext* context,
         PersonalGraphManager* manager,
         Vector<graph::mojom::blink::DIDCredentialInfoPtr> infos) {
        ScriptState* ss = resolver->GetScriptState();
        if (!ss->ContextIsValid()) return;
        ScriptState::Scope scope(ss);
        v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> v8_ctx = ss->GetContext();
        v8::Local<v8::Array> arr =
            v8::Array::New(isolate, static_cast<int>(infos.size()));
        for (wtf_size_t i = 0; i < infos.size(); i++) {
          arr->Set(v8_ctx, i, MakeDIDCredentialObject(isolate, v8_ctx, infos[i])).Check();
        }
        resolver->Resolve(ScriptValue(isolate, arr));
      },
      WrapPersistent(resolver),
      WrapPersistent(execution_context_.Get()),
      WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::activeIdentity(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureDIDServiceConnected();

  did_service_->GetActiveCredential(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         ExecutionContext* context,
         PersonalGraphManager* manager,
         graph::mojom::blink::DIDCredentialInfoPtr info) {
        if (!info) {
          resolver->Resolve(ScriptValue::CreateNull(
              resolver->GetScriptState()->GetIsolate()));
          return;
        }
        ScriptState* ss = resolver->GetScriptState();
        if (!ss->ContextIsValid()) return;
        ScriptState::Scope scope(ss);
        v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> v8_ctx = ss->GetContext();
        resolver->Resolve(ScriptValue(isolate, MakeDIDCredentialObject(isolate, v8_ctx, info)));
      },
      WrapPersistent(resolver),
      WrapPersistent(execution_context_.Get()),
      WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::setActiveIdentity(
    ScriptState* script_state,
    const String& did) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureDIDServiceConnected();

  // List credentials to find the one matching the DID, then set it active.
  did_service_->ListCredentials(BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         ExecutionContext* context,
         PersonalGraphManager* manager,
         const String& target_did,
         Vector<graph::mojom::blink::DIDCredentialInfoPtr> infos) {
        String credential_id;
        for (const auto& info : infos) {
          if (info->did == target_did) {
            credential_id = info->id;
            break;
          }
        }
        if (credential_id.IsNull()) {
          ScriptState* ss = resolver->GetScriptState();
          if (!ss->ContextIsValid()) return;
          ScriptState::Scope scope(ss);
          v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
          resolver->Resolve(ScriptValue(ss->GetIsolate(),
                                        v8::Boolean::New(ss->GetIsolate(), false)));
          return;
        }
        manager->GetDIDService()->SetActiveCredential(
            credential_id.Utf8().c_str(),
            BindOnce(
                [](ScriptPromiseResolver<IDLAny>* resolver, bool success) {
                  ScriptState* ss = resolver->GetScriptState();
                  if (!ss->ContextIsValid()) return;
                  ScriptState::Scope scope(ss);
                  v8::MicrotasksScope microtasks(ss->GetIsolate(), ss->GetContext()->GetMicrotaskQueue(), v8::MicrotasksScope::kDoNotRunMicrotasks);
                  resolver->Resolve(ScriptValue(ss->GetIsolate(),
                                                v8::Boolean::New(ss->GetIsolate(), success)));
                },
                WrapPersistent(resolver)));
      },
      WrapPersistent(resolver),
      WrapPersistent(execution_context_.Get()),
      WrapPersistent(this),
      did));

  return promise;
}

void PersonalGraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(service_);
  visitor->Trace(sync_service_);
  visitor->Trace(did_service_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
