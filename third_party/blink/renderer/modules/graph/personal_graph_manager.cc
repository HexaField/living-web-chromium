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
#include "third_party/blink/renderer/modules/graph/personal_graph.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"

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
      service_(context) {}

void PersonalGraphManager::EnsureServiceConnected() {
  if (service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(GetTaskRunner(execution_context_)));
}

// Helper: bind a PersonalGraphHost for a graph UUID, create the
// PersonalGraph object, and resolve the promise.
namespace {

void BindAndResolve(
    ScriptPromiseResolver<IDLAny>* resolver,
    ExecutionContext* context,
    HeapMojoRemote<graph::mojom::blink::PersonalGraphService>& service,
    const String& uuid,
    const String& name) {
  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host_remote;
  auto host_receiver = host_remote.InitWithNewPipeAndPassReceiver();
  service->BindGraph(uuid, std::move(host_receiver));
  auto* graph = MakeGarbageCollected<PersonalGraph>(
      context, uuid, name, std::move(host_remote));
  ScriptState* ss = resolver->GetScriptState();
  ScriptState::Scope scope(ss);
  resolver->Resolve(ScriptValue(
      ss->GetIsolate(),
      ToV8Traits<PersonalGraph>::ToV8(ss, graph)));
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
            BindAndResolve(resolver, context, manager->service_,
                           info->uuid, info->name);
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
        ScriptState::Scope scope(ss);
        v8::Isolate* isolate = ss->GetIsolate();
        v8::Local<v8::Context> v8_ctx = ss->GetContext();
        v8::Local<v8::Array> arr =
            v8::Array::New(isolate, static_cast<int>(infos.size()));
        for (wtf_size_t i = 0; i < infos.size(); i++) {
          mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost>
              host_remote;
          auto host_receiver = host_remote.InitWithNewPipeAndPassReceiver();
          manager->service_->BindGraph(infos[i]->uuid,
                                        std::move(host_receiver));
          auto* graph = MakeGarbageCollected<PersonalGraph>(
              context, infos[i]->uuid, infos[i]->name,
              std::move(host_remote));
          arr->Set(v8_ctx, i,
                   ToV8Traits<PersonalGraph>::ToV8(ss, graph))
              .Check();
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
            BindAndResolve(resolver, context, manager->service_,
                           info->uuid, info->name);
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
  resolver->Resolve(ScriptValue::CreateNull(script_state->GetIsolate()));
  return resolver->Promise();
}

ScriptPromise<IDLAny> PersonalGraphManager::listShared(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  ScriptState::Scope scope(script_state);
  resolver->Resolve(ScriptValue(script_state->GetIsolate(),
                                v8::Array::New(script_state->GetIsolate(), 0)));
  return resolver->Promise();
}

void PersonalGraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(service_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
