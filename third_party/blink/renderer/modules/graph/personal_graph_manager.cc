// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/personal_graph_manager.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/personal_graph.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"

using WTF::BindOnce;
using WTF::WrapPersistent;

namespace blink {

PersonalGraphManager::PersonalGraphManager(ExecutionContext* context)
    : execution_context_(context),
      service_(context) {}

void PersonalGraphManager::EnsureServiceConnected() {
  if (service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(
          execution_context_->GetTaskRunner(TaskType::kMiscPlatformAPI)));
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
  resolver->Resolve(graph);
}

}  // namespace

ScriptPromise<IDLAny> PersonalGraphManager::create(ScriptState* script_state,
                                                    const String& name) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  EnsureServiceConnected();

  std::optional<WTF::String> opt_name;
  if (!name.IsNull() && !name.empty())
    opt_name = name;

  service_->CreateGraph(
      opt_name,
      WTF::BindOnce(
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

  service_->ListGraphs(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         ExecutionContext* context,
         PersonalGraphManager* manager,
         WTF::Vector<graph::mojom::blink::GraphInfoPtr> infos) {
        HeapVector<Member<PersonalGraph>> graphs;
        for (const auto& info : infos) {
          mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost>
              host_remote;
          auto host_receiver = host_remote.InitWithNewPipeAndPassReceiver();
          manager->service_->BindGraph(info->uuid, std::move(host_receiver));
          graphs.push_back(MakeGarbageCollected<PersonalGraph>(
              context, info->uuid, info->name,
              std::move(host_remote)));
        }
        resolver->Resolve(graphs);
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
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             ExecutionContext* context,
             PersonalGraphManager* manager,
             graph::mojom::blink::GraphInfoPtr info) {
            if (!info) {
              resolver->Resolve(
                  ScriptValue::CreateNull(resolver->GetScriptState()));
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
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver, bool success) {
            resolver->Resolve(success);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> PersonalGraphManager::join(ScriptState* script_state,
                                                  const String& uri) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  resolver->Resolve(ScriptValue::CreateNull(script_state));
  return resolver->Promise();
}

ScriptPromise<IDLAny> PersonalGraphManager::listShared(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  HeapVector<Member<PersonalGraph>> empty;
  resolver->Resolve(empty);
  return resolver->Promise();
}

void PersonalGraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(service_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
