// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph_manager.h"

#include <utility>

#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_from_snapshot_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_snapshot_format.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/graph_snapshot.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
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

// §5.5: default trust level is "external"; local creation is not reachable here.
graph::mojom::blink::GraphTrustLevel TrustLevelFromString(const String& value) {
  return value == "local" ? graph::mojom::blink::GraphTrustLevel::kLocal
                          : graph::mojom::blink::GraphTrustLevel::kExternal;
}

}  // namespace

// static
Vector<V8SnapshotFormat> GraphManager::supportedSnapshotFormats() {
  // §5.3.4: the three REQUIRED formats. jsonld is OPTIONAL and omitted because
  // RDF 1.2 triple terms (carried by every reifier) have no stable JSON-LD 1.2
  // (@triple) form in current tooling. Must stay in sync with the browser-side
  // SupportedSnapshotFormats() enforced by GetAsSnapshot()/FromSnapshot().
  return {
      V8SnapshotFormat(V8SnapshotFormat::Enum::kNquadsCanonical),
      V8SnapshotFormat(V8SnapshotFormat::Enum::kNquads),
      V8SnapshotFormat(V8SnapshotFormat::Enum::kTurtle),
  };
}

GraphManager::GraphManager(ExecutionContext* context)
    : execution_context_(context), service_(context) {}

void GraphManager::ConnectToBrowser() {
  if (service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(
          GetTaskRunner(execution_context_.Get())));
}

ScriptPromise<Graph> GraphManager::create(ScriptState* script_state,
                                          const GraphCreationOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Graph>>(script_state);
  auto promise = resolver->Promise();

  ConnectToBrowser();

  String display_name;
  if (options->hasDisplayName())
    display_name = options->displayName();

  // §3.4: mint the PersonalGraphHost pipe; hand the receiver to the browser so
  // it can bind the new graph, and keep the remote for the Graph object.
  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host_remote;
  auto host_receiver = host_remote.InitWithNewPipeAndPassReceiver();

  service_->Create(
      display_name.IsNull() ? String() : display_name, std::move(host_receiver),
      WTF::BindOnce(
          [](ScriptPromiseResolver<Graph>* resolver,
             ExecutionContext* context,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host,
             graph::mojom::blink::GraphInfoPtr info) {
            if (!info) {
              resolver->RejectWithDOMException(
                  DOMExceptionCode::kInvalidStateError,
                  "Failed to create graph");
              return;
            }
            resolver->Resolve(MakeGarbageCollected<Graph>(context, info,
                                                          std::move(host)));
          },
          WrapPersistent(resolver),
          WrapPersistent(execution_context_.Get()), std::move(host_remote)));

  return promise;
}

ScriptPromise<Graph> GraphManager::fromSnapshot(
    ScriptState* script_state,
    GraphSnapshot* snapshot,
    const GraphFromSnapshotOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Graph>>(script_state);
  auto promise = resolver->Promise();

  ConnectToBrowser();

  graph::mojom::blink::GraphTrustLevel trust =
      TrustLevelFromString(options->trustLevel().AsString());

  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host_remote;
  auto host_receiver = host_remote.InitWithNewPipeAndPassReceiver();

  service_->FromSnapshot(
      snapshot->ToMojo(), trust, std::move(host_receiver),
      WTF::BindOnce(
          [](ScriptPromiseResolver<Graph>* resolver,
             ExecutionContext* context,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host,
             graph::mojom::blink::GraphInfoPtr info, const String& error) {
            if (!info || !error.IsNull()) {
              // §5.5: browser returns a DOMException name on failure
              // ("NotSupportedError", "DataError", "QuotaExceededError", ...).
              Graph::RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(MakeGarbageCollected<Graph>(context, info,
                                                          std::move(host)));
          },
          WrapPersistent(resolver),
          WrapPersistent(execution_context_.Get()), std::move(host_remote)));

  return promise;
}

void GraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(service_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
