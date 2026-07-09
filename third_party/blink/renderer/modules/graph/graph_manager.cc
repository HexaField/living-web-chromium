// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph_manager.h"

#include <utility>

#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_fork_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_from_snapshot_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_group_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_groupify_options.h"
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

// §8.2 option dictionaries -> Mojo. Absent optional members stay null; the
// required |syncModule| is always present (enforced by the bindings).
graph::mojom::blink::GroupCreationOptionsPtr CreationOptionsToMojo(
    const GroupCreationOptions* options) {
  auto out = graph::mojom::blink::GroupCreationOptions::New();
  out->sync_module = options->syncModule();
  if (options->hasDisplayName())
    out->display_name = options->displayName();
  if (options->hasDescription())
    out->description = options->description();
  if (options->hasInitialDelegates())
    out->initial_delegates = options->initialDelegates();
  if (options->hasParticipatesIn())
    out->participates_in = options->participatesIn();
  return out;
}

graph::mojom::blink::GroupifyOptionsPtr GroupifyOptionsToMojo(
    const GroupifyOptions* options) {
  auto out = graph::mojom::blink::GroupifyOptions::New();
  out->sync_module = options->syncModule();
  if (options->hasDisplayName())
    out->display_name = options->displayName();
  if (options->hasDescription())
    out->description = options->description();
  if (options->hasInitialDelegates())
    out->initial_delegates = options->initialDelegates();
  return out;
}

graph::mojom::blink::ForkOptionsPtr ForkOptionsToMojo(
    const ForkOptions* options) {
  auto out = graph::mojom::blink::ForkOptions::New();
  out->sync_module = options->syncModule();
  if (options->hasForkRevision())
    out->fork_revision = options->forkRevision();
  // §4.8: announceFork defaults to true (applied by the bindings).
  out->announce_fork = options->announceFork();
  if (options->hasInitialDelegates())
    out->initial_delegates = options->initialDelegates();
  if (options->hasDisplayName())
    out->display_name = options->displayName();
  if (options->hasDescription())
    out->description = options->description();
  return out;
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
    : execution_context_(context),
      service_(context),
      group_service_(context) {}

void GraphManager::ConnectToBrowser() {
  if (service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(
          GetTaskRunner(execution_context_.Get())));
}

void GraphManager::ConnectToGroupService() {
  if (group_service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      group_service_.BindNewPipeAndPassReceiver(
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

Group* GraphManager::BuildGroup(
    ExecutionContext* context,
    const graph::mojom::blink::GroupInfoPtr& info,
    mojo::PendingRemote<graph::mojom::blink::GroupHost> group_host,
    mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> graph_host) {
  // The host graph is freshly materialised alongside the group; wrap it in a
  // Graph bound to |graph_host|, then hand both to the Group.
  auto* graph =
      MakeGarbageCollected<Graph>(context, info->graph, std::move(graph_host));
  return MakeGarbageCollected<Group>(context, info, std::move(group_host),
                                     graph, this);
}

ScriptPromise<Group> GraphManager::createGroup(
    ScriptState* script_state,
    const GroupCreationOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Group>>(script_state);
  auto promise = resolver->Promise();

  ConnectToGroupService();

  // §8.2: allocate a fresh host-graph pipe and a GroupHost pipe; the browser
  // binds both to the newly groupified graph.
  mojo::PendingRemote<graph::mojom::blink::GroupHost> group_remote;
  auto group_receiver = group_remote.InitWithNewPipeAndPassReceiver();
  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> graph_remote;
  auto graph_receiver = graph_remote.InitWithNewPipeAndPassReceiver();

  group_service_->CreateGroup(
      CreationOptionsToMojo(options), std::move(group_receiver),
      std::move(graph_receiver),
      WTF::BindOnce(
          [](ScriptPromiseResolver<Group>* resolver, GraphManager* self,
             ExecutionContext* context,
             mojo::PendingRemote<graph::mojom::blink::GroupHost> group_host,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost>
                 graph_host,
             graph::mojom::blink::GroupInfoPtr info, const String& error) {
            if (!info || !error.IsNull()) {
              Graph::RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(self->BuildGroup(context, info,
                                               std::move(group_host),
                                               std::move(graph_host)));
          },
          WrapPersistent(resolver), WrapPersistent(this),
          WrapPersistent(execution_context_.Get()), std::move(group_remote),
          std::move(graph_remote)));

  return promise;
}

ScriptPromise<Group> GraphManager::groupify(ScriptState* script_state,
                                            Graph* graph,
                                            const GroupifyOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Group>>(script_state);
  auto promise = resolver->Promise();

  ConnectToGroupService();

  // §8.2: groupify reuses the caller's existing graph (named by its internal
  // id) — only the GroupHost pipe is minted, and the returned Group's `graph`
  // is the very object the caller passed in.
  mojo::PendingRemote<graph::mojom::blink::GroupHost> group_remote;
  auto group_receiver = group_remote.InitWithNewPipeAndPassReceiver();

  group_service_->Groupify(
      graph->InternalId(), GroupifyOptionsToMojo(options),
      std::move(group_receiver),
      WTF::BindOnce(
          [](ScriptPromiseResolver<Group>* resolver, GraphManager* self,
             ExecutionContext* context, Graph* graph,
             mojo::PendingRemote<graph::mojom::blink::GroupHost> group_host,
             graph::mojom::blink::GroupInfoPtr info, const String& error) {
            if (!info || !error.IsNull()) {
              Graph::RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(MakeGarbageCollected<Group>(
                context, info, std::move(group_host), graph, self));
          },
          WrapPersistent(resolver), WrapPersistent(this),
          WrapPersistent(execution_context_.Get()), WrapPersistent(graph),
          std::move(group_remote)));

  return promise;
}

ScriptPromise<Group> GraphManager::forkGroup(ScriptState* script_state,
                                             const String& parent_iri_or_did,
                                             const ForkOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Group>>(script_state);
  auto promise = resolver->Promise();

  ConnectToGroupService();

  mojo::PendingRemote<graph::mojom::blink::GroupHost> group_remote;
  auto group_receiver = group_remote.InitWithNewPipeAndPassReceiver();
  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> graph_remote;
  auto graph_receiver = graph_remote.InitWithNewPipeAndPassReceiver();

  group_service_->ForkGroup(
      parent_iri_or_did, ForkOptionsToMojo(options), std::move(group_receiver),
      std::move(graph_receiver),
      WTF::BindOnce(
          [](ScriptPromiseResolver<Group>* resolver, GraphManager* self,
             ExecutionContext* context,
             mojo::PendingRemote<graph::mojom::blink::GroupHost> group_host,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost>
                 graph_host,
             graph::mojom::blink::GroupInfoPtr info, const String& error) {
            if (!info || !error.IsNull()) {
              Graph::RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(self->BuildGroup(context, info,
                                               std::move(group_host),
                                               std::move(graph_host)));
          },
          WrapPersistent(resolver), WrapPersistent(this),
          WrapPersistent(execution_context_.Get()), std::move(group_remote),
          std::move(graph_remote)));

  return promise;
}

ScriptPromise<Group> GraphManager::openGroup(ScriptState* script_state,
                                             const String& iri_or_did) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Group>>(script_state);
  auto promise = resolver->Promise();

  // §8.2: openGroup fails only when the group is not locally mounted (§4.7).
  OpenGroupByDid(
      iri_or_did,
      WTF::BindOnce(
          [](ScriptPromiseResolver<Group>* resolver, Group* group) {
            if (!group) {
              resolver->RejectWithDOMException(
                  DOMExceptionCode::kNotFoundError,
                  "The group is not locally mounted");
              return;
            }
            resolver->Resolve(group);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<Group>> GraphManager::listGroups(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Group>>>(
          script_state);
  auto promise = resolver->Promise();

  ConnectToGroupService();

  group_service_->ListGroups(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Group>>* resolver,
         GraphManager* self, Vector<String> dids) {
        Group::ResolveGroupList(self, resolver, dids);
      },
      WrapPersistent(resolver), WrapPersistent(this)));

  return promise;
}

void GraphManager::OpenGroupByDid(const String& iri_or_did,
                                  base::OnceCallback<void(Group*)> on_done) {
  ConnectToGroupService();

  mojo::PendingRemote<graph::mojom::blink::GroupHost> group_remote;
  auto group_receiver = group_remote.InitWithNewPipeAndPassReceiver();
  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> graph_remote;
  auto graph_receiver = graph_remote.InitWithNewPipeAndPassReceiver();

  group_service_->OpenGroup(
      iri_or_did, std::move(group_receiver), std::move(graph_receiver),
      WTF::BindOnce(
          [](GraphManager* self, ExecutionContext* context,
             base::OnceCallback<void(Group*)> on_done,
             mojo::PendingRemote<graph::mojom::blink::GroupHost> group_host,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost>
                 graph_host,
             graph::mojom::blink::GroupInfoPtr info, const String& error) {
            if (!info || !error.IsNull()) {
              std::move(on_done).Run(nullptr);
              return;
            }
            std::move(on_done).Run(self->BuildGroup(
                context, info, std::move(group_host), std::move(graph_host)));
          },
          WrapPersistent(this), WrapPersistent(execution_context_.Get()),
          std::move(on_done), std::move(group_remote),
          std::move(graph_remote)));
}

void GraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(service_);
  visitor->Trace(group_service_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
