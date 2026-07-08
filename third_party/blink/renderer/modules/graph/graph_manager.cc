// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph_manager.h"

#include <utility>

#include "base/notreached.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_capability_proof_input.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_fork_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_from_snapshot_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_sync_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_group_creation_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_groupify_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_module_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_mount_mode.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_mount_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_mounted_graph_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_snapshot_format.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sync_module_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_sync_space_info.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/graph_snapshot.h"
#include "third_party/blink/renderer/modules/graph/subscription_event.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
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

// ---- Spec 05 §6 synchronisation converters ----

// §6.2 MountMode <-> V8. The arms are exhaustive; the trailing NOTREACHED guards
// a value the bindings can never produce.
graph::mojom::blink::MountMode MountModeFromV8(const V8MountMode& mode) {
  switch (mode.AsEnum()) {
    case V8MountMode::Enum::kRead:
      return graph::mojom::blink::MountMode::kRead;
    case V8MountMode::Enum::kWrite:
      return graph::mojom::blink::MountMode::kWrite;
    case V8MountMode::Enum::kGovernance:
      return graph::mojom::blink::MountMode::kGovernance;
  }
  NOTREACHED();
}

V8MountMode MountModeToV8(graph::mojom::blink::MountMode mode) {
  switch (mode) {
    case graph::mojom::blink::MountMode::kRead:
      return V8MountMode(V8MountMode::Enum::kRead);
    case graph::mojom::blink::MountMode::kWrite:
      return V8MountMode(V8MountMode::Enum::kWrite);
    case graph::mojom::blink::MountMode::kGovernance:
      return V8MountMode(V8MountMode::Enum::kGovernance);
  }
  NOTREACHED();
}

// §5.5 GraphSyncState / §6.4 ModuleState: Mojo enum -> V8 enum. Local copies of
// the Graph.cc converters — the two translation units do not share a header.
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

V8ModuleState ModuleStateToV8(graph::mojom::blink::ModuleState state) {
  switch (state) {
    case graph::mojom::blink::ModuleState::kRunning:
      return V8ModuleState(V8ModuleState::Enum::kRunning);
    case graph::mojom::blink::ModuleState::kSuspended:
      return V8ModuleState(V8ModuleState::Enum::kSuspended);
    case graph::mojom::blink::ModuleState::kError:
      return V8ModuleState(V8ModuleState::Enum::kError);
  }
  NOTREACHED();
}

// JSON-serialise a script object to its canonical string — the presentation JSON
// the browser stores. Returns false when the value cannot be stringified (e.g. a
// cycle). The v8 handle must be live, so this runs before the async host call.
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

// §6.2 MountOptions -> Mojo. |mode| carries its "read" default from the bindings.
// capabilityProof is copied only when present (REQUIRED for write/governance
// mounts, enforced browser-side); its presentations are stringified here while
// their v8 handles are live. The URI/hash strings are non-nullable on the wire,
// so absent members default to empty rather than a null WTF::String.
graph::mojom::blink::MountOptionsPtr MountOptionsToMojo(
    ScriptState* script_state,
    const MountOptions* options) {
  auto out = graph::mojom::blink::MountOptions::New();
  out->mode = MountModeFromV8(options->mode());
  if (options->hasCapabilityProof()) {
    const CapabilityProofInput* proof = options->capabilityProof();
    auto mojo_proof = graph::mojom::blink::CapabilityProofInput::New();
    mojo_proof->chain = proof->chain();
    if (proof->hasPresentations()) {
      for (const auto& presentation : proof->presentations()) {
        String json;
        if (SerializeToJson(script_state, presentation, json))
          mojo_proof->presentations.push_back(json);
      }
    }
    out->capability_proof = std::move(mojo_proof);
  }
  out->snapshot_uri =
      options->hasSnapshotUri() ? options->snapshotUri() : g_empty_string;
  out->space_uri =
      options->hasSpaceUri() ? options->spaceUri() : g_empty_string;
  out->module_hash =
      options->hasModuleHash() ? options->moduleHash() : g_empty_string;
  if (options->hasRelays())
    out->relays = options->relays();
  return out;
}

// §6.4 Mojo inventory entries -> Blink dictionaries.
MountedGraphInfo* MountedInfoFromMojo(
    const graph::mojom::blink::MountedGraphInfoPtr& info) {
  auto* out = MakeGarbageCollected<MountedGraphInfo>();
  out->setGraphDid(info->graph_did);
  out->setMode(MountModeToV8(info->mode));
  out->setSyncState(SyncStateToV8(info->sync_state));
  out->setSpaceUri(info->space_uri);
  out->setModuleHash(info->module_hash);
  out->setPeerCount(info->peer_count);
  return out;
}

SyncModuleInfo* ModuleInfoFromMojo(
    const graph::mojom::blink::SyncModuleInfoPtr& info) {
  auto* out = MakeGarbageCollected<SyncModuleInfo>();
  out->setContentHash(info->content_hash);
  if (!info->name.IsNull())
    out->setName(info->name);
  out->setSpaceCount(info->space_count);
  out->setState(ModuleStateToV8(info->state));
  out->setStorageBytes(info->storage_bytes);
  return out;
}

SyncSpaceInfo* SpaceInfoFromMojo(
    const graph::mojom::blink::SyncSpaceInfoPtr& info) {
  auto* out = MakeGarbageCollected<SyncSpaceInfo>();
  out->setSpaceUri(info->space_uri);
  out->setModuleHash(info->module_hash);
  out->setGraphCount(info->graph_count);
  out->setPeerCount(info->peer_count);
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
      group_service_(context),
      manager_client_(this, context) {}

void GraphManager::ConnectToBrowser() {
  if (service_.is_bound())
    return;
  execution_context_->GetBrowserInterfaceBroker().GetInterface(
      service_.BindNewPipeAndPassReceiver(
          GetTaskRunner(execution_context_.Get())));
  // §6.4: register the realm's subscription-event sink as soon as the manager is
  // bound, so onsubscriptiongained / onsubscriptionlost can be delivered.
  service_->SubscribeManager(manager_client_.BindNewPipeAndPassRemote(
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

ScriptPromise<Graph> GraphManager::mount(ScriptState* script_state,
                                         const String& graph_did,
                                         const MountOptions* options) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<Graph>>(script_state);
  auto promise = resolver->Promise();

  ConnectToBrowser();

  // §6.2: a "read" mount yields a read-only Graph. The flag is computed here and
  // threaded to the constructed Graph so its mutating operations reject
  // synchronously, before any diff is built.
  bool read_only =
      MountModeFromV8(options->mode()) == graph::mojom::blink::MountMode::kRead;

  // §6.2: mint the PersonalGraphHost pipe for the mounted graph; the browser
  // binds the receiver once the mount is authorised.
  mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host_remote;
  auto host_receiver = host_remote.InitWithNewPipeAndPassReceiver();

  service_->Mount(
      graph_did, MountOptionsToMojo(script_state, options),
      std::move(host_receiver),
      WTF::BindOnce(
          [](ScriptPromiseResolver<Graph>* resolver, ExecutionContext* context,
             bool read_only,
             mojo::PendingRemote<graph::mojom::blink::PersonalGraphHost> host,
             graph::mojom::blink::GraphInfoPtr info, const String& error) {
            if (!info || !error.IsNull()) {
              // §6.2: browser returns a DOMException name — "InvalidStateError"
              // (already mounted), "NotAllowedError" (authorisation failure),
              // "NotFoundError" (unresolvable DID).
              Graph::RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(MakeGarbageCollected<Graph>(
                context, info, std::move(host), read_only));
          },
          WrapPersistent(resolver), WrapPersistent(execution_context_.Get()),
          read_only, std::move(host_remote)));

  return promise;
}

ScriptPromise<IDLUndefined> GraphManager::unmount(ScriptState* script_state,
                                                  const String& graph_did) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  ConnectToBrowser();

  service_->Unmount(
      graph_did,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             const String& error) {
            if (!error.IsNull()) {
              Graph::RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<MountedGraphInfo>> GraphManager::listMounted(
    ScriptState* script_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<MountedGraphInfo>>>(script_state);
  auto promise = resolver->Promise();

  ConnectToBrowser();

  service_->ListMounted(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<MountedGraphInfo>>* resolver,
         Vector<graph::mojom::blink::MountedGraphInfoPtr> mounted) {
        HeapVector<Member<MountedGraphInfo>> out;
        out.ReserveInitialCapacity(mounted.size());
        for (const auto& info : mounted)
          out.push_back(MountedInfoFromMojo(info));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<SyncModuleInfo>> GraphManager::listModules(
    ScriptState* script_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<SyncModuleInfo>>>(script_state);
  auto promise = resolver->Promise();

  ConnectToBrowser();

  service_->ListModules(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<SyncModuleInfo>>* resolver,
         Vector<graph::mojom::blink::SyncModuleInfoPtr> modules) {
        HeapVector<Member<SyncModuleInfo>> out;
        out.ReserveInitialCapacity(modules.size());
        for (const auto& info : modules)
          out.push_back(ModuleInfoFromMojo(info));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<SyncSpaceInfo>> GraphManager::listSpaces(
    ScriptState* script_state) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<SyncSpaceInfo>>>(script_state);
  auto promise = resolver->Promise();

  ConnectToBrowser();

  service_->ListSpaces(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<SyncSpaceInfo>>* resolver,
         Vector<graph::mojom::blink::SyncSpaceInfoPtr> spaces) {
        HeapVector<Member<SyncSpaceInfo>> out;
        out.ReserveInitialCapacity(spaces.size());
        for (const auto& info : spaces)
          out.push_back(SpaceInfoFromMojo(info));
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver)));

  return promise;
}

const AtomicString& GraphManager::InterfaceName() const {
  return event_target_names::kGraphManager;
}

ExecutionContext* GraphManager::GetExecutionContext() const {
  return execution_context_.Get();
}

void GraphManager::OnSubscriptionGained(const String& graph_did,
                                        graph::mojom::blink::MountMode mode) {
  // §6.4: a gained event carries the mode granted; |reason| is null.
  DispatchEvent(*SubscriptionEvent::Create(
      event_type_names::kSubscriptiongained, graph_did, MountModeToV8(mode),
      String()));
}

void GraphManager::OnSubscriptionLost(
    const String& graph_did,
    graph::mojom::blink::MountMode previous_mode,
    const String& reason) {
  // §6.4/§8.5: |reason| carries the cause of the loss.
  DispatchEvent(*SubscriptionEvent::Create(event_type_names::kSubscriptionlost,
                                           graph_did,
                                           MountModeToV8(previous_mode), reason));
}

void GraphManager::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(service_);
  visitor->Trace(group_service_);
  visitor->Trace(manager_client_);
  EventTarget::Trace(visitor);
}

}  // namespace blink
