// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/group_service.h"

#include <algorithm>
#include <utility>

#include "base/functional/bind.h"

namespace content {

namespace {

graph::mojom::GraphTrustLevel TrustToMojo(GraphTrustLevel t) {
  switch (t) {
    case GraphTrustLevel::kLocal:
      return graph::mojom::GraphTrustLevel::kLocal;
    case GraphTrustLevel::kExternal:
      return graph::mojom::GraphTrustLevel::kExternal;
  }
  return graph::mojom::GraphTrustLevel::kLocal;
}

}  // namespace

GroupService::GroupService(DIDKeyProvider* identity,
                           GraphBackendManager* graphs,
                           GovernanceBackend* governance,
                           SyncBackend* sync,
                           ShapeService* shapes,
                           FlowService* flows)
    : graphs_(graphs),
      governance_(governance),
      sync_(sync),
      shapes_(shapes),
      flows_(flows),
      groups_(identity, graphs) {}

GroupService::~GroupService() = default;

void GroupService::BindReceiver(
    mojo::PendingReceiver<graph::mojom::GroupManager> receiver) {
  receivers_.Add(this, std::move(receiver));
}

// ---- option / info converters ---------------------------------------------

// static
GroupCreationOptions GroupService::CreationFromMojo(
    const graph::mojom::GroupCreationOptionsPtr& o) {
  GroupCreationOptions opts;
  opts.sync_module = o->sync_module;
  opts.display_name = o->display_name;
  opts.description = o->description;
  opts.initial_delegates = o->initial_delegates;
  opts.participates_in = o->participates_in;
  return opts;
}

// static
GroupifyOptions GroupService::GroupifyFromMojo(
    const graph::mojom::GroupifyOptionsPtr& o) {
  GroupifyOptions opts;
  opts.sync_module = o->sync_module;
  opts.display_name = o->display_name;
  opts.description = o->description;
  opts.initial_delegates = o->initial_delegates;
  return opts;
}

// static
ForkOptions GroupService::ForkFromMojo(
    const graph::mojom::ForkOptionsPtr& o) {
  ForkOptions opts;
  opts.sync_module = o->sync_module;
  opts.fork_revision = o->fork_revision;
  opts.announce_fork = o->announce_fork;
  opts.initial_delegates = o->initial_delegates;
  opts.display_name = o->display_name;
  opts.description = o->description;
  return opts;
}

// static
graph::mojom::GraphInfoPtr GroupService::BuildGraphInfo(GraphBackend* backend) {
  auto info = graph::mojom::GraphInfo::New();
  info->id = backend->id();
  std::string iri;
  if (backend->GetIri(&iri))
    info->iri = iri;
  info->did = backend->did();
  info->display_name = backend->display_name();
  info->trust_level = TrustToMojo(backend->trust_level());
  return info;
}

// static
graph::mojom::GroupInfoPtr GroupService::BuildGroupInfo(GroupBackend* group) {
  auto info = graph::mojom::GroupInfo::New();
  info->did = group->did();
  info->graph = BuildGraphInfo(group->graph());
  info->name = group->name();
  info->description = group->description();
  info->created = group->created();
  info->creator = group->creator();
  return info;
}

// ---- host lifetime ---------------------------------------------------------

graph::mojom::GroupInfoPtr GroupService::Attach(
    std::unique_ptr<GroupBackend> group,
    mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver) {
  GraphBackend* host = group->graph();
  graph::mojom::GroupInfoPtr info = BuildGroupInfo(group.get());
  if (graph_receiver.is_valid()) {
    RetainGraphHost(std::make_unique<PersonalGraphHost>(
        host, graphs_, governance_, sync_, shapes_, flows_,
        std::move(graph_receiver)));
  }
  RetainGroupHost(std::make_unique<GroupHost>(
      std::move(group), governance_, std::move(group_receiver)));
  return info;
}

void GroupService::RetainGroupHost(std::unique_ptr<GroupHost> host) {
  GroupHost* raw = host.get();
  raw->set_disconnect_handler(
      base::BindOnce(&GroupService::OnGroupHostDisconnected,
                     weak_factory_.GetWeakPtr(), raw));
  group_hosts_.push_back(std::move(host));
}

void GroupService::RetainGraphHost(std::unique_ptr<PersonalGraphHost> host) {
  PersonalGraphHost* raw = host.get();
  raw->set_disconnect_handler(
      base::BindOnce(&GroupService::OnGraphHostDisconnected,
                     weak_factory_.GetWeakPtr(), raw));
  graph_hosts_.push_back(std::move(host));
}

void GroupService::OnGroupHostDisconnected(GroupHost* host) {
  // Destroy only the Mojo host; the group's host graph stays mounted so the
  // group can be re-opened by did:graph or IRI (§4.7).
  std::erase_if(group_hosts_,
                [host](const std::unique_ptr<GroupHost>& h) {
                  return h.get() == host;
                });
}

void GroupService::OnGraphHostDisconnected(PersonalGraphHost* host) {
  // Destroy only the Mojo host; unlike PersonalGraphManager the backing group
  // graph is NOT removed — the group identity persists for the realm's life.
  std::erase_if(graph_hosts_,
                [host](const std::unique_ptr<PersonalGraphHost>& h) {
                  return h.get() == host;
                });
}

// ---- mojom::GroupManager ---------------------------------------------------

void GroupService::CreateGroup(
    graph::mojom::GroupCreationOptionsPtr options,
    mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver,
    CreateGroupCallback callback) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(CreationFromMojo(options));
  if (!group) {
    std::move(callback).Run(nullptr, groups_.last_error());
    return;
  }
  std::move(callback).Run(
      Attach(std::move(group), std::move(group_receiver),
             std::move(graph_receiver)),
      std::nullopt);
}

void GroupService::Groupify(
    const std::string& graph_id,
    graph::mojom::GroupifyOptionsPtr options,
    mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
    GroupifyCallback callback) {
  GraphBackend* existing = graphs_->Find(graph_id);
  if (!existing) {
    // §4.2: an unknown id cannot be groupified.
    std::move(callback).Run(nullptr, "InvalidStateError");
    return;
  }
  std::unique_ptr<GroupBackend> group =
      groups_.Groupify(existing, GroupifyFromMojo(options));
  if (!group) {
    std::move(callback).Run(nullptr, groups_.last_error());
    return;
  }
  // groupify reuses the caller's existing graph — the caller already holds its
  // PersonalGraphHost, so only a GroupHost is bound here.
  std::move(callback).Run(
      Attach(std::move(group), std::move(group_receiver),
             mojo::PendingReceiver<graph::mojom::PersonalGraphHost>()),
      std::nullopt);
}

void GroupService::ForkGroup(
    const std::string& parent,
    graph::mojom::ForkOptionsPtr options,
    mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver,
    ForkGroupCallback callback) {
  std::unique_ptr<GroupBackend> group =
      groups_.ForkGroup(parent, ForkFromMojo(options));
  if (!group) {
    std::move(callback).Run(nullptr, groups_.last_error());
    return;
  }
  std::move(callback).Run(
      Attach(std::move(group), std::move(group_receiver),
             std::move(graph_receiver)),
      std::nullopt);
}

void GroupService::OpenGroup(
    const std::string& iri_or_did,
    mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver,
    OpenGroupCallback callback) {
  std::unique_ptr<GroupBackend> group = groups_.OpenGroup(iri_or_did);
  if (!group) {
    std::move(callback).Run(nullptr, groups_.last_error());
    return;
  }
  std::move(callback).Run(
      Attach(std::move(group), std::move(group_receiver),
             std::move(graph_receiver)),
      std::nullopt);
}

void GroupService::ListGroups(ListGroupsCallback callback) {
  std::vector<std::string> dids;
  for (const auto& g : groups_.ListGroups())
    dids.push_back(g->did());
  std::move(callback).Run(std::move(dids));
}

}  // namespace content
