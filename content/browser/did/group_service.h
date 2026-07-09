// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GroupService — the per-realm Mojo host for the navigator.graph group surface
// (Spec 03 §8.2). It wraps a GroupBackendManager (the port of living_web::
// GroupManager) over the realm's shared GraphBackendManager and identity, binds
// a GroupHost — and, for a freshly materialised host graph, a PersonalGraphHost —
// per group it mints or opens, and returns the GroupInfo the renderer needs to
// build its Group wrapper.
//
// Groups persist in the shared graph store for the realm's lifetime: a group is
// a did:graph identity that can be re-opened by did:graph or IRI (§4.7), so a
// dropped GroupHost or group PersonalGraphHost pipe destroys only the Mojo host,
// never the group's host graph (this is the one behavioural difference from
// PersonalGraphManager, whose disconnect drops the backing graph). The service
// shares the realm's GraphBackendManager with PersonalGraphManager so groups and
// personal graphs resolve against one dataset (§7.2 named-graph resolution, §4.7
// local group resolution); it must not outlive that manager or the identity.

#ifndef CONTENT_BROWSER_DID_GROUP_SERVICE_H_
#define CONTENT_BROWSER_DID_GROUP_SERVICE_H_

#include <memory>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/did/group_backend_manager.h"
#include "content/browser/did/group_host.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph/personal_graph_host.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

class GroupService : public graph::mojom::GroupManager {
 public:
  // |identity|, |graphs|, and |governance| are the realm's shared identity
  // provider, graph store, and Spec 04 governance backend (the same objects the
  // realm's PersonalGraphManager owns/uses). All three outlive this service. The
  // governance backend is threaded into every PersonalGraphHost this service
  // binds (so the §11 surface + enforcement gate share one registry) and into
  // every GroupHost (for §8.1.5 delegateCapability).
  GroupService(DIDKeyProvider* identity,
               GraphBackendManager* graphs,
               GovernanceBackend* governance);

  GroupService(const GroupService&) = delete;
  GroupService& operator=(const GroupService&) = delete;

  ~GroupService() override;

  void BindReceiver(
      mojo::PendingReceiver<graph::mojom::GroupManager> receiver);

  // graph::mojom::GroupManager:
  void CreateGroup(
      graph::mojom::GroupCreationOptionsPtr options,
      mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
      mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver,
      CreateGroupCallback callback) override;
  void Groupify(
      const std::string& graph_id,
      graph::mojom::GroupifyOptionsPtr options,
      mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
      GroupifyCallback callback) override;
  void ForkGroup(
      const std::string& parent,
      graph::mojom::ForkOptionsPtr options,
      mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
      mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver,
      ForkGroupCallback callback) override;
  void OpenGroup(
      const std::string& iri_or_did,
      mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
      mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver,
      OpenGroupCallback callback) override;
  void ListGroups(ListGroupsCallback callback) override;

 private:
  static GroupCreationOptions CreationFromMojo(
      const graph::mojom::GroupCreationOptionsPtr& o);
  static GroupifyOptions GroupifyFromMojo(
      const graph::mojom::GroupifyOptionsPtr& o);
  static ForkOptions ForkFromMojo(const graph::mojom::ForkOptionsPtr& o);
  static graph::mojom::GraphInfoPtr BuildGraphInfo(GraphBackend* backend);
  static graph::mojom::GroupInfoPtr BuildGroupInfo(GroupBackend* group);

  // Binds a GroupHost over |group| (taking ownership of the backend view) and,
  // when |graph_receiver| is valid, a PersonalGraphHost over the group's host
  // graph, wiring each pipe's disconnect to destroy only its host. Returns the
  // GroupInfo for the freshly-attached group.
  graph::mojom::GroupInfoPtr Attach(
      std::unique_ptr<GroupBackend> group,
      mojo::PendingReceiver<graph::mojom::GroupHost> group_receiver,
      mojo::PendingReceiver<graph::mojom::PersonalGraphHost> graph_receiver);

  void RetainGroupHost(std::unique_ptr<GroupHost> host);
  void RetainGraphHost(std::unique_ptr<PersonalGraphHost> host);
  void OnGroupHostDisconnected(GroupHost* host);
  void OnGraphHostDisconnected(PersonalGraphHost* host);

  raw_ptr<GraphBackendManager> graphs_;    // The realm's shared graph store.
  raw_ptr<GovernanceBackend> governance_;  // The realm's Spec 04 registry.
  GroupBackendManager groups_;
  std::vector<std::unique_ptr<GroupHost>> group_hosts_;
  std::vector<std::unique_ptr<PersonalGraphHost>> graph_hosts_;
  mojo::ReceiverSet<graph::mojom::GroupManager> receivers_;
  base::WeakPtrFactory<GroupService> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_GROUP_SERVICE_H_
