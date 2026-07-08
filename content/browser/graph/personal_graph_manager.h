// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// PersonalGraphManager — the per-realm Mojo host for navigator.graph (Spec 02
// §3.4/§4.1/§5.5). It wraps a GraphBackendManager (the port of living_web::
// GraphManager), binds a PersonalGraphHost for each graph it creates or
// materialises, and returns the GraphInfo the renderer needs to construct its
// PersonalGraph wrapper. The backends and their hosts are owned here for the
// lifetime of the realm.

#ifndef CONTENT_BROWSER_GRAPH_PERSONAL_GRAPH_MANAGER_H_
#define CONTENT_BROWSER_GRAPH_PERSONAL_GRAPH_MANAGER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph/personal_graph_host.h"
#include "content/browser/graph_sync/sync_backend.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

class PersonalGraphManager : public graph::mojom::PersonalGraphManager {
 public:
  explicit PersonalGraphManager(DIDKeyProvider* identity);

  PersonalGraphManager(const PersonalGraphManager&) = delete;
  PersonalGraphManager& operator=(const PersonalGraphManager&) = delete;

  ~PersonalGraphManager() override;

  void BindReceiver(
      mojo::PendingReceiver<graph::mojom::PersonalGraphManager> receiver);

  // The realm's graph store, shared with the Spec 03 GroupService so groups and
  // personal graphs resolve against one dataset (§7.2 named-graph resolution,
  // §4.7 local group resolution). The borrower must not outlive this manager.
  GraphBackendManager* backends() { return &backends_; }

  // The realm's Spec 04 governance backend (the plug-in registry + §11 surface).
  // Shared with the Spec 03 GroupService so group-authored delegations and the
  // renderer §11 API run against one registry. Must not outlive this manager.
  GovernanceBackend* governance() { return &governance_; }

  // The realm's Spec 05 sync backend (diff construction/validation, space
  // derivation, read gating, the durable diff queue). Shared with every
  // PersonalGraphHost and with the Spec 03 GroupService so the §6/§9 sync surface
  // and the §9.3 sync-blocking rule run against a single chain view. Must not
  // outlive this manager.
  SyncBackend* sync() { return &sync_; }

  // graph::mojom::PersonalGraphManager:
  void Create(const std::optional<std::string>& display_name,
              mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
              CreateCallback callback) override;
  void FromSnapshot(
      graph::mojom::GraphSnapshotPtr snapshot,
      graph::mojom::GraphTrustLevel trust,
      mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
      FromSnapshotCallback callback) override;

  // ---- Spec 05 §6.2/§6.4 sync surface (folded into this manager) ----
  void Mount(const std::string& graph_did,
             graph::mojom::MountOptionsPtr options,
             mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
             MountCallback callback) override;
  void Unmount(const std::string& graph_did, UnmountCallback callback) override;
  void ListMounted(ListMountedCallback callback) override;
  void ListModules(ListModulesCallback callback) override;
  void ListSpaces(ListSpacesCallback callback) override;
  void SubscribeManager(
      mojo::PendingRemote<graph::mojom::PersonalGraphManagerClient> client)
      override;

 private:
  // One entry of the realm's mount table (§6.2), keyed by the mounted graph DID.
  // |host| and the backend named by |backend_id| are owned via |hosts_| /
  // |backends_|; the rest is the §6.4 inventory the renderer reads back.
  struct MountEntry {
    raw_ptr<PersonalGraphHost> host;
    std::string backend_id;
    graph::mojom::MountMode mode;
    std::string space_uri;
    std::string module_hash;
    graph::mojom::GraphSyncState sync_state;
  };

  static graph::mojom::GraphTrustLevel TrustToMojo(GraphTrustLevel t);
  static GraphTrustLevel TrustFromMojo(graph::mojom::GraphTrustLevel t);
  static graph::mojom::GraphInfoPtr BuildInfo(GraphBackend* backend);

  // Binds |host| (wrapping the graph with internal |id|) into |hosts_| and wires
  // its pipe-disconnect to OnHostDisconnected.
  void Retain(std::unique_ptr<PersonalGraphHost> host, const std::string& id);

  // Destroys the disconnected |host| and drops its backend + store. Safe to run
  // from within the host receiver's own disconnect handler (mojo permits a
  // receiver to be destroyed there, exactly as mojo::ReceiverSet does).
  void OnHostDisconnected(PersonalGraphHost* host, const std::string& id);

  GraphBackendManager backends_;
  GovernanceBackend governance_;
  // Declared after |governance_|: SyncBackend borrows &governance_ at
  // construction, so it must be initialised later (and destroyed earlier).
  SyncBackend sync_;
  std::vector<std::unique_ptr<PersonalGraphHost>> hosts_;
  // §6.2 mount table, keyed by mounted graph DID.
  std::map<std::string, MountEntry> mounts_;
  mojo::ReceiverSet<graph::mojom::PersonalGraphManager> receivers_;
  // §6.4: bound by SubscribeManager; the browser pushes onsubscriptiongained /
  // onsubscriptionlost through it as mounts gain and lose diff delivery.
  mojo::Remote<graph::mojom::PersonalGraphManagerClient> manager_client_;
  base::WeakPtrFactory<PersonalGraphManager> weak_factory_{this};
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_PERSONAL_GRAPH_MANAGER_H_
