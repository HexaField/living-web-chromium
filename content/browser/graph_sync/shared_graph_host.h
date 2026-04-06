// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_SHARED_GRAPH_HOST_H_
#define CONTENT_BROWSER_GRAPH_SYNC_SHARED_GRAPH_HOST_H_

#include <string>
#include <vector>

#include "content/browser/graph/graph_store.h"
#include "content/browser/graph_governance/governance_engine.h"
#include "content/browser/graph_sync/sync_service.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph_sync.mojom.h"

namespace content {

// SharedGraphHostImpl — browser-side host for a single shared graph.
// Wraps SyncSession for peer/signalling operations and GovernanceEngine
// for constraint validation. One instance per BindSharedGraph() call.
class SharedGraphHostImpl : public graph::mojom::SharedGraphHost {
 public:
  SharedGraphHostImpl(
      SyncSession* session,
      GraphStore* store,
      GovernanceEngine* governance,
      const std::string& agent_did,
      mojo::PendingReceiver<graph::mojom::SharedGraphHost> receiver);
  ~SharedGraphHostImpl() override;

  SharedGraphHostImpl(const SharedGraphHostImpl&) = delete;
  SharedGraphHostImpl& operator=(const SharedGraphHostImpl&) = delete;

  // mojom::SharedGraphHost:
  void GetPeers(GetPeersCallback callback) override;
  void GetOnlinePeers(GetOnlinePeersCallback callback) override;
  void SendSignal(const std::string& remote_did,
                  const std::string& payload_json,
                  SendSignalCallback callback) override;
  void Broadcast(const std::string& payload_json,
                 BroadcastCallback callback) override;
  void Sync(SyncCallback callback) override;
  void Commit(graph::mojom::GraphDiffPtr diff,
              CommitCallback callback) override;
  void GetCurrentRevision(GetCurrentRevisionCallback callback) override;
  void Subscribe(
      mojo::PendingRemote<graph::mojom::SharedGraphClient> client) override;
  void CanAddTriple(const std::string& predicate,
                    const std::string& scope_entity,
                    CanAddTripleCallback callback) override;
  void ConstraintsFor(const std::optional<std::string>& scope_entity,
                      ConstraintsForCallback callback) override;
  void MyCapabilities(MyCapabilitiesCallback callback) override;

 private:
  // Not owned — SyncService owns SyncSession, GraphManager owns GraphStore.
  raw_ptr<SyncSession> session_;
  raw_ptr<GraphStore> store_;
  // Owned — each shared graph host has its own governance engine instance.
  std::unique_ptr<GovernanceEngine> governance_;
  std::string agent_did_;
  mojo::Receiver<graph::mojom::SharedGraphHost> receiver_;
  mojo::Remote<graph::mojom::SharedGraphClient> client_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_SHARED_GRAPH_HOST_H_
