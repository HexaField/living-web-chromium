// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/personal_graph_manager.h"

#include <algorithm>
#include <utility>

#include "base/functional/bind.h"

namespace content {

PersonalGraphManager::PersonalGraphManager(DIDKeyProvider* identity)
    : backends_(identity), governance_(identity) {}

PersonalGraphManager::~PersonalGraphManager() = default;

void PersonalGraphManager::BindReceiver(
    mojo::PendingReceiver<graph::mojom::PersonalGraphManager> receiver) {
  receivers_.Add(this, std::move(receiver));
}

// static
graph::mojom::GraphTrustLevel PersonalGraphManager::TrustToMojo(
    GraphTrustLevel t) {
  switch (t) {
    case GraphTrustLevel::kLocal:
      return graph::mojom::GraphTrustLevel::kLocal;
    case GraphTrustLevel::kExternal:
      return graph::mojom::GraphTrustLevel::kExternal;
  }
  return graph::mojom::GraphTrustLevel::kLocal;
}

// static
GraphTrustLevel PersonalGraphManager::TrustFromMojo(
    graph::mojom::GraphTrustLevel t) {
  switch (t) {
    case graph::mojom::GraphTrustLevel::kLocal:
      return GraphTrustLevel::kLocal;
    case graph::mojom::GraphTrustLevel::kExternal:
      return GraphTrustLevel::kExternal;
  }
  return GraphTrustLevel::kExternal;
}

// static
graph::mojom::GraphInfoPtr PersonalGraphManager::BuildInfo(
    GraphBackend* backend) {
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

void PersonalGraphManager::Retain(std::unique_ptr<PersonalGraphHost> host,
                                  const std::string& id) {
  PersonalGraphHost* raw = host.get();
  raw->set_disconnect_handler(
      base::BindOnce(&PersonalGraphManager::OnHostDisconnected,
                     weak_factory_.GetWeakPtr(), raw, id));
  hosts_.push_back(std::move(host));
}

void PersonalGraphManager::OnHostDisconnected(PersonalGraphHost* host,
                                              const std::string& id) {
  // Erase the host first (severing its raw_ptr to the backend), then drop the
  // backend and its store.
  std::erase_if(hosts_, [host](const std::unique_ptr<PersonalGraphHost>& h) {
    return h.get() == host;
  });
  backends_.Remove(id);
}

void PersonalGraphManager::Create(
    const std::optional<std::string>& display_name,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
    CreateCallback callback) {
  GraphBackend* backend = backends_.Create(display_name);
  Retain(std::make_unique<PersonalGraphHost>(backend, &backends_, &governance_,
                                             std::move(receiver)),
         backend->id());
  std::move(callback).Run(BuildInfo(backend));
}

void PersonalGraphManager::FromSnapshot(
    graph::mojom::GraphSnapshotPtr snapshot,
    graph::mojom::GraphTrustLevel trust,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver,
    FromSnapshotCallback callback) {
  std::string error;
  GraphBackend* backend = backends_.FromSnapshot(
      PersonalGraphHost::FromMojo(snapshot), TrustFromMojo(trust), &error);
  if (!backend) {
    std::move(callback).Run(nullptr, error);
    return;
  }
  Retain(std::make_unique<PersonalGraphHost>(backend, &backends_, &governance_,
                                             std::move(receiver)),
         backend->id());
  std::move(callback).Run(BuildInfo(backend), std::nullopt);
}

}  // namespace content
