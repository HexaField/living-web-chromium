// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/graph_manager.h"

#include "base/environment.h"
#include "base/files/file_path.h"
#include "base/no_destructor.h"
#include "base/uuid.h"
#include "base/logging.h"

namespace content {

namespace {

base::FilePath GetDefaultPersistenceDir() {
  auto env = base::Environment::Create();
  auto home = env->GetVar("HOME");
  if (home.has_value()) {
    return base::FilePath(*home).AppendASCII(".living-web").AppendASCII("graphs");
  }
  return base::FilePath();
}

}  // namespace

GraphManager::GraphManager()
    : signing_service_(std::make_unique<SigningService>(&did_key_provider_)) {}
GraphManager::~GraphManager() = default;

// static
GraphManager& GraphManager::GetInstance() {
  static base::NoDestructor<GraphManager> instance;
  return *instance;
}

void GraphManager::BindReceiver(
    mojo::PendingReceiver<graph::mojom::PersonalGraphService> receiver) {
  receivers_.Add(this, std::move(receiver));
}

void GraphManager::BindDIDReceiver(
    mojo::PendingReceiver<graph::mojom::DIDCredentialService> receiver) {
  signing_service_->BindReceiver(std::move(receiver));
}

graph::mojom::GraphInfoPtr GraphManager::MakeGraphInfo(
    const GraphStore& store) {
  auto info = graph::mojom::GraphInfo::New();
  info->uuid = store.uuid();
  info->name = store.name();
  info->state = graph::mojom::GraphSyncState::kPrivate;
  return info;
}

void GraphManager::CreateGraph(const std::optional<std::string>& name,
                                CreateGraphCallback callback) {
  std::string uuid = base::Uuid::GenerateRandomV4().AsLowercaseString();
  std::string graph_name = name.value_or("");

  auto store = std::make_unique<GraphStore>(uuid, graph_name,
                                             GetDefaultPersistenceDir());
  auto info = MakeGraphInfo(*store);

  stores_[uuid] = std::move(store);
  LOG(INFO) << "Created graph: " << uuid << " (" << graph_name << ")";

  std::move(callback).Run(std::move(info));
}

void GraphManager::ListGraphs(ListGraphsCallback callback) {
  std::vector<graph::mojom::GraphInfoPtr> infos;
  for (const auto& [uuid, store] : stores_) {
    infos.push_back(MakeGraphInfo(*store));
  }
  std::move(callback).Run(std::move(infos));
}

void GraphManager::GetGraph(const std::string& uuid,
                             GetGraphCallback callback) {
  auto it = stores_.find(uuid);
  if (it == stores_.end()) {
    std::move(callback).Run(nullptr);
    return;
  }
  std::move(callback).Run(MakeGraphInfo(*it->second));
}

void GraphManager::RemoveGraph(const std::string& uuid,
                                RemoveGraphCallback callback) {
  auto it = stores_.find(uuid);
  if (it == stores_.end()) {
    std::move(callback).Run(false);
    return;
  }
  stores_.erase(it);
  LOG(INFO) << "Removed graph: " << uuid;
  std::move(callback).Run(true);
}

void GraphManager::BindGraph(
    const std::string& uuid,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver) {
  auto it = stores_.find(uuid);
  if (it == stores_.end()) {
    LOG(WARNING) << "BindGraph: graph not found: " << uuid;
    return;
  }
  auto host = std::make_unique<GraphHost>(it->second.get(),
                                           std::move(receiver));
  hosts_.push_back(std::move(host));
  LOG(INFO) << "BindGraph: bound host for " << uuid;
}

GraphStore* GraphManager::GetStore(const std::string& uuid) {
  auto it = stores_.find(uuid);
  return it != stores_.end() ? it->second.get() : nullptr;
}

}  // namespace content
