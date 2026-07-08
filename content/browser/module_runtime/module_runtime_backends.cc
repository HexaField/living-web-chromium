// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/module_runtime/module_runtime_backends.h"

#include <utility>

#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/graph_sync/graph_diff.h"
#include "content/browser/graph_sync/sync_backend.h"
#include "third_party/ed25519/ed25519.h"

namespace content {

// ---- host-graph ------------------------------------------------------------

ModuleGraphAdapter::ModuleGraphAdapter() = default;
ModuleGraphAdapter::~ModuleGraphAdapter() = default;

void ModuleGraphAdapter::Bind(const std::string& graph_did,
                              GraphBackend* backend) {
  by_did_[graph_did] = backend;
}

void ModuleGraphAdapter::Unbind(const std::string& graph_did) {
  by_did_.erase(graph_did);
}

GraphBackend* ModuleGraphAdapter::Resolve(const std::string& graph_did,
                                          std::string* err) {
  auto it = by_did_.find(graph_did);
  if (it == by_did_.end() || !it->second) {
    *err = "unknown graph";
    return nullptr;
  }
  return it->second;
}

bool ModuleGraphAdapter::QueryTriples(const std::string& graph_did,
                                      const TripleQuery& query,
                                      std::vector<living_web::Triple>* out,
                                      std::string* err) {
  GraphBackend* g = Resolve(graph_did, err);
  if (!g)
    return false;
  if (!g->QueryTriples(query, out)) {
    *err = g->last_error();
    return false;
  }
  return true;
}

bool ModuleGraphAdapter::QuerySparql(const std::string& graph_did,
                                     const std::string& sparql,
                                     std::string* out,
                                     std::string* err) {
  GraphBackend* g = Resolve(graph_did, err);
  if (!g)
    return false;
  living_web::SparqlResult r = g->QuerySparql(sparql, {});
  if (!r.ok) {
    *err = r.error;
    return false;
  }
  *out = r.payload;
  return true;
}

bool ModuleGraphAdapter::Snapshot(const std::string& graph_did,
                                  std::vector<living_web::Triple>* out,
                                  std::string* err) {
  GraphBackend* g = Resolve(graph_did, err);
  if (!g)
    return false;
  if (!g->Snapshot(out)) {
    *err = g->last_error();
    return false;
  }
  return true;
}

bool ModuleGraphAdapter::Apply(const std::string& graph_did,
                               const GraphDiff& diff,
                               std::string* err) {
  GraphBackend* g = Resolve(graph_did, err);
  if (!g)
    return false;
  std::vector<living_web::Triple> adds;
  adds.reserve(diff.additions.size());
  for (const DiffTriple& dt : diff.additions)
    adds.push_back(dt.triple);
  if (!adds.empty() && !g->AddTriples(adds)) {
    *err = g->last_error();
    return false;
  }
  for (const DiffTriple& dt : diff.removals) {
    bool removed = false;
    if (!g->RemoveTriple(dt.triple, &removed)) {
      *err = g->last_error();
      return false;
    }
  }
  return true;
}

// ---- host-crypto -----------------------------------------------------------

ModuleCryptoAdapter::ModuleCryptoAdapter(DIDKeyProvider* identity)
    : identity_(identity) {}

ModuleCryptoAdapter::~ModuleCryptoAdapter() = default;

bool ModuleCryptoAdapter::SignCommit(const std::string& /*graph_did*/,
                                     const std::string& commit_id,
                                     HostSigned* out,
                                     std::string* err) {
  // §5.4: sign on behalf of the local agent — the realm's active credential.
  const DIDKeyPair* signer = identity_->GetActiveCredential();
  if (!signer) {
    *err = "no active credential";
    return false;
  }
  const std::string msg = living_web::BuildSignatureMessage(commit_id);
  auto sig =
      identity_->SignRaw(signer->id, std::vector<uint8_t>(msg.begin(), msg.end()));
  if (!sig) {
    *err = "sign failed";
    return false;
  }
  out->signature = std::move(*sig);
  out->verification_method = signer->method_id;
  return true;
}

bool ModuleCryptoAdapter::SignSignal(const std::string& space_uri,
                                     const std::string& local_did,
                                     const std::string& remote_did,
                                     const std::vector<uint8_t>& payload,
                                     HostSigned* out,
                                     std::string* err) {
  const DIDKeyPair* signer = identity_->GetActiveCredential();
  if (!signer) {
    *err = "no active credential";
    return false;
  }
  // §9.7 signal envelope pre-image: space '\x1f' local '\x1f' remote '\x1f' payload.
  std::string pre = space_uri;
  pre.push_back('\x1f');
  pre += local_did;
  pre.push_back('\x1f');
  pre += remote_did;
  pre.push_back('\x1f');
  pre.append(payload.begin(), payload.end());
  auto sig =
      identity_->SignRaw(signer->id, std::vector<uint8_t>(pre.begin(), pre.end()));
  if (!sig) {
    *err = "sign failed";
    return false;
  }
  out->signature = std::move(*sig);
  out->verification_method = signer->method_id;
  return true;
}

bool ModuleCryptoAdapter::Verify(const std::vector<uint8_t>& message,
                                 const HostSigned& signature,
                                 const std::string& public_key,
                                 bool* valid) {
  auto pub = living_web::did_key::ParseDidKeyEd25519(public_key);
  if (!pub || pub->size() != 32 || signature.signature.size() != 64) {
    *valid = false;
    return true;
  }
  *valid = ed25519_verify(signature.signature.data(), message.data(),
                          message.size(), pub->data()) == 1;
  return true;
}

}  // namespace content
