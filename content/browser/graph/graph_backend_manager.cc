// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/graph_backend_manager.h"

#include <cstddef>
#include <cstdint>
#include <utility>

#include "base/uuid.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/graph/oxigraph_store.h"
#include "content/browser/graph/rdf_serialization.h"
#include "crypto/sha2.h"
#include "third_party/ed25519/ed25519.h"

namespace content {

namespace {

std::string NewGraphId() {
  return "urn:graph:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
}

}  // namespace

GraphBackendManager::GraphBackendManager(DIDKeyProvider* identity)
    : identity_(identity) {}

GraphBackendManager::~GraphBackendManager() = default;

GraphBackend* GraphBackendManager::Create(
    std::optional<std::string> display_name) {
  std::string id = NewGraphId();
  auto g = std::make_unique<GraphBackend>(identity_, id, GraphTrustLevel::kLocal);
  if (display_name)
    g->set_display_name(*display_name);
  GraphBackend* raw = g.get();
  graphs_[id] = std::move(g);
  return raw;
}

GraphBackend* GraphBackendManager::FromSnapshot(const GraphSnapshot& snap,
                                                GraphTrustLevel trust,
                                                std::string* error) {
  auto fail = [&](const char* name) -> GraphBackend* {
    if (error)
      *error = name;
    return nullptr;
  };

  // Step 1: format check (§5.3.4). Any format absent from the advertised set
  // -> NotSupportedError. jsonld is defined but not advertised here; the three
  // REQUIRED formats (nquads-canonical / nquads / turtle) are accepted.
  if (!IsSnapshotFormatSupported(snap.format))
    return fail("NotSupportedError");

  // §9.7: bound snapshot.data before any parsing (DoS defence).
  constexpr size_t kMaxSnapshotBytes = 100u * 1024u * 1024u;
  if (snap.data.size() > kMaxSnapshotBytes)
    return fail("QuotaExceededError");

  // Step 2: proof check. Empty proofs, or any failing proof, -> DataError.
  if (snap.proofs.empty())
    return fail("DataError");
  std::string payload =
      crypto::SHA256HashString(snap.graph_iri + "|" + snap.timestamp);
  for (const auto& pr : snap.proofs) {
    auto pub = living_web::did_key::ParseDidKeyEd25519(pr.author);
    auto sig = living_web::did_key::MultibaseDecode(pr.signature);
    if (!pub || pub->size() != 32 || !sig || sig->size() != 64)
      return fail("DataError");
    if (ed25519_verify(sig->data(),
                       reinterpret_cast<const uint8_t*>(payload.data()),
                       payload.size(), pub->data()) != 1)
      return fail("DataError");
  }

  // Step 3: parse snapshot.data into N-Quads for loading.
  std::string nquads, err;
  switch (snap.format) {
    case SnapshotFormat::kNQuadsCanonical:
    case SnapshotFormat::kNQuads:
      nquads = snap.data;
      break;
    case SnapshotFormat::kTurtle:
      if (!living_web::OxigraphStore::Convert(
              snap.data, living_web::RdfFormat::kTurtle,
              living_web::RdfFormat::kNQuads, &nquads, &err))
        return fail("DataError");
      break;
    case SnapshotFormat::kJsonLd:
      return fail("NotSupportedError");  // unreachable (rejected at step 1)
  }

  // Step 4: hash check. Recanonicalise + hash and compare to the claimed IRI.
  std::string expected;
  if (!living_web::OxigraphStore::GraphIri(nquads, &expected, &err))
    return fail("DataError");
  if (expected != snap.graph_iri)
    return fail("DataError");

  // Step 5: allocate a fresh id + store.
  std::string id = NewGraphId();
  auto graph = std::make_unique<GraphBackend>(identity_, id, trust);

  // Step 6: insert every triple without re-signing.
  if (!graph->LoadVerifiedNquads(nquads)) {
    if (error)
      *error = graph->last_error();
    return nullptr;
  }

  // Step 7: DID attachment from the snapshot's authoritative graphDid.
  if (snap.graph_did)
    graph->set_did(*snap.graph_did);

  // Step 8: trust level (set at construction).

  // Step 9: verify invariant (defensive) — dissolve + DataError on mismatch.
  std::string iri;
  if (!graph->GetIri(&iri) || iri != snap.graph_iri) {
    graph->Dissolve();
    return fail("DataError");
  }

  // Step 10: retain and return.
  GraphBackend* raw = graph.get();
  graphs_[id] = std::move(graph);
  return raw;
}

GraphBackend* GraphBackendManager::FromSnapshot(const GraphSnapshot& snap,
                                                std::string* error) {
  return FromSnapshot(snap, GraphTrustLevel::kExternal, error);
}

GraphBackend* GraphBackendManager::CreateMounted(const std::string& graph_did) {
  std::string id = NewGraphId();
  auto g =
      std::make_unique<GraphBackend>(identity_, id, GraphTrustLevel::kExternal);
  g->set_did(graph_did);
  GraphBackend* raw = g.get();
  graphs_[id] = std::move(g);
  return raw;
}

GraphBackend* GraphBackendManager::Find(const std::string& id) {
  auto it = graphs_.find(id);
  return it == graphs_.end() ? nullptr : it->second.get();
}

bool GraphBackendManager::Remove(const std::string& id) {
  return graphs_.erase(id) > 0;
}

}  // namespace content
