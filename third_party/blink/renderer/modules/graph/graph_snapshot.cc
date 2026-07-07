// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph_snapshot.h"

#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"

namespace blink {

namespace {

// §5.3 SnapshotFormat string forms.
constexpr char kNQuadsCanonical[] = "nquads-canonical";
constexpr char kNQuads[] = "nquads";
constexpr char kTurtle[] = "turtle";
constexpr char kJsonLd[] = "jsonld";

// §5.3 GraphSignBy string forms.
constexpr char kAgent[] = "agent";
constexpr char kGraph[] = "graph";
constexpr char kBoth[] = "both";

}  // namespace

// static
String GraphSnapshot::FormatToString(
    graph::mojom::blink::SnapshotFormat format) {
  switch (format) {
    case graph::mojom::blink::SnapshotFormat::kNQuadsCanonical:
      return kNQuadsCanonical;
    case graph::mojom::blink::SnapshotFormat::kNQuads:
      return kNQuads;
    case graph::mojom::blink::SnapshotFormat::kTurtle:
      return kTurtle;
    case graph::mojom::blink::SnapshotFormat::kJsonLd:
      return kJsonLd;
  }
  return kNQuadsCanonical;
}

// static
graph::mojom::blink::SnapshotFormat GraphSnapshot::FormatFromString(
    const String& format) {
  if (format == kNQuads)
    return graph::mojom::blink::SnapshotFormat::kNQuads;
  if (format == kTurtle)
    return graph::mojom::blink::SnapshotFormat::kTurtle;
  if (format == kJsonLd)
    return graph::mojom::blink::SnapshotFormat::kJsonLd;
  // Default (and "nquads-canonical") map to the canonical form.
  return graph::mojom::blink::SnapshotFormat::kNQuadsCanonical;
}

// static
graph::mojom::blink::GraphSignBy GraphSnapshot::SignByFromString(
    const String& sign_by) {
  if (sign_by == kGraph)
    return graph::mojom::blink::GraphSignBy::kGraph;
  if (sign_by == kBoth)
    return graph::mojom::blink::GraphSignBy::kBoth;
  return graph::mojom::blink::GraphSignBy::kAgent;
}

// static
GraphSnapshot* GraphSnapshot::FromMojo(
    const graph::mojom::blink::GraphSnapshotPtr& snapshot) {
  HeapVector<Member<SnapshotProof>> proofs;
  proofs.ReserveInitialCapacity(snapshot->proofs.size());
  for (const auto& proof : snapshot->proofs) {
    proofs.push_back(MakeGarbageCollected<SnapshotProof>(
        proof->role, proof->author, proof->method, proof->signature));
  }
  auto* frozen_proofs =
      MakeGarbageCollected<FrozenArray<SnapshotProof>>(std::move(proofs));
  return MakeGarbageCollected<GraphSnapshot>(
      snapshot->graph_iri, snapshot->graph_did,
      FormatToString(snapshot->format), snapshot->timestamp, snapshot->data,
      frozen_proofs);
}

graph::mojom::blink::GraphSnapshotPtr GraphSnapshot::ToMojo() const {
  auto out = graph::mojom::blink::GraphSnapshot::New();
  out->graph_iri = graph_iri_;
  out->graph_did = graph_did_.IsNull() ? String() : graph_did_;
  out->format = FormatFromString(format_);
  out->timestamp = timestamp_;
  out->data = data_;
  out->proofs.reserve(proofs_->size());
  for (const auto& proof : *proofs_) {
    auto mojo_proof = graph::mojom::blink::SnapshotProof::New();
    mojo_proof->role = proof->role();
    mojo_proof->author = proof->author();
    mojo_proof->method = proof->method();
    mojo_proof->signature = proof->signature();
    out->proofs.push_back(std::move(mojo_proof));
  }
  return out;
}

}  // namespace blink
