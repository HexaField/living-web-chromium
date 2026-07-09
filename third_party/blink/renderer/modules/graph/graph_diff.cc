// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph_diff.h"

#include <utility>

#include "third_party/blink/renderer/bindings/modules/v8/v8_union_usvstring_literalvalue.h"
#include "third_party/blink/renderer/modules/graph/capability_proof.h"
#include "third_party/blink/renderer/modules/graph/literal_value.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"

namespace blink {

namespace {

// §3.1: reconstruct the Triple.object union from its Mojo form. Self-contained
// so GraphDiff (delivered during event dispatch) needs no dependency on the
// Graph translation unit's converters.
V8UnionUSVStringOrLiteralValue* ObjectFromMojo(
    const graph::mojom::blink::TripleObjectPtr& object) {
  if (object->is_literal()) {
    const auto& literal = object->get_literal();
    auto* value = MakeGarbageCollected<LiteralValue>(
        literal->lexical, literal->datatype, literal->language);
    return MakeGarbageCollected<V8UnionUSVStringOrLiteralValue>(value);
  }
  return MakeGarbageCollected<V8UnionUSVStringOrLiteralValue>(
      object->get_iri_or_bnode());
}

Triple* TripleFromMojo(const graph::mojom::blink::TriplePtr& triple) {
  return MakeGarbageCollected<Triple>(triple->subject, triple->predicate,
                                      ObjectFromMojo(triple->object));
}

// §5.1: a diff carries reifier-annotated triples; GraphDiff surfaces only the
// bare Triple of each (the reifier metadata is reachable via Graph.provenance()).
FrozenArray<Triple>* DiffTriplesToFrozen(
    const Vector<graph::mojom::blink::DiffTriplePtr>& diff_triples) {
  HeapVector<Member<Triple>> triples;
  triples.ReserveInitialCapacity(diff_triples.size());
  for (const auto& diff_triple : diff_triples)
    triples.push_back(TripleFromMojo(diff_triple->triple));
  return MakeGarbageCollected<FrozenArray<Triple>>(std::move(triples));
}

}  // namespace

// static
GraphDiff* GraphDiff::FromMojo(const graph::mojom::blink::GraphDiffPtr& diff) {
  Vector<String> dependencies = diff->dependencies;
  auto* frozen_dependencies =
      MakeGarbageCollected<FrozenArray<IDLUSVString>>(std::move(dependencies));
  CapabilityProof* proof =
      diff->capability_proof
          ? CapabilityProof::FromMojo(diff->capability_proof)
          : nullptr;
  return MakeGarbageCollected<GraphDiff>(
      diff->graph_did, diff->revision, diff->commit_id,
      DiffTriplesToFrozen(diff->additions), DiffTriplesToFrozen(diff->removals),
      frozen_dependencies, proof, diff->author, diff->timestamp,
      diff->diffs_since_snapshot, diff->signature);
}

void GraphDiff::Trace(Visitor* visitor) const {
  visitor->Trace(additions_);
  visitor->Trace(removals_);
  visitor->Trace(dependencies_);
  visitor->Trace(capability_proof_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
