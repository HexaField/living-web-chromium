// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// GraphDiff — the unit of gossip: a signed set of triple additions and removals
// carried between peers (Graph Synchronisation Protocol spec §5.1). Browser-
// returned as an element of Graph.pendingDiffs() and as the payload of the diff
// event. The reifier metadata each committed triple carries (author, signature,
// ...) is reachable through Graph.provenance(); GraphDiff surfaces the bare
// Triples plus the diff-level identity and authorisation.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_DIFF_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_DIFF_H_

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/modules/graph/triple.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class CapabilityProof;

class GraphDiff final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Build a renderer GraphDiff from the Mojo payload (browser -> renderer).
  static GraphDiff* FromMojo(const graph::mojom::blink::GraphDiffPtr& diff);

  GraphDiff(const String& graph_did,
            const String& revision,
            const String& commit_id,
            FrozenArray<Triple>* additions,
            FrozenArray<Triple>* removals,
            FrozenArray<IDLUSVString>* dependencies,
            CapabilityProof* capability_proof,
            const String& author,
            const String& timestamp,
            uint32_t diffs_since_snapshot,
            const String& signature)
      : graph_did_(graph_did),
        revision_(revision),
        commit_id_(commit_id),
        additions_(additions),
        removals_(removals),
        dependencies_(dependencies),
        capability_proof_(capability_proof),
        author_(author),
        timestamp_(timestamp),
        diffs_since_snapshot_(diffs_since_snapshot),
        signature_(signature) {}

  const String& graphDid() const { return graph_did_; }
  const String& revision() const { return revision_; }
  const String& commitId() const { return commit_id_; }
  const FrozenArray<Triple>& additions() const { return *additions_; }
  const FrozenArray<Triple>& removals() const { return *removals_; }
  const FrozenArray<IDLUSVString>& dependencies() const {
    return *dependencies_;
  }
  CapabilityProof* capabilityProof() const {  // null when the diff carries none
    return capability_proof_.Get();
  }
  const String& author() const { return author_; }
  const String& timestamp() const { return timestamp_; }
  uint32_t diffsSinceSnapshot() const { return diffs_since_snapshot_; }
  const String& signature() const { return signature_; }

  void Trace(Visitor* visitor) const override;

 private:
  String graph_did_;
  String revision_;
  String commit_id_;
  Member<FrozenArray<Triple>> additions_;
  Member<FrozenArray<Triple>> removals_;
  Member<FrozenArray<IDLUSVString>> dependencies_;
  Member<CapabilityProof> capability_proof_;
  String author_;
  String timestamp_;
  uint32_t diffs_since_snapshot_;
  String signature_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_DIFF_H_
