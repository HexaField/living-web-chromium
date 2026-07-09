// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// GraphSnapshot — a transportable, self-verifying rendering of a graph's full
// triple set with one or more cryptographic proofs (Personal Linked Data Graphs
// spec §5.3). Produced by Graph.getAsSnapshot() and consumed by
// GraphManager.fromSnapshot(). This translation unit also provides the
// SnapshotFormat / GraphSignBy enum <-> Mojo converters shared across the
// module.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_SNAPSHOT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_SNAPSHOT_H_

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/modules/graph/snapshot_proof.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class GraphSnapshot final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Build a renderer GraphSnapshot from the Mojo payload (browser -> renderer).
  static GraphSnapshot* FromMojo(
      const graph::mojom::blink::GraphSnapshotPtr& snapshot);

  GraphSnapshot(const String& graph_iri,
                const String& graph_did,
                const String& format,
                const String& timestamp,
                const String& data,
                FrozenArray<SnapshotProof>* proofs)
      : graph_iri_(graph_iri),
        graph_did_(graph_did),
        format_(format),
        timestamp_(timestamp),
        data_(data),
        proofs_(proofs) {}

  const String& graphIri() const { return graph_iri_; }
  const String& graphDid() const { return graph_did_; }  // null when none
  const String& format() const { return format_; }
  const String& timestamp() const { return timestamp_; }
  const String& data() const { return data_; }
  const FrozenArray<SnapshotProof>& proofs() const { return *proofs_; }

  // Reconstruct the Mojo payload for GraphManager.fromSnapshot().
  graph::mojom::blink::GraphSnapshotPtr ToMojo() const;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(proofs_);
    ScriptWrappable::Trace(visitor);
  }

  // §5.3 enum <-> Mojo converters, shared with Graph::getAsSnapshot().
  static String FormatToString(graph::mojom::blink::SnapshotFormat format);
  static graph::mojom::blink::SnapshotFormat FormatFromString(
      const String& format);
  static graph::mojom::blink::GraphSignBy SignByFromString(
      const String& sign_by);

 private:
  String graph_iri_;
  String graph_did_;
  String format_;
  String timestamp_;
  String data_;
  Member<FrozenArray<SnapshotProof>> proofs_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_SNAPSHOT_H_
