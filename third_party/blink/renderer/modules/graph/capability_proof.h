// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// CapabilityProof — the ZCAP delegation chain authorising a diff (Graph
// Synchronisation Protocol spec §5.3). Browser-returned as GraphDiff's
// capabilityProof. The verbatim presentation JSON is retained and parsed lazily
// into a FrozenArray<object> on first access (a diff may be surfaced during
// event dispatch, where no promise-resolver script scope exists).

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_CAPABILITY_PROOF_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_CAPABILITY_PROOF_H_

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class ScriptState;

class CapabilityProof final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Build a renderer CapabilityProof from the Mojo payload (browser ->
  // renderer). |presentations_json| is the verbatim per-presentation JSON,
  // retained and parsed on first presentations() access.
  static CapabilityProof* FromMojo(
      const graph::mojom::blink::CapabilityProofPtr& proof);

  CapabilityProof(FrozenArray<IDLUSVString>* chain,
                  FrozenArray<IDLUSVString>* caveats_satisfied,
                  bool has_content_caveats,
                  Vector<String> presentations_json)
      : chain_(chain),
        caveats_satisfied_(caveats_satisfied),
        has_content_caveats_(has_content_caveats),
        presentations_json_(std::move(presentations_json)) {}

  const FrozenArray<IDLUSVString>& chain() const { return *chain_; }
  const FrozenArray<IDLUSVString>& caveatsSatisfied() const {
    return *caveats_satisfied_;
  }
  bool hasContentCaveats() const { return has_content_caveats_; }
  // Lazily parses the retained presentation JSON into a stable FrozenArray on
  // first call; the same array is returned thereafter.
  const FrozenArray<IDLObject>& presentations(ScriptState* script_state);

  void Trace(Visitor* visitor) const override;

 private:
  Member<FrozenArray<IDLUSVString>> chain_;
  Member<FrozenArray<IDLUSVString>> caveats_satisfied_;
  bool has_content_caveats_;
  Vector<String> presentations_json_;
  Member<FrozenArray<IDLObject>> presentations_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_CAPABILITY_PROOF_H_
