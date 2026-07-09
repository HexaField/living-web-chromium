// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PublishedGraph — the space + module addressing a published graph is shared by
// (Graph Synchronisation Protocol spec §6.1). Browser-returned from
// Graph.publish().

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PUBLISHED_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PUBLISHED_GRAPH_H_

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class PublishedGraph final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Build a renderer PublishedGraph from the Mojo payload (browser -> renderer).
  static PublishedGraph* FromMojo(
      const graph::mojom::blink::PublishedGraphInfoPtr& info);

  PublishedGraph(const String& graph_did,
                 const String& space_uri,
                 const String& module_hash,
                 FrozenArray<IDLUSVString>* relays)
      : graph_did_(graph_did),
        space_uri_(space_uri),
        module_hash_(module_hash),
        relays_(relays) {}

  const String& graphDid() const { return graph_did_; }
  const String& spaceUri() const { return space_uri_; }
  const String& moduleHash() const { return module_hash_; }
  const FrozenArray<IDLUSVString>& relays() const { return *relays_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(relays_);
    ScriptWrappable::Trace(visitor);
  }

 private:
  String graph_did_;
  String space_uri_;
  String module_hash_;
  Member<FrozenArray<IDLUSVString>> relays_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PUBLISHED_GRAPH_H_
