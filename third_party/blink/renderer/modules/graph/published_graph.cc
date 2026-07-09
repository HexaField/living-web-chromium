// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/published_graph.h"

#include <utility>

#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

// static
PublishedGraph* PublishedGraph::FromMojo(
    const graph::mojom::blink::PublishedGraphInfoPtr& info) {
  Vector<String> relays = info->relays;
  auto* frozen_relays =
      MakeGarbageCollected<FrozenArray<IDLUSVString>>(std::move(relays));
  return MakeGarbageCollected<PublishedGraph>(info->graph_did, info->space_uri,
                                              info->module_hash, frozen_relays);
}

}  // namespace blink
