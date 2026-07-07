// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// NavigatorGraph — supplements Navigator with the [SameObject] `graph`
// attribute (Personal Linked Data Graphs spec §3.4). Lazily constructs the
// per-realm GraphManager.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_NAVIGATOR_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_NAVIGATOR_GRAPH_H_

#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/supplementable.h"

namespace blink {

class GraphManager;

class NavigatorGraph final : public GarbageCollected<NavigatorGraph>,
                             public Supplement<Navigator> {
 public:
  static const char kSupplementName[];

  static NavigatorGraph& From(Navigator&);

  // §3.4 navigator.graph.
  static GraphManager* graph(Navigator&);

  explicit NavigatorGraph(Navigator&);

  GraphManager* graph();

  void Trace(Visitor*) const override;

 private:
  Member<GraphManager> graph_manager_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_NAVIGATOR_GRAPH_H_
