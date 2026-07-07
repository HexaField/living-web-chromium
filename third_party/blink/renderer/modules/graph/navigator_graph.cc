// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/navigator_graph.h"

#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/graph_manager.h"

namespace blink {

const char NavigatorGraph::kSupplementName[] = "NavigatorGraph";

NavigatorGraph& NavigatorGraph::From(Navigator& navigator) {
  NavigatorGraph* supplement =
      Supplement<Navigator>::From<NavigatorGraph>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<NavigatorGraph>(navigator);
    ProvideTo(navigator, supplement);
  }
  return *supplement;
}

// static
GraphManager* NavigatorGraph::graph(Navigator& navigator) {
  return From(navigator).graph();
}

NavigatorGraph::NavigatorGraph(Navigator& navigator)
    : Supplement<Navigator>(navigator) {}

GraphManager* NavigatorGraph::graph() {
  // §3.4: [SameObject] — one GraphManager per realm, created on first access.
  if (!graph_manager_) {
    graph_manager_ = MakeGarbageCollected<GraphManager>(
        GetSupplementable()->GetExecutionContext());
  }
  return graph_manager_.Get();
}

void NavigatorGraph::Trace(Visitor* visitor) const {
  visitor->Trace(graph_manager_);
  Supplement<Navigator>::Trace(visitor);
}

}  // namespace blink
