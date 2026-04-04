// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/navigator_graph.h"

#include "third_party/blink/renderer/modules/graph/personal_graph_manager.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"

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
PersonalGraphManager* NavigatorGraph::graph(Navigator& navigator) {
  return From(navigator).graph();
}

NavigatorGraph::NavigatorGraph(Navigator& navigator)
    : Supplement<Navigator>(navigator) {}

PersonalGraphManager* NavigatorGraph::graph() {
  if (!graph_manager_) {
    graph_manager_ = MakeGarbageCollected<PersonalGraphManager>(
        GetSupplementable()->GetExecutionContext());
  }
  return graph_manager_.Get();
}

void NavigatorGraph::Trace(Visitor* visitor) const {
  visitor->Trace(graph_manager_);
  Supplement<Navigator>::Trace(visitor);
}

}  // namespace blink
