// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/navigator_graph.h"

#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/graph/personal_graph.h"
#include "third_party/blink/renderer/platform/browser_interface_broker_proxy.h"

namespace blink {

const char NavigatorGraph::kSupplementName[] = "NavigatorGraph";

// static
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

NavigatorGraph::~NavigatorGraph() = default;

PersonalGraphManager* NavigatorGraph::graph() {
  if (!graph_manager_) {
    auto* execution_context = GetSupplementable()->GetExecutionContext();
    if (!execution_context)
      return nullptr;

    // Connect to the browser-process PersonalGraphService via Mojo.
    execution_context->GetBrowserInterfaceBroker().GetInterface(
        service_remote_.BindNewPipeAndPassReceiver());

    graph_manager_ = MakeGarbageCollected<PersonalGraphManager>(
        execution_context, std::move(service_remote_));
  }
  return graph_manager_.Get();
}

void NavigatorGraph::Trace(Visitor* visitor) const {
  visitor->Trace(graph_manager_);
  Supplement<Navigator>::Trace(visitor);
}

}  // namespace blink
