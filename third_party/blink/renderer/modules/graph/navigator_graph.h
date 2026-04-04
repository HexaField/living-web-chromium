// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_NAVIGATOR_GRAPH_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_NAVIGATOR_GRAPH_H_

#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/supplementable.h"

namespace blink {

class PersonalGraphManager;

class NavigatorGraph final : public GarbageCollected<NavigatorGraph>,
                             public Supplement<Navigator> {
 public:
  static const char kSupplementName[];

  static NavigatorGraph& From(Navigator&);
  static PersonalGraphManager* graph(Navigator&);

  explicit NavigatorGraph(Navigator&);
  ~NavigatorGraph() override;

  PersonalGraphManager* graph();

  void Trace(Visitor*) const override;

 private:
  Member<PersonalGraphManager> graph_manager_;
  mojo::Remote<graph::mojom::blink::PersonalGraphService> service_remote_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_NAVIGATOR_GRAPH_H_
