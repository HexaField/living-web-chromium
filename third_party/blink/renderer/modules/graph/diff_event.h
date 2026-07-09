// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// DiffEvent — the event fired for Graph.ondiff (Graph Synchronisation Protocol
// spec §6.3). Its `diff` attribute is the diff just applied to the local graph
// (§5.1). Browser-dispatched only; not constructible from script.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DIFF_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DIFF_EVENT_H_

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/modules/graph/graph_diff.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class DiffEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Internal factory used by Graph when dispatching a PersonalGraphClient event.
  static DiffEvent* Create(const AtomicString& type, GraphDiff* diff) {
    return MakeGarbageCollected<DiffEvent>(type, diff);
  }

  DiffEvent(const AtomicString& type, GraphDiff* diff)
      : Event(type, Bubbles::kNo, Cancelable::kNo), diff_(diff) {}

  GraphDiff* diff() const { return diff_.Get(); }

  const AtomicString& InterfaceName() const override;

  void Trace(Visitor* visitor) const override;

 private:
  Member<GraphDiff> diff_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DIFF_EVENT_H_
