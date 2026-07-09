// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/graph_triple_event.h"

#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_triple_event_init.h"
#include "third_party/blink/renderer/core/event_interface_names.h"

namespace blink {

// static
GraphTripleEvent* GraphTripleEvent::Create(
    const AtomicString& type,
    const GraphTripleEventInit* initializer) {
  return MakeGarbageCollected<GraphTripleEvent>(type, initializer);
}

GraphTripleEvent::GraphTripleEvent(const AtomicString& type,
                                   const GraphTripleEventInit* initializer)
    : Event(type, initializer),
      triple_(initializer->hasTriple() ? initializer->triple() : nullptr) {}

const AtomicString& GraphTripleEvent::InterfaceName() const {
  return event_interface_names::kGraphTripleEvent;
}

void GraphTripleEvent::Trace(Visitor* visitor) const {
  visitor->Trace(triple_);
  Event::Trace(visitor);
}

}  // namespace blink
