// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// GraphTripleEvent — the event fired for Graph.ontripleadded and
// Graph.ontripleremoved (Personal Linked Data Graphs spec §4.2). Its `triple`
// attribute is the newly-written / removed data triple.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_TRIPLE_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_TRIPLE_EVENT_H_

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/modules/graph/triple.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class GraphTripleEventInit;

class GraphTripleEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Internal factory used by Graph when dispatching a PersonalGraphClient event.
  static GraphTripleEvent* Create(const AtomicString& type, Triple* triple) {
    return MakeGarbageCollected<GraphTripleEvent>(type, triple);
  }

  // Script-facing constructor: new GraphTripleEvent(type, { triple }).
  static GraphTripleEvent* Create(const AtomicString& type,
                                  const GraphTripleEventInit* initializer);

  GraphTripleEvent(const AtomicString& type, Triple* triple)
      : Event(type, Bubbles::kNo, Cancelable::kNo), triple_(triple) {}
  GraphTripleEvent(const AtomicString& type,
                   const GraphTripleEventInit* initializer);

  Triple* triple() const { return triple_.Get(); }

  const AtomicString& InterfaceName() const override;

  void Trace(Visitor* visitor) const override;

 private:
  Member<Triple> triple_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_TRIPLE_EVENT_H_
