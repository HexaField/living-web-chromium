// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_TRIPLE_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_TRIPLE_EVENT_H_

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"

namespace blink {

class TripleEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static TripleEvent* Create(const AtomicString& type,
                              const ScriptValue& triple) {
    return MakeGarbageCollected<TripleEvent>(type, triple);
  }

  TripleEvent(const AtomicString& type, const ScriptValue& triple)
      : Event(type, Bubbles::kNo, Cancelable::kNo), triple_(triple) {}

  ScriptValue triple() const { return triple_; }

  void Trace(Visitor* visitor) const override {
    Event::Trace(visitor);
  }

 private:
  ScriptValue triple_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_TRIPLE_EVENT_H_
