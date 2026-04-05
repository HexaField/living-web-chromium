// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SYNC_STATE_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SYNC_STATE_EVENT_H_

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class SyncStateEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static SyncStateEvent* Create(const AtomicString& type,
                                 const String& state) {
    return MakeGarbageCollected<SyncStateEvent>(type, state);
  }

  SyncStateEvent(const AtomicString& type, const String& state)
      : Event(type, Bubbles::kNo, Cancelable::kNo), state_(state) {}

  const String& state() const { return state_; }

  void Trace(Visitor* visitor) const override {
    Event::Trace(visitor);
  }

 private:
  String state_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SYNC_STATE_EVENT_H_
