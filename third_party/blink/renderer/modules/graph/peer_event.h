// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_EVENT_H_

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class PeerEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static PeerEvent* Create(const AtomicString& type, const String& did) {
    return MakeGarbageCollected<PeerEvent>(type, did);
  }

  PeerEvent(const AtomicString& type, const String& did)
      : Event(type, Bubbles::kNo, Cancelable::kNo), did_(did) {}

  const String& did() const { return did_; }

  void Trace(Visitor* visitor) const override {
    Event::Trace(visitor);
  }

 private:
  String did_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_EVENT_H_
