// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// SubscriptionEvent — the event fired for GraphManager.onsubscriptiongained /
// onsubscriptionlost (Graph Synchronisation Protocol spec §6.4). `previousMode`
// is the mode gained (gained event) or held before loss (lost event); `reason`
// is null for a gained event and carries the cause for a lost event (§8.5).
// Browser-dispatched only; not constructible from script.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SUBSCRIPTION_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SUBSCRIPTION_EVENT_H_

#include "third_party/blink/renderer/bindings/modules/v8/v8_mount_mode.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class SubscriptionEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Internal factory used by GraphManager when dispatching a
  // PersonalGraphManagerClient event. |reason| is a null String for a gained
  // event.
  static SubscriptionEvent* Create(const AtomicString& type,
                                   const String& graph_did,
                                   const V8MountMode& previous_mode,
                                   const String& reason) {
    return MakeGarbageCollected<SubscriptionEvent>(type, graph_did,
                                                   previous_mode, reason);
  }

  SubscriptionEvent(const AtomicString& type,
                    const String& graph_did,
                    const V8MountMode& previous_mode,
                    const String& reason)
      : Event(type, Bubbles::kNo, Cancelable::kNo),
        graph_did_(graph_did),
        previous_mode_(previous_mode),
        reason_(reason) {}

  const String& graphDid() const { return graph_did_; }
  V8MountMode previousMode() const { return previous_mode_; }
  const String& reason() const { return reason_; }  // null when none

  const AtomicString& InterfaceName() const override;

  void Trace(Visitor* visitor) const override { Event::Trace(visitor); }

 private:
  String graph_did_;
  V8MountMode previous_mode_;
  String reason_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SUBSCRIPTION_EVENT_H_
