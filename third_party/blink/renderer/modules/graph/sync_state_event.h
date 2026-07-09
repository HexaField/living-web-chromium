// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// SyncStateEvent — the event fired for Graph.onsyncstatechange (Graph
// Synchronisation Protocol spec §6.3). Its `state` attribute is the graph's new
// sync state (§5.5). Browser-dispatched only; not constructible from script.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SYNC_STATE_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SYNC_STATE_EVENT_H_

#include "third_party/blink/renderer/bindings/modules/v8/v8_graph_sync_state.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class SyncStateEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Internal factory used by Graph when dispatching a PersonalGraphClient event.
  static SyncStateEvent* Create(const AtomicString& type,
                                const V8GraphSyncState& state) {
    return MakeGarbageCollected<SyncStateEvent>(type, state);
  }

  SyncStateEvent(const AtomicString& type, const V8GraphSyncState& state)
      : Event(type, Bubbles::kNo, Cancelable::kNo), state_(state) {}

  V8GraphSyncState state() const { return state_; }

  const AtomicString& InterfaceName() const override;

  void Trace(Visitor* visitor) const override { Event::Trace(visitor); }

 private:
  V8GraphSyncState state_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SYNC_STATE_EVENT_H_
