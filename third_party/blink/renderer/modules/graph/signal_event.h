// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// SignalEvent — the event fired for Graph.onsignal (Graph Synchronisation
// Protocol spec §6.3). Its `from` attribute is the sending peer session and
// `payload` the raw signalling bytes (§11). Browser-dispatched only; not
// constructible from script.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNAL_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNAL_EVENT_H_

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/core/typed_arrays/not_shared.h"
#include "third_party/blink/renderer/modules/graph/peer.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class SignalEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Internal factory used by Graph when dispatching a PersonalGraphClient event.
  static SignalEvent* Create(const AtomicString& type,
                             Peer* from,
                             DOMUint8Array* payload) {
    return MakeGarbageCollected<SignalEvent>(type, from, payload);
  }

  SignalEvent(const AtomicString& type, Peer* from, DOMUint8Array* payload)
      : Event(type, Bubbles::kNo, Cancelable::kNo),
        from_(from),
        payload_(payload) {}

  Peer* from() const { return from_.Get(); }
  NotShared<DOMUint8Array> payload() const {
    return NotShared<DOMUint8Array>(payload_.Get());
  }

  const AtomicString& InterfaceName() const override;

  void Trace(Visitor* visitor) const override;

 private:
  Member<Peer> from_;
  Member<DOMUint8Array> payload_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNAL_EVENT_H_
