// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PeerEvent — the event fired for Graph.onpeerjoined and Graph.onpeerleft (Graph
// Synchronisation Protocol spec §6.3). Its `peer` attribute is the joining /
// departing peer session. Browser-dispatched only; not constructible from
// script.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_EVENT_H_

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/modules/graph/peer.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

class PeerEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Internal factory used by Graph when dispatching a PersonalGraphClient event.
  static PeerEvent* Create(const AtomicString& type, Peer* peer) {
    return MakeGarbageCollected<PeerEvent>(type, peer);
  }

  PeerEvent(const AtomicString& type, Peer* peer)
      : Event(type, Bubbles::kNo, Cancelable::kNo), peer_(peer) {}

  Peer* peer() const { return peer_.Get(); }

  const AtomicString& InterfaceName() const override;

  void Trace(Visitor* visitor) const override;

 private:
  Member<Peer> peer_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_EVENT_H_
