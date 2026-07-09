// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// FlowTransitionEvent — the event fired for Graph.ontransitionfired (Graph Flows
// spec §6.2 step 8, §11) and Graph.ontransitiondeadline (§13.4). `flowName` is
// the flow whose transition fired, `instanceUri` the FlowInstance it fired on,
// `transitionName` the §4.3 transition, and `newState` the §6.2 state the
// instance advanced to (null for a deadline notification not yet auto-
// transitioned). Browser-dispatched only; not constructible from script.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_FLOW_TRANSITION_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_FLOW_TRANSITION_EVENT_H_

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class FlowTransitionEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Internal factory used by Graph when dispatching a flow transition. |new_state|
  // is a null WTF::String for a deadline notification (surfaced as IDL null).
  static FlowTransitionEvent* Create(const AtomicString& type,
                                     const String& flow_name,
                                     const String& instance_uri,
                                     const String& transition_name,
                                     const String& new_state) {
    return MakeGarbageCollected<FlowTransitionEvent>(
        type, flow_name, instance_uri, transition_name, new_state);
  }

  FlowTransitionEvent(const AtomicString& type,
                      const String& flow_name,
                      const String& instance_uri,
                      const String& transition_name,
                      const String& new_state)
      : Event(type, Bubbles::kNo, Cancelable::kNo),
        flow_name_(flow_name),
        instance_uri_(instance_uri),
        transition_name_(transition_name),
        new_state_(new_state) {}

  const String& flowName() const { return flow_name_; }
  const String& instanceUri() const { return instance_uri_; }
  const String& transitionName() const { return transition_name_; }
  const String& newState() const { return new_state_; }  // null when absent

  const AtomicString& InterfaceName() const override;

  void Trace(Visitor* visitor) const override { Event::Trace(visitor); }

 private:
  String flow_name_;
  String instance_uri_;
  String transition_name_;
  String new_state_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_FLOW_TRANSITION_EVENT_H_
