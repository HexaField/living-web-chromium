// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/flow_transition_event.h"

#include "third_party/blink/renderer/core/event_interface_names.h"

namespace blink {

const AtomicString& FlowTransitionEvent::InterfaceName() const {
  return event_interface_names::kFlowTransitionEvent;
}

}  // namespace blink
