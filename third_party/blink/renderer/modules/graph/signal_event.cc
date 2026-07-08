// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/signal_event.h"

#include "third_party/blink/renderer/core/event_interface_names.h"

namespace blink {

const AtomicString& SignalEvent::InterfaceName() const {
  return event_interface_names::kSignalEvent;
}

void SignalEvent::Trace(Visitor* visitor) const {
  visitor->Trace(from_);
  visitor->Trace(payload_);
  Event::Trace(visitor);
}

}  // namespace blink
