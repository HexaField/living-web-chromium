// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/diff_event.h"

#include "third_party/blink/renderer/core/event_interface_names.h"

namespace blink {

const AtomicString& DiffEvent::InterfaceName() const {
  return event_interface_names::kDiffEvent;
}

void DiffEvent::Trace(Visitor* visitor) const {
  visitor->Trace(diff_);
  Event::Trace(visitor);
}

}  // namespace blink
