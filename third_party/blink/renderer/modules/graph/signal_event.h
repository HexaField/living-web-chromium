// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNAL_EVENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNAL_EVENT_H_

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class SignalEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static SignalEvent* Create(const AtomicString& type,
                              const String& remote_did,
                              const ScriptValue& payload) {
    return MakeGarbageCollected<SignalEvent>(type, remote_did, payload);
  }

  SignalEvent(const AtomicString& type,
              const String& remote_did,
              const ScriptValue& payload)
      : Event(type, Bubbles::kNo, Cancelable::kNo),
        remote_did_(remote_did),
        payload_(payload) {}

  const String& remoteDid() const { return remote_did_; }
  ScriptValue payload() const { return payload_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(payload_);
    Event::Trace(visitor);
  }

 private:
  String remote_did_;
  ScriptValue payload_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNAL_EVENT_H_
