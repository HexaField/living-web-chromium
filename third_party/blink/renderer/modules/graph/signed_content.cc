// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/signed_content.h"

#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"

namespace blink {

ScriptValue SignedContent::data(ScriptState* script_state) const {
  v8::Isolate* isolate = script_state->GetIsolate();
  if (data_json_.empty())
    return ScriptValue::CreateNull(isolate);

  v8::Local<v8::String> json = V8String(isolate, data_json_);
  v8::Local<v8::Value> parsed;
  if (v8::JSON::Parse(script_state->GetContext(), json).ToLocal(&parsed))
    return ScriptValue(isolate, parsed);
  // Fall back to the raw string if the payload is not valid JSON.
  return ScriptValue(isolate, json);
}

}  // namespace blink
