// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/capability_proof.h"

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"

namespace blink {

// static
CapabilityProof* CapabilityProof::FromMojo(
    const graph::mojom::blink::CapabilityProofPtr& proof) {
  Vector<String> chain = proof->chain;
  Vector<String> caveats = proof->caveats_satisfied;
  auto* frozen_chain =
      MakeGarbageCollected<FrozenArray<IDLUSVString>>(std::move(chain));
  auto* frozen_caveats =
      MakeGarbageCollected<FrozenArray<IDLUSVString>>(std::move(caveats));
  return MakeGarbageCollected<CapabilityProof>(
      frozen_chain, frozen_caveats, proof->has_content_caveats,
      proof->presentations);
}

const FrozenArray<IDLObject>& CapabilityProof::presentations(
    ScriptState* script_state) {
  if (presentations_)
    return *presentations_;

  // The getter is invoked synchronously from JavaScript, so the realm's context
  // is already entered; parse each retained VerifiablePresentation string into
  // the object it serialises. A malformed element is skipped.
  HeapVector<ScriptValue> elements;
  elements.ReserveInitialCapacity(presentations_json_.size());
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();
  for (const String& json : presentations_json_) {
    v8::Local<v8::Value> parsed;
    if (v8::JSON::Parse(context, V8String(isolate, json)).ToLocal(&parsed))
      elements.emplace_back(isolate, parsed);
  }
  presentations_ =
      MakeGarbageCollected<FrozenArray<IDLObject>>(std::move(elements));
  return *presentations_;
}

void CapabilityProof::Trace(Visitor* visitor) const {
  visitor->Trace(chain_);
  visitor->Trace(caveats_satisfied_);
  visitor->Trace(presentations_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
