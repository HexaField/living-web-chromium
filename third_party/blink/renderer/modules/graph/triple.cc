// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/triple.h"

#include "third_party/blink/renderer/bindings/modules/v8/v8_union_usvstring_literalvalue.h"

namespace blink {

// static
Triple* Triple::Create(const String& subject,
                       const String& predicate,
                       V8UnionUSVStringOrLiteralValue* object) {
  return MakeGarbageCollected<Triple>(subject, predicate, object);
}

void Triple::Trace(Visitor* visitor) const {
  visitor->Trace(object_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
