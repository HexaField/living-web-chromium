// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SEMANTIC_TRIPLE_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SEMANTIC_TRIPLE_H_

#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class SemanticTriple final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static SemanticTriple* Create(const String& source,
                                const String& target,
                                const String& predicate) {
    return MakeGarbageCollected<SemanticTriple>(source, target, predicate);
  }

  SemanticTriple(const String& source,
                 const String& target,
                 const String& predicate)
      : source_(source), target_(target), predicate_(predicate) {}

  const String& source() const { return source_; }
  const String& target() const { return target_; }
  const String& predicate() const { return predicate_; }

  void Trace(Visitor* visitor) const override {
    ScriptWrappable::Trace(visitor);
  }

 private:
  String source_;
  String target_;
  String predicate_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SEMANTIC_TRIPLE_H_
