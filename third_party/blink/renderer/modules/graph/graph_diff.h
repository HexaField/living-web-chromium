// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_DIFF_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_DIFF_H_

#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class GraphDiff final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  GraphDiff() = default;

  const String& revision() const { return revision_; }
  const String& author() const { return author_; }
  uint64_t timestamp() const { return timestamp_; }

  void Trace(Visitor* visitor) const override {
    ScriptWrappable::Trace(visitor);
  }

 private:
  String revision_;
  String author_;
  uint64_t timestamp_ = 0;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_GRAPH_DIFF_H_
