// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Reifier — the per-triple provenance record (Personal Linked Data Graphs spec
// §3.7). Browser-returned only (via Graph.provenance()); carries the reifying
// blank-node id, the reified Triple, and the four prov://* values.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_REIFIER_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_REIFIER_H_

#include "third_party/blink/renderer/modules/graph/triple.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class Reifier final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  Reifier(const String& id,
          Triple* triple,
          const String& author,
          const String& timestamp,
          const String& method,
          const String& signature)
      : id_(id),
        triple_(triple),
        author_(author),
        timestamp_(timestamp),
        method_(method),
        signature_(signature) {}

  const String& id() const { return id_; }
  Triple* triple() const { return triple_.Get(); }
  const String& author() const { return author_; }
  const String& timestamp() const { return timestamp_; }
  const String& method() const { return method_; }
  const String& signature() const { return signature_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(triple_);
    ScriptWrappable::Trace(visitor);
  }

 private:
  String id_;
  Member<Triple> triple_;
  String author_;
  String timestamp_;
  String method_;
  String signature_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_REIFIER_H_
