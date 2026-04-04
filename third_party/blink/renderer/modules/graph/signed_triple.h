// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNED_TRIPLE_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNED_TRIPLE_H_

#include "third_party/blink/renderer/modules/graph/content_proof.h"
#include "third_party/blink/renderer/modules/graph/semantic_triple.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class SignedTriple final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  SignedTriple(SemanticTriple* data,
               const String& author,
               const String& timestamp,
               ContentProof* proof)
      : data_(data),
        author_(author),
        timestamp_(timestamp),
        proof_(proof) {}

  SemanticTriple* data() const { return data_.Get(); }
  const String& author() const { return author_; }
  const String& timestamp() const { return timestamp_; }
  ContentProof* proof() const { return proof_.Get(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(data_);
    visitor->Trace(proof_);
    ScriptWrappable::Trace(visitor);
  }

 private:
  Member<SemanticTriple> data_;
  String author_;
  String timestamp_;
  Member<ContentProof> proof_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNED_TRIPLE_H_
