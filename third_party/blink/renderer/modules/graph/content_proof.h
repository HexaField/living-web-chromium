// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_CONTENT_PROOF_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_CONTENT_PROOF_H_

#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class ContentProof final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  ContentProof(const String& key, const String& signature)
      : key_(key), signature_(signature) {}

  const String& key() const { return key_; }
  const String& signature() const { return signature_; }

  void Trace(Visitor* visitor) const override {
    ScriptWrappable::Trace(visitor);
  }

 private:
  String key_;
  String signature_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_CONTENT_PROOF_H_
