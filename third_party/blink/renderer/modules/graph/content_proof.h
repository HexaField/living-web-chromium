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
  ContentProof(const String& method, const String& signature, const String& type)
      : method_(method), signature_(signature), type_(type) {}

  const String& method() const { return method_; }
  const String& signature() const { return signature_; }
  const String& type() const { return type_; }

  void Trace(Visitor* visitor) const override {
    ScriptWrappable::Trace(visitor);
  }

 private:
  String method_;
  String signature_;
  String type_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_CONTENT_PROOF_H_
