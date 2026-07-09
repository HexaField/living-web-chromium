// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// SnapshotProof — a cryptographic proof over a GraphSnapshot (Personal Linked
// Data Graphs spec §5.3). Browser-returned as part of a GraphSnapshot.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SNAPSHOT_PROOF_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SNAPSHOT_PROOF_H_

#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class SnapshotProof final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  SnapshotProof(const String& role,
                const String& author,
                const String& method,
                const String& signature)
      : role_(role),
        author_(author),
        method_(method),
        signature_(signature) {}

  const String& role() const { return role_; }        // "agent" or "graph"
  const String& author() const { return author_; }
  const String& method() const { return method_; }
  const String& signature() const { return signature_; }

  void Trace(Visitor* visitor) const override {
    ScriptWrappable::Trace(visitor);
  }

 private:
  String role_;
  String author_;
  String method_;
  String signature_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SNAPSHOT_PROOF_H_
