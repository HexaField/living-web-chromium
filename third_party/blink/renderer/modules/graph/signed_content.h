// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// SignedContent — the result of DIDCredential.sign()/signCapability()
// (Decentralised Identity spec §6.1). Carries the signer DID, the RFC 3339
// timestamp, the original data, and the cryptographic ContentProof.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNED_CONTENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNED_CONTENT_H_

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/modules/graph/content_proof.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class ScriptState;

class SignedContent final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  SignedContent(const String& author,
                const String& timestamp,
                const String& data_json,
                ContentProof* proof)
      : author_(author),
        timestamp_(timestamp),
        data_json_(data_json),
        proof_(proof) {}

  const String& author() const { return author_; }
  const String& timestamp() const { return timestamp_; }

  // §6.1 `any data` — the original signed value. Parsed from the canonical
  // JSON the browser round-trips through Mojo.
  ScriptValue data(ScriptState*) const;

  ContentProof* proof() const { return proof_.Get(); }

  // Internal: the JSON serialisation used to reconstruct the Mojo payload for
  // verify(). Not exposed to script.
  const String& dataJson() const { return data_json_; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(proof_);
    ScriptWrappable::Trace(visitor);
  }

 private:
  String author_;
  String timestamp_;
  String data_json_;
  Member<ContentProof> proof_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_SIGNED_CONTENT_H_
