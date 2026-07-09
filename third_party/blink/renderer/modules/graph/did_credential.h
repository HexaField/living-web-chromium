// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// DIDCredential — represents a decentralised identity credential and exposes
// the uniform signing surface (Decentralised Identity spec §6).

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DID_CREDENTIAL_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DID_CREDENTIAL_H_

#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/modules/graph/signed_content.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "mojo/public/mojom/graph/graph.mojom-blink.h"

namespace blink {

class ExecutionContext;
class PersonalGraphManager;
class ScriptState;
class V8BufferSource;

class DIDCredential final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  DIDCredential(ExecutionContext*,
                const String& id,
                const String& did,
                const String& method,
                const String& algorithm,
                const String& display_name,
                const String& created_at,
                bool is_locked,
                PersonalGraphManager* manager);

  // IDL attributes
  const String& id() const { return id_; }
  const String& did() const { return did_; }
  const String& method() const { return method_; }
  const String& algorithm() const { return algorithm_; }
  const String& displayName() const { return display_name_; }
  const String& createdAt() const { return created_at_; }
  bool isLocked() const { return is_locked_; }

  // §6.1 Signing API
  ScriptPromise<SignedContent> sign(ScriptState*, const ScriptValue& data);
  ScriptPromise<IDLBoolean> verify(ScriptState*, SignedContent* content);
  ScriptPromise<SignedContent> signCapability(ScriptState*,
                                              const ScriptValue& zcap);
  ScriptPromise<IDLArrayBuffer> signRaw(ScriptState*,
                                        const V8BufferSource* payload);

  // §7 Resolution
  ScriptPromise<IDLAny> resolve(ScriptState*);

  // §5.3.2 Lock / unlock
  ScriptPromise<IDLUndefined> lock(ScriptState*);
  ScriptPromise<IDLUndefined> unlock(ScriptState*);

  void Trace(Visitor*) const override;

 private:
  HeapMojoRemote<graph::mojom::blink::DIDCredentialService>& GetService();

  // Serialise a ScriptValue to canonical JSON text for the Mojo `data_json`
  // field. Returns false (and rejects nothing) if serialisation fails.
  static bool SerializeToJson(ScriptState*,
                              const ScriptValue& value,
                              String& out_json);

  String id_;
  String did_;
  String method_;
  String algorithm_;
  String display_name_;
  String created_at_;
  bool is_locked_;

  Member<PersonalGraphManager> manager_;
  Member<ExecutionContext> execution_context_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DID_CREDENTIAL_H_
