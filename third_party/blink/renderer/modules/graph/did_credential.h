// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DID_CREDENTIAL_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DID_CREDENTIAL_H_

#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "mojo/public/mojom/graph/graph.mojom-blink.h"

namespace blink {

class ExecutionContext;

class DIDCredential final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  DIDCredential(ExecutionContext*,
                const String& id,
                const String& did,
                const String& algorithm,
                const String& display_name,
                const String& created_at,
                bool is_locked,
                HeapMojoRemote<graph::mojom::blink::DIDCredentialService>&);

  // IDL attributes
  const String& id() const { return id_; }
  const String& did() const { return did_; }
  const String& algorithm() const { return algorithm_; }
  const String& displayName() const { return display_name_; }
  const String& createdAt() const { return created_at_; }
  bool isLocked() const { return is_locked_; }

  // IDL methods
  ScriptPromise<IDLAny> sign(ScriptState*, const String& data_json);
  ScriptPromise<IDLBoolean> verify(ScriptState*, ScriptValue signed_content);
  ScriptPromise<IDLAny> resolve(ScriptState*);
  ScriptPromise<IDLBoolean> lock(ScriptState*);
  ScriptPromise<IDLBoolean> unlock(ScriptState*);

  void Trace(Visitor*) const override;

 private:
  String id_;
  String did_;
  String algorithm_;
  String display_name_;
  String created_at_;
  bool is_locked_;

  // Borrows the service remote from PersonalGraphManager (which owns it).
  // The DIDCredential must not outlive the manager.
  HeapMojoRemote<graph::mojom::blink::DIDCredentialService>& service_;
  Member<ExecutionContext> execution_context_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_DID_CREDENTIAL_H_
