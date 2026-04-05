// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_MANAGER_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_MANAGER_H_

#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "mojo/public/mojom/graph/graph.mojom-blink.h"

namespace blink {

class DIDCredential;

class PersonalGraphManager final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  explicit PersonalGraphManager(ExecutionContext*);

  ScriptPromise<IDLAny> create(ScriptState*, const String& name = String());
  ScriptPromise<IDLAny> list(ScriptState*);
  ScriptPromise<IDLAny> get(ScriptState*, const String& uuid);
  ScriptPromise<IDLAny> remove(ScriptState*, const String& uuid);
  ScriptPromise<IDLAny> join(ScriptState*, const String& uri);
  ScriptPromise<IDLAny> listShared(ScriptState*);

  // DID Identity
  ScriptPromise<IDLAny> createIdentity(ScriptState*, const String& display_name = String());
  ScriptPromise<IDLAny> listIdentities(ScriptState*);
  ScriptPromise<IDLAny> activeIdentity(ScriptState*);

  // Expose DID service remote for DIDCredential objects.
  HeapMojoRemote<graph::mojom::blink::DIDCredentialService>& GetDIDService() {
    EnsureDIDServiceConnected();
    return did_service_;
  }

  void Trace(Visitor*) const override;

 private:
  void EnsureServiceConnected();
  void EnsureDIDServiceConnected();

  Member<ExecutionContext> execution_context_;
  HeapMojoRemote<graph::mojom::blink::PersonalGraphService> service_;
  HeapMojoRemote<graph::mojom::blink::DIDCredentialService> did_service_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PERSONAL_GRAPH_MANAGER_H_
