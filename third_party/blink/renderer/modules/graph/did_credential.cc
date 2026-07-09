// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/did_credential.h"

#include "base/containers/span.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/graph/content_proof.h"
#include "third_party/blink/renderer/modules/graph/personal_graph_manager.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

DIDCredential::DIDCredential(ExecutionContext* context,
                            const String& id,
                            const String& did,
                            const String& method,
                            const String& algorithm,
                            const String& display_name,
                            const String& created_at,
                            bool is_locked,
                            PersonalGraphManager* manager)
    : id_(id),
      did_(did),
      method_(method),
      algorithm_(algorithm),
      display_name_(display_name),
      created_at_(created_at),
      is_locked_(is_locked),
      manager_(manager),
      execution_context_(context) {}

HeapMojoRemote<graph::mojom::blink::DIDCredentialService>&
DIDCredential::GetService() {
  return manager_->GetDIDService();
}

// static
bool DIDCredential::SerializeToJson(ScriptState* script_state,
                                    const ScriptValue& value,
                                    String& out_json) {
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();
  v8::Local<v8::Value> v8_value = value.V8Value();
  if (v8_value.IsEmpty()) {
    out_json = "null";
    return true;
  }
  v8::Local<v8::String> json;
  if (!v8::JSON::Stringify(context, v8_value).ToLocal(&json))
    return false;
  out_json = ToCoreString(isolate, json);
  return true;
}

namespace {

// Build a renderer SignedContent object from the Mojo payload.
SignedContent* MakeSignedContent(
    const graph::mojom::blink::SignedContentPtr& result) {
  auto* proof = MakeGarbageCollected<ContentProof>(
      result->proof->method, result->proof->signature, result->proof->type);
  return MakeGarbageCollected<SignedContent>(
      result->author, result->timestamp, result->data_json, proof);
}

}  // namespace

ScriptPromise<SignedContent> DIDCredential::sign(ScriptState* script_state,
                                                 const ScriptValue& data) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SignedContent>>(script_state);
  auto promise = resolver->Promise();

  // §6.1 step 2: reject with InvalidStateError if the credential is locked.
  if (is_locked_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "The credential is locked"));
    return promise;
  }
  if (!GetService().is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  String data_json;
  if (!SerializeToJson(script_state, data, data_json)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kDataError, "Data is not serialisable"));
    return promise;
  }

  GetService()->Sign(
      id_, data_json,
      BindOnce(
          [](ScriptPromiseResolver<SignedContent>* resolver,
             graph::mojom::blink::SignedContentPtr result) {
            if (!result) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kInvalidStateError, "Signing failed"));
              return;
            }
            resolver->Resolve(MakeSignedContent(result));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLBoolean> DIDCredential::verify(ScriptState* script_state,
                                                SignedContent* content) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  if (!content) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kTypeMismatchError, "Expected SignedContent"));
    return promise;
  }
  if (!GetService().is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  auto mojo_content = graph::mojom::blink::SignedContent::New();
  mojo_content->author = content->author();
  mojo_content->timestamp = content->timestamp();
  mojo_content->data_json = content->dataJson();
  auto proof = graph::mojom::blink::ContentProof::New();
  if (content->proof()) {
    proof->method = content->proof()->method();
    proof->signature = content->proof()->signature();
    proof->type = content->proof()->type();
  }
  mojo_content->proof = std::move(proof);

  GetService()->Verify(
      std::move(mojo_content),
      BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver, bool valid) {
            resolver->Resolve(valid);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<SignedContent> DIDCredential::signCapability(
    ScriptState* script_state,
    const ScriptValue& zcap) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SignedContent>>(script_state);
  auto promise = resolver->Promise();

  if (is_locked_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "The credential is locked"));
    return promise;
  }
  if (!GetService().is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  String zcap_json;
  if (!SerializeToJson(script_state, zcap, zcap_json)) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kDataError, "Capability is not serialisable"));
    return promise;
  }

  GetService()->SignCapability(
      id_, zcap_json,
      BindOnce(
          [](ScriptPromiseResolver<SignedContent>* resolver,
             graph::mojom::blink::SignedContentPtr result) {
            if (!result) {
              // §6.3 step 1: structurally invalid ZCAP-LD document.
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kSyntaxError,
                  "Invalid ZCAP-LD capability document"));
              return;
            }
            resolver->Resolve(MakeSignedContent(result));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLArrayBuffer> DIDCredential::signRaw(
    ScriptState* script_state,
    const V8BufferSource* payload) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLArrayBuffer>>(script_state);
  auto promise = resolver->Promise();

  // §6.5 step 2: reject with InvalidStateError if the credential is locked.
  if (is_locked_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "The credential is locked"));
    return promise;
  }
  if (!GetService().is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  // §6.5 step 4: the byte sequence represented by |payload|, signed verbatim.
  DOMArrayPiece piece(payload);
  Vector<uint8_t> bytes;
  bytes.AppendSpan(base::span(piece.Bytes(), piece.ByteLength()));

  GetService()->SignRaw(
      id_, std::move(bytes),
      BindOnce(
          [](ScriptPromiseResolver<IDLArrayBuffer>* resolver,
             const std::optional<Vector<uint8_t>>& signature) {
            if (!signature) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kInvalidStateError, "Raw signing failed"));
              return;
            }
            resolver->Resolve(DOMArrayBuffer::Create(
                base::span(signature->data(), signature->size())));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> DIDCredential::resolve(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!GetService().is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  GetService()->ResolveDID(
      did_,
      BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             const String& doc_json) {
            ScriptState* ss = resolver->GetScriptState();
            ScriptState::Scope scope(ss);
            v8::Isolate* isolate = ss->GetIsolate();
            if (doc_json.empty()) {
              resolver->Resolve(ScriptValue::CreateNull(isolate));
              return;
            }
            v8::Local<v8::String> json = V8String(isolate, doc_json);
            v8::Local<v8::Value> parsed;
            if (v8::JSON::Parse(ss->GetContext(), json).ToLocal(&parsed)) {
              resolver->Resolve(ScriptValue(isolate, parsed));
            } else {
              resolver->Resolve(ScriptValue(isolate, json));
            }
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> DIDCredential::lock(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!GetService().is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  GetService()->Lock(
      id_,
      BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             DIDCredential* cred, bool success) {
            if (success)
              cred->is_locked_ = true;
            resolver->Resolve();
          },
          WrapPersistent(resolver), WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLUndefined> DIDCredential::unlock(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!GetService().is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  GetService()->Unlock(
      id_,
      BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver,
             DIDCredential* cred, bool success) {
            if (success)
              cred->is_locked_ = false;
            resolver->Resolve();
          },
          WrapPersistent(resolver), WrapPersistent(this)));

  return promise;
}

void DIDCredential::Trace(Visitor* visitor) const {
  visitor->Trace(manager_);
  visitor->Trace(execution_context_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
