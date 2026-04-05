// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/did_credential.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

DIDCredential::DIDCredential(
    ExecutionContext* context,
    const String& id,
    const String& did,
    const String& algorithm,
    const String& display_name,
    const String& created_at,
    bool is_locked,
    HeapMojoRemote<graph::mojom::blink::DIDCredentialService>& service)
    : id_(id),
      did_(did),
      algorithm_(algorithm),
      display_name_(display_name),
      created_at_(created_at),
      is_locked_(is_locked),
      service_(service),
      execution_context_(context) {}

ScriptPromise<IDLAny> DIDCredential::sign(ScriptState* script_state,
                                           const String& data_json) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  service_->Sign(
      id_, data_json,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             graph::mojom::blink::SignedContentPtr result) {
            if (!result) {
              resolver->Reject(MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kOperationError, "Signing failed"));
              return;
            }
            ScriptState* ss = resolver->GetScriptState();
            ScriptState::Scope scope(ss);
            v8::Isolate* isolate = ss->GetIsolate();
            v8::Local<v8::Context> ctx = ss->GetContext();
            v8::Local<v8::Object> obj = v8::Object::New(isolate);
            obj->Set(ctx, V8String(isolate, "author"),
                     V8String(isolate, result->author)).Check();
            obj->Set(ctx, V8String(isolate, "timestamp"),
                     V8String(isolate, result->timestamp)).Check();
            obj->Set(ctx, V8String(isolate, "data"),
                     V8String(isolate, result->data_json)).Check();
            v8::Local<v8::Object> proof = v8::Object::New(isolate);
            proof->Set(ctx, V8String(isolate, "key"),
                       V8String(isolate, result->proof->key)).Check();
            proof->Set(ctx, V8String(isolate, "signature"),
                       V8String(isolate, result->proof->signature)).Check();
            obj->Set(ctx, V8String(isolate, "proof"), proof).Check();
            resolver->Resolve(ScriptValue(isolate, obj));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLBoolean> DIDCredential::verify(
    ScriptState* script_state,
    ScriptValue signed_content) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  // Parse the JS object into a Mojo SignedContent.
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> ctx = script_state->GetContext();
  v8::Local<v8::Value> val = signed_content.V8Value();

  if (!val->IsObject()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kTypeMismatchError, "Expected object"));
    return promise;
  }

  v8::Local<v8::Object> obj = val.As<v8::Object>();
  auto content = graph::mojom::blink::SignedContent::New();

  v8::Local<v8::Value> author_val;
  if (obj->Get(ctx, V8String(isolate, "author")).ToLocal(&author_val) &&
      author_val->IsString()) {
    content->author = ToCoreString(isolate, author_val.As<v8::String>());
  }
  v8::Local<v8::Value> ts_val;
  if (obj->Get(ctx, V8String(isolate, "timestamp")).ToLocal(&ts_val) &&
      ts_val->IsString()) {
    content->timestamp = ToCoreString(isolate, ts_val.As<v8::String>());
  }
  v8::Local<v8::Value> data_val;
  if (obj->Get(ctx, V8String(isolate, "data")).ToLocal(&data_val) &&
      data_val->IsString()) {
    content->data_json = ToCoreString(isolate, data_val.As<v8::String>());
  }

  auto proof = graph::mojom::blink::ContentProof::New();
  v8::Local<v8::Value> proof_val;
  if (obj->Get(ctx, V8String(isolate, "proof")).ToLocal(&proof_val) &&
      proof_val->IsObject()) {
    v8::Local<v8::Object> proof_obj = proof_val.As<v8::Object>();
    v8::Local<v8::Value> key_val;
    if (proof_obj->Get(ctx, V8String(isolate, "key")).ToLocal(&key_val) &&
        key_val->IsString()) {
      proof->key = ToCoreString(isolate, key_val.As<v8::String>());
    }
    v8::Local<v8::Value> sig_val;
    if (proof_obj->Get(ctx, V8String(isolate, "signature")).ToLocal(&sig_val) &&
        sig_val->IsString()) {
      proof->signature = ToCoreString(isolate, sig_val.As<v8::String>());
    }
  }
  content->proof = std::move(proof);

  service_->Verify(
      std::move(content),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver, bool valid) {
            resolver->Resolve(valid);
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLAny> DIDCredential::resolve(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  service_->ResolveDID(
      did_,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLAny>* resolver,
             const std::optional<WTF::String>& doc_json) {
            if (!doc_json) {
              resolver->Resolve(ScriptValue::CreateNull(
                  resolver->GetScriptState()->GetIsolate()));
              return;
            }
            ScriptState* ss = resolver->GetScriptState();
            ScriptState::Scope scope(ss);
            v8::Isolate* isolate = ss->GetIsolate();
            v8::Local<v8::String> json_str =
                V8String(isolate, *doc_json);
            v8::Local<v8::Value> parsed;
            if (v8::JSON::Parse(ss->GetContext(), json_str)
                    .ToLocal(&parsed)) {
              resolver->Resolve(ScriptValue(isolate, parsed));
            } else {
              resolver->Resolve(ScriptValue(isolate, json_str));
            }
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLBoolean> DIDCredential::lock(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  service_->Lock(
      id_,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver,
             DIDCredential* cred, bool success) {
            if (success) cred->is_locked_ = true;
            resolver->Resolve(success);
          },
          WrapPersistent(resolver),
          WrapPersistent(this)));

  return promise;
}

ScriptPromise<IDLBoolean> DIDCredential::unlock(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  if (!service_.is_bound()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "DID service not connected"));
    return promise;
  }

  service_->Unlock(
      id_,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver,
             DIDCredential* cred, bool success) {
            if (success) cred->is_locked_ = false;
            resolver->Resolve(success);
          },
          WrapPersistent(resolver),
          WrapPersistent(this)));

  return promise;
}

void DIDCredential::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
