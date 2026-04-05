// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/signing_service.h"

#include "base/logging.h"

namespace content {

SigningService::SigningService(DIDKeyProvider* key_provider)
    : key_provider_(key_provider) {}

SigningService::~SigningService() = default;

void SigningService::BindReceiver(
    mojo::PendingReceiver<graph::mojom::DIDCredentialService> receiver) {
  receivers_.Add(this, std::move(receiver));
}

void SigningService::CreateCredential(const std::string& display_name,
                                      const std::string& algorithm,
                                      CreateCredentialCallback callback) {
  // Only Ed25519 supported for now.
  if (algorithm != "Ed25519" && !algorithm.empty()) {
    std::move(callback).Run(nullptr);
    return;
  }

  auto key = key_provider_->CreateKey(display_name);
  if (!key) {
    std::move(callback).Run(nullptr);
    return;
  }

  auto info = graph::mojom::DIDCredentialInfo::New();
  info->id = key->id;
  info->did = key->did;
  info->algorithm = key->algorithm;
  info->display_name = key->display_name;
  info->created_at = key->created_at;
  info->is_locked = key->is_locked;
  std::move(callback).Run(std::move(info));
}

void SigningService::ListCredentials(ListCredentialsCallback callback) {
  auto credentials = key_provider_->ListCredentials();
  std::vector<graph::mojom::DIDCredentialInfoPtr> result;
  result.reserve(credentials.size());
  for (const auto* cred : credentials) {
    auto info = graph::mojom::DIDCredentialInfo::New();
    info->id = cred->id;
    info->did = cred->did;
    info->algorithm = cred->algorithm;
    info->display_name = cred->display_name;
    info->created_at = cred->created_at;
    info->is_locked = cred->is_locked;
    result.push_back(std::move(info));
  }
  std::move(callback).Run(std::move(result));
}

void SigningService::GetActiveCredential(
    GetActiveCredentialCallback callback) {
  const auto* cred = key_provider_->GetActiveCredential();
  if (!cred) {
    std::move(callback).Run(nullptr);
    return;
  }
  auto info = graph::mojom::DIDCredentialInfo::New();
  info->id = cred->id;
  info->did = cred->did;
  info->algorithm = cred->algorithm;
  info->display_name = cred->display_name;
  info->created_at = cred->created_at;
  info->is_locked = cred->is_locked;
  std::move(callback).Run(std::move(info));
}

void SigningService::SetActiveCredential(
    const std::string& credential_id,
    SetActiveCredentialCallback callback) {
  std::move(callback).Run(key_provider_->SetActiveCredential(credential_id));
}

void SigningService::DeleteCredential(const std::string& credential_id,
                                      DeleteCredentialCallback callback) {
  std::move(callback).Run(key_provider_->DeleteCredential(credential_id));
}

void SigningService::Sign(const std::string& credential_id,
                          const std::string& data_json,
                          SignCallback callback) {
  auto result = key_provider_->Sign(credential_id, data_json);
  if (!result) {
    std::move(callback).Run(nullptr);
    return;
  }

  auto signed_content = graph::mojom::SignedContent::New();
  signed_content->author = result->author;
  signed_content->timestamp = result->timestamp;
  signed_content->data_json = result->data_json;

  auto proof = graph::mojom::ContentProof::New();
  proof->key = result->proof_key;
  proof->signature = result->proof_sig;
  signed_content->proof = std::move(proof);

  std::move(callback).Run(std::move(signed_content));
}

void SigningService::Verify(graph::mojom::SignedContentPtr content,
                            VerifyCallback callback) {
  if (!content || !content->proof) {
    std::move(callback).Run(false);
    return;
  }

  bool valid = key_provider_->Verify(
      content->author,
      content->data_json,
      content->timestamp,
      content->proof->signature);
  std::move(callback).Run(valid);
}

void SigningService::Lock(const std::string& credential_id,
                          LockCallback callback) {
  std::move(callback).Run(key_provider_->Lock(credential_id));
}

void SigningService::Unlock(const std::string& credential_id,
                            UnlockCallback callback) {
  std::move(callback).Run(key_provider_->Unlock(credential_id));
}

void SigningService::ResolveDID(const std::string& did,
                                ResolveDIDCallback callback) {
  std::string doc = key_provider_->ResolveDID(did);
  if (doc.empty()) {
    std::move(callback).Run(std::nullopt);
    return;
  }
  std::move(callback).Run(doc);
}

}  // namespace content
