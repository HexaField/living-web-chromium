// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_DID_SIGNING_SERVICE_H_
#define CONTENT_BROWSER_DID_SIGNING_SERVICE_H_

#include <string>
#include <optional>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_key_provider.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

// SigningService — Mojo host for DIDCredentialService.
// Delegates to DIDKeyProvider for all crypto operations.
class SigningService : public graph::mojom::DIDCredentialService {
 public:
  explicit SigningService(DIDKeyProvider* key_provider);
  ~SigningService() override;

  void BindReceiver(
      mojo::PendingReceiver<graph::mojom::DIDCredentialService> receiver);

  // mojom::DIDCredentialService:
  void CreateCredential(const std::string& display_name,
                        const std::string& algorithm,
                        CreateCredentialCallback callback) override;
  void ListCredentials(ListCredentialsCallback callback) override;
  void GetActiveCredential(GetActiveCredentialCallback callback) override;
  void SetActiveCredential(const std::string& credential_id,
                           SetActiveCredentialCallback callback) override;
  void DeleteCredential(const std::string& credential_id,
                        DeleteCredentialCallback callback) override;
  void Sign(const std::string& credential_id,
            const std::string& data_json,
            SignCallback callback) override;
  void Verify(graph::mojom::SignedContentPtr content,
              VerifyCallback callback) override;
  void Lock(const std::string& credential_id,
            LockCallback callback) override;
  void Unlock(const std::string& credential_id,
              UnlockCallback callback) override;
  void ResolveDID(const std::string& did,
                  ResolveDIDCallback callback) override;

 private:
  raw_ptr<DIDKeyProvider> key_provider_;  // Not owned.
  mojo::ReceiverSet<graph::mojom::DIDCredentialService> receivers_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_SIGNING_SERVICE_H_
