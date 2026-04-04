// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_DID_DID_KEY_PROVIDER_H_
#define CONTENT_BROWSER_DID_DID_KEY_PROVIDER_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace content {

// Ed25519 key pair for DID key management.
struct DIDKeyPair {
  DIDKeyPair();
  ~DIDKeyPair();
  DIDKeyPair(const DIDKeyPair&);
  DIDKeyPair& operator=(const DIDKeyPair&);
  DIDKeyPair(DIDKeyPair&&);
  DIDKeyPair& operator=(DIDKeyPair&&);

  std::string id;            // Internal credential ID
  std::string did;           // did:key:z6Mk... URI
  std::string display_name;
  std::string algorithm;     // "Ed25519"
  std::string created_at;    // RFC 3339
  bool is_locked = false;

  // Key material (in production, stored in OS keychain).
  std::vector<uint8_t> public_key;   // 32 bytes
  std::vector<uint8_t> private_key;  // 64 bytes (Ed25519 expanded)
};

struct SignedContentResult {
  SignedContentResult();
  ~SignedContentResult();
  SignedContentResult(const SignedContentResult&);
  SignedContentResult& operator=(const SignedContentResult&);
  SignedContentResult(SignedContentResult&&);
  SignedContentResult& operator=(SignedContentResult&&);

  std::string author;       // DID URI
  std::string timestamp;    // RFC 3339
  std::string data_json;
  std::string proof_key;    // DID URI of signing key
  std::string proof_sig;    // hex-encoded signature
};

// DIDKeyProvider — manages Ed25519 key pairs for DID identities.
class DIDKeyProvider {
 public:
  DIDKeyProvider();
  ~DIDKeyProvider();

  DIDKeyProvider(const DIDKeyProvider&) = delete;
  DIDKeyProvider& operator=(const DIDKeyProvider&) = delete;

  std::unique_ptr<DIDKeyPair> CreateKey(const std::string& display_name);
  std::vector<const DIDKeyPair*> ListCredentials() const;
  const DIDKeyPair* GetCredential(const std::string& id) const;
  bool DeleteCredential(const std::string& id);
  const DIDKeyPair* GetActiveCredential() const;
  bool SetActiveCredential(const std::string& id);
  std::optional<SignedContentResult> Sign(const std::string& credential_id,
                                           const std::string& data_json);
  bool Verify(const std::string& author_did,
              const std::string& data_json,
              const std::string& timestamp,
              const std::string& signature_hex);
  std::string ResolveDID(const std::string& did) const;
  bool Lock(const std::string& credential_id);
  bool Unlock(const std::string& credential_id);

 private:
  std::string DeriveDidKey(const std::vector<uint8_t>& public_key) const;
  std::vector<uint8_t> ExtractPublicKey(const std::string& did) const;
  std::string CurrentTimestamp() const;
  std::string HexEncode(const std::vector<uint8_t>& bytes) const;
  std::vector<uint8_t> HexDecode(const std::string& hex) const;

  std::unordered_map<std::string, std::unique_ptr<DIDKeyPair>> credentials_;
  std::string active_credential_id_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_DID_KEY_PROVIDER_H_
