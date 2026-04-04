// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_DID_DID_KEY_PROVIDER_H_
#define CONTENT_BROWSER_DID_DID_KEY_PROVIDER_H_

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>

namespace content {

// Ed25519 key pair for DID key management.
struct DIDKeyPair {
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
  std::string author;       // DID URI
  std::string timestamp;    // RFC 3339
  std::string data_json;
  std::string proof_key;    // DID URI of signing key
  std::string proof_sig;    // hex-encoded signature
};

// DIDKeyProvider — manages Ed25519 key pairs for DID identities.
//
// Uses BoringSSL's Ed25519 implementation for key generation and
// signing. In production, private keys would be stored in the OS
// keychain via device/fido/ or components/os_crypt/.
class DIDKeyProvider {
 public:
  DIDKeyProvider();
  ~DIDKeyProvider();

  DIDKeyProvider(const DIDKeyProvider&) = delete;
  DIDKeyProvider& operator=(const DIDKeyProvider&) = delete;

  // Create a new Ed25519 key pair. Returns the credential info.
  std::unique_ptr<DIDKeyPair> CreateKey(const std::string& display_name);

  // List all stored credentials.
  std::vector<const DIDKeyPair*> ListCredentials() const;

  // Get a credential by ID.
  const DIDKeyPair* GetCredential(const std::string& id) const;

  // Delete a credential.
  bool DeleteCredential(const std::string& id);

  // Get/set active (default) credential.
  const DIDKeyPair* GetActiveCredential() const;
  bool SetActiveCredential(const std::string& id);

  // Sign data with a credential's private key.
  // Signs: SHA-256(JCS(data) || timestamp) with Ed25519.
  std::optional<SignedContentResult> Sign(const std::string& credential_id,
                                           const std::string& data_json);

  // Verify signed content.
  bool Verify(const std::string& author_did,
              const std::string& data_json,
              const std::string& timestamp,
              const std::string& signature_hex);

  // Resolve a did:key URI to a DID Document (JSON).
  // did:key resolution is purely algorithmic — no network.
  std::string ResolveDID(const std::string& did) const;

  // Lock/unlock a credential.
  bool Lock(const std::string& credential_id);
  bool Unlock(const std::string& credential_id);

 private:
  // Derive did:key URI from Ed25519 public key.
  // Encoding: did:key:z + base58btc(multicodec(0xed01) + pubkey)
  std::string DeriveDidKey(const std::vector<uint8_t>& public_key) const;

  // Extract public key bytes from did:key URI.
  std::vector<uint8_t> ExtractPublicKey(const std::string& did) const;

  // Generate current timestamp as RFC 3339.
  std::string CurrentTimestamp() const;

  // Hex encode/decode.
  std::string HexEncode(const std::vector<uint8_t>& bytes) const;
  std::vector<uint8_t> HexDecode(const std::string& hex) const;

  std::unordered_map<std::string, std::unique_ptr<DIDKeyPair>> credentials_;
  std::string active_credential_id_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_DID_KEY_PROVIDER_H_
