// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// DIDKeyProvider — browser-process backend for the Decentralised Identity Web
// Platform specification (Spec 01), did:key method. The cryptographic encoding
// (did:key derivation/parsing, multibase) and JCS canonicalisation live in the
// Chromium-independent modules content/browser/did/did_key_codec.* and
// content/browser/did/jcs.*, which are shared verbatim with the standalone
// conformance harness so the two backends never diverge.

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

  std::string author;         // DID URI
  std::string timestamp;      // RFC 3339
  std::string data_json;
  std::string proof_method;   // verification method id (DID URI + fragment)
  std::string proof_sig;      // multibase(base58btc, 'z') Ed25519 signature
  std::string proof_type;     // "Ed25519Signature2020"
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

  // sign(data) per §6.1/§6.4. Canonicalises |data_json| with JCS [[RFC8785]],
  // hashes SHA-256(canonical || timestamp), signs with Ed25519, and returns a
  // multibase-encoded signature. Returns nullopt if the credential is unknown
  // or locked, or if |data_json| is not well-formed JSON.
  std::optional<SignedContentResult> Sign(const std::string& credential_id,
                                           const std::string& data_json);

  // signCapability(zcap) per §6.3. Canonicalises and signs a capability
  // document; returns nullopt if |zcap_json| is not a JSON object. Full
  // ZCAP-LD structural validation lives in the Capability Framework (Spec 04).
  std::optional<SignedContentResult> SignCapability(
      const std::string& credential_id, const std::string& zcap_json);

  // signRaw(payload) per §6.5. Signs the bytes verbatim — no canonicalisation,
  // hashing, timestamp, or framing — and returns the raw 64-byte Ed25519
  // signature. Returns nullopt if the credential is unknown or locked.
  std::optional<std::vector<uint8_t>> SignRaw(
      const std::string& credential_id,
      const std::vector<uint8_t>& payload);

  // verify() per §6.2. |signature_multibase| is a multibase string.
  bool Verify(const std::string& author_did,
              const std::string& data_json,
              const std::string& timestamp,
              const std::string& signature_multibase);

  std::string ResolveDID(const std::string& did) const;
  bool Lock(const std::string& credential_id);
  bool Unlock(const std::string& credential_id);
  bool IsLocked(const std::string& credential_id) const;

 private:
  std::string CurrentTimestamp() const;

  std::unordered_map<std::string, std::unique_ptr<DIDKeyPair>> credentials_;
  std::string active_credential_id_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_DID_KEY_PROVIDER_H_
