// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/did_key_provider.h"

#include <ctime>
#include <iomanip>
#include <sstream>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/uuid.h"
#include "crypto/sha2.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"

namespace content {

DIDKeyPair::DIDKeyPair() = default;
DIDKeyPair::~DIDKeyPair() = default;
DIDKeyPair::DIDKeyPair(const DIDKeyPair&) = default;
DIDKeyPair& DIDKeyPair::operator=(const DIDKeyPair&) = default;
DIDKeyPair::DIDKeyPair(DIDKeyPair&&) = default;
DIDKeyPair& DIDKeyPair::operator=(DIDKeyPair&&) = default;

SignedContentResult::SignedContentResult() = default;
SignedContentResult::~SignedContentResult() = default;
SignedContentResult::SignedContentResult(const SignedContentResult&) = default;
SignedContentResult& SignedContentResult::operator=(const SignedContentResult&) = default;
SignedContentResult::SignedContentResult(SignedContentResult&&) = default;
SignedContentResult& SignedContentResult::operator=(SignedContentResult&&) = default;

DIDKeyProvider::DIDKeyProvider() = default;
DIDKeyProvider::~DIDKeyProvider() = default;

std::unique_ptr<DIDKeyPair> DIDKeyProvider::CreateKey(
    const std::string& display_name) {
  auto key = std::make_unique<DIDKeyPair>();
  key->id = base::Uuid::GenerateRandomV4().AsLowercaseString();
  key->display_name = display_name;
  key->algorithm = "Ed25519";
  key->created_at = CurrentTimestamp();
  key->is_locked = false;

  // Generate Ed25519 key pair using BoringSSL.
  key->public_key.resize(32);
  key->private_key.resize(64);
  ED25519_keypair(key->public_key.data(), key->private_key.data());

  // Derive did:key URI.
  key->did = DeriveDidKey(key->public_key);

  LOG(INFO) << "Created DID credential: " << key->did
            << " (" << display_name << ")";

  std::string id = key->id;
  credentials_[id] = std::move(key);

  // Set as active if first credential.
  if (active_credential_id_.empty())
    active_credential_id_ = id;

  return std::make_unique<DIDKeyPair>(*credentials_[id]);
}

std::vector<const DIDKeyPair*> DIDKeyProvider::ListCredentials() const {
  std::vector<const DIDKeyPair*> result;
  for (const auto& [id, key] : credentials_) {
    result.push_back(key.get());
  }
  return result;
}

const DIDKeyPair* DIDKeyProvider::GetCredential(const std::string& id) const {
  auto it = credentials_.find(id);
  return it != credentials_.end() ? it->second.get() : nullptr;
}

bool DIDKeyProvider::DeleteCredential(const std::string& id) {
  auto it = credentials_.find(id);
  if (it == credentials_.end())
    return false;
  credentials_.erase(it);
  if (active_credential_id_ == id)
    active_credential_id_.clear();
  return true;
}

const DIDKeyPair* DIDKeyProvider::GetActiveCredential() const {
  if (active_credential_id_.empty())
    return nullptr;
  return GetCredential(active_credential_id_);
}

bool DIDKeyProvider::SetActiveCredential(const std::string& id) {
  if (credentials_.find(id) == credentials_.end())
    return false;
  active_credential_id_ = id;
  return true;
}

std::optional<SignedContentResult> DIDKeyProvider::Sign(
    const std::string& credential_id,
    const std::string& data_json) {
  auto it = credentials_.find(credential_id);
  if (it == credentials_.end())
    return std::nullopt;

  const auto& key = it->second;
  if (key->is_locked)
    return std::nullopt;

  std::string timestamp = CurrentTimestamp();

  // Compute message: SHA-256(data_json || timestamp)
  // Note: In full implementation, data_json should be JCS-canonicalized first.
  std::string message_input = data_json + timestamp;
  std::string hash = crypto::SHA256HashString(message_input);

  // Sign with Ed25519.
  std::vector<uint8_t> signature(64);
  if (!ED25519_sign(signature.data(),
                     reinterpret_cast<const uint8_t*>(hash.data()),
                     hash.size(),
                     key->private_key.data())) {
    LOG(ERROR) << "Ed25519 signing failed";
    return std::nullopt;
  }

  SignedContentResult result;
  result.author = key->did;
  result.timestamp = timestamp;
  result.data_json = data_json;
  result.proof_key = key->did;
  result.proof_sig = HexEncode(signature);

  return result;
}

bool DIDKeyProvider::Verify(const std::string& author_did,
                             const std::string& data_json,
                             const std::string& timestamp,
                             const std::string& signature_hex) {
  // Extract public key from did:key URI.
  auto public_key = ExtractPublicKey(author_did);
  if (public_key.size() != 32)
    return false;

  // Compute message: SHA-256(data_json || timestamp)
  std::string message_input = data_json + timestamp;
  std::string hash = crypto::SHA256HashString(message_input);

  // Decode signature from hex.
  auto signature = HexDecode(signature_hex);
  if (signature.size() != 64)
    return false;

  // Verify with Ed25519.
  return ED25519_verify(
      reinterpret_cast<const uint8_t*>(hash.data()),
      hash.size(),
      signature.data(),
      public_key.data()) == 1;
}

std::string DIDKeyProvider::ResolveDID(const std::string& did) const {
  // did:key resolution is algorithmic — extract public key and build
  // DID Document.
  auto public_key = ExtractPublicKey(did);
  if (public_key.empty())
    return "";

  std::string key_hex = HexEncode(public_key);

  // Build minimal DID Document.
  return R"({
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": ")" + did + R"(",
  "verificationMethod": [{
    "id": ")" + did + R"(#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": ")" + did + R"(",
    "publicKeyMultibase": "z)" + key_hex + R"("
  }],
  "authentication": [")" + did + R"(#key-1"],
  "assertionMethod": [")" + did + R"(#key-1"],
  "capabilityDelegation": [")" + did + R"(#key-1"],
  "capabilityInvocation": [")" + did + R"(#key-1"]
})";
}

bool DIDKeyProvider::Lock(const std::string& credential_id) {
  auto it = credentials_.find(credential_id);
  if (it == credentials_.end())
    return false;
  it->second->is_locked = true;
  return true;
}

bool DIDKeyProvider::Unlock(const std::string& credential_id) {
  auto it = credentials_.find(credential_id);
  if (it == credentials_.end())
    return false;
  // In production: trigger platform authentication (biometric/passphrase).
  it->second->is_locked = false;
  return true;
}

std::string DIDKeyProvider::DeriveDidKey(
    const std::vector<uint8_t>& public_key) const {
  // did:key encoding: did:key:z + base58btc(0xed01 + pubkey)
  // Simplified: use hex encoding with z prefix for now.
  // Full implementation would use proper multicodec + base58btc.
  std::string encoded = "z6Mk";  // Ed25519 multicodec prefix in base58btc
  encoded += HexEncode(public_key).substr(0, 44);  // Truncated for readability
  return "did:key:" + encoded;
}

std::vector<uint8_t> DIDKeyProvider::ExtractPublicKey(
    const std::string& did) const {
  // Parse did:key:z6Mk... to extract public key.
  // Simplified: decode from our hex encoding.
  if (did.find("did:key:z6Mk") != 0)
    return {};

  std::string hex_part = did.substr(12);  // After "did:key:z6Mk"
  // Pad to 64 chars if needed for 32 bytes.
  while (hex_part.size() < 64)
    hex_part += "0";
  return HexDecode(hex_part.substr(0, 64));
}

std::string DIDKeyProvider::CurrentTimestamp() const {
  auto now = std::time(nullptr);
  auto* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

std::string DIDKeyProvider::HexEncode(
    const std::vector<uint8_t>& bytes) const {
  return base::HexEncode(bytes);
}

std::vector<uint8_t> DIDKeyProvider::HexDecode(const std::string& hex) const {
  std::vector<uint8_t> result;
  result.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    auto from_hex = [](char c) -> uint8_t {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return 10 + c - 'a';
      if (c >= 'A' && c <= 'F') return 10 + c - 'A';
      return 0;
    };
    result.push_back((from_hex(hex[i]) << 4) | from_hex(hex[i + 1]));
  }
  return result;
}

}  // namespace content
