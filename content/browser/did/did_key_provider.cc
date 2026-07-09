// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/did_key_provider.h"

#include <ctime>
#include <iomanip>
#include <sstream>

#include "base/logging.h"
#include "base/uuid.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/jcs.h"
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
SignedContentResult& SignedContentResult::operator=(
    const SignedContentResult&) = default;
SignedContentResult::SignedContentResult(SignedContentResult&&) = default;
SignedContentResult& SignedContentResult::operator=(SignedContentResult&&) =
    default;

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

  // did:key:z || base58btc(0xed01 || pub). public_key is always 32 bytes, so
  // DeriveDidKeyEd25519 never fails here.
  key->did = *living_web::did_key::DeriveDidKeyEd25519(key->public_key);

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

  // §6.4: canonicalise the payload with JCS before hashing. Reject payloads
  // that are not well-formed JSON.
  auto canonical = living_web::jcs::Canonicalize(data_json);
  if (!canonical)
    return std::nullopt;

  std::string timestamp = CurrentTimestamp();

  // Message = SHA-256(JCS(data) || timestamp).
  std::string message_input = *canonical + timestamp;
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

  // §6.4 step 5: proof = { method: <verificationMethodId>,
  // signature: multibase(sig), type: "Ed25519Signature2020" }. For did:key the
  // verification method id is the DID plus the key's multibase fragment.
  SignedContentResult result;
  result.author = key->did;
  result.timestamp = timestamp;
  result.data_json = data_json;
  result.proof_method =
      key->did + "#" +
      *living_web::did_key::Ed25519PublicKeyMultibase(key->public_key);
  result.proof_sig = living_web::did_key::MultibaseEncode(signature);
  result.proof_type = "Ed25519Signature2020";

  return result;
}

std::optional<SignedContentResult> DIDKeyProvider::SignCapability(
    const std::string& credential_id,
    const std::string& zcap_json) {
  // §6.3: the identity layer canonicalises and signs the capability document.
  // Require a JSON object; full ZCAP-LD structural validation and the
  // delegator-authorisation rule are defined by the Capability Framework
  // (Spec 04).
  auto canonical = living_web::jcs::Canonicalize(zcap_json);
  if (!canonical || canonical->empty() || (*canonical)[0] != '{')
    return std::nullopt;
  return Sign(credential_id, zcap_json);
}

std::optional<std::vector<uint8_t>> DIDKeyProvider::SignRaw(
    const std::string& credential_id,
    const std::vector<uint8_t>& payload) {
  auto it = credentials_.find(credential_id);
  if (it == credentials_.end())
    return std::nullopt;

  const auto& key = it->second;
  if (key->is_locked)
    return std::nullopt;

  // §6.5: sign the bytes verbatim — no canonicalisation, hashing, timestamp,
  // or framing. The caller owns any canonicalisation.
  std::vector<uint8_t> signature(64);
  if (!ED25519_sign(signature.data(), payload.data(), payload.size(),
                     key->private_key.data())) {
    LOG(ERROR) << "Ed25519 raw signing failed";
    return std::nullopt;
  }
  return signature;
}

bool DIDKeyProvider::Verify(const std::string& author_did,
                             const std::string& data_json,
                             const std::string& timestamp,
                             const std::string& signature_multibase) {
  // Resolve the author DID algorithmically to recover the public key.
  auto public_key = living_web::did_key::ParseDidKeyEd25519(author_did);
  if (!public_key || public_key->size() != 32)
    return false;

  // Reproduce the identical canonical byte sequence used when signing.
  auto canonical = living_web::jcs::Canonicalize(data_json);
  if (!canonical)
    return false;

  std::string message_input = *canonical + timestamp;
  std::string hash = crypto::SHA256HashString(message_input);

  // Decode signature from multibase.
  auto signature = living_web::did_key::MultibaseDecode(signature_multibase);
  if (!signature || signature->size() != 64)
    return false;

  // Verify with Ed25519.
  return ED25519_verify(
      reinterpret_cast<const uint8_t*>(hash.data()),
      hash.size(),
      signature->data(),
      public_key->data()) == 1;
}

std::string DIDKeyProvider::ResolveDID(const std::string& did) const {
  // §7: did:key resolution is algorithmic and always yields trustLevel
  // "local".
  auto public_key = living_web::did_key::ParseDidKeyEd25519(did);
  if (!public_key)
    return "";

  std::string pk_multibase =
      *living_web::did_key::Ed25519PublicKeyMultibase(*public_key);

  return R"({
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": ")" + did + R"(",
  "verificationMethod": [{
    "id": ")" + did + "#" + pk_multibase + R"(",
    "type": "Ed25519VerificationKey2020",
    "controller": ")" + did + R"(",
    "publicKeyMultibase": ")" + pk_multibase + R"("
  }],
  "authentication": [")" + did + "#" + pk_multibase + R"("],
  "assertionMethod": [")" + did + "#" + pk_multibase + R"("],
  "capabilityDelegation": [")" + did + "#" + pk_multibase + R"("],
  "capabilityInvocation": [")" + did + "#" + pk_multibase + R"("],
  "trustLevel": "local"
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

bool DIDKeyProvider::IsLocked(const std::string& credential_id) const {
  auto it = credentials_.find(credential_id);
  return it != credentials_.end() && it->second->is_locked;
}

std::string DIDKeyProvider::CurrentTimestamp() const {
  auto now = std::time(nullptr);
  auto* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

}  // namespace content
