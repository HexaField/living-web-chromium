// DID Key Provider - standalone implementation
#ifndef LIVING_WEB_DID_KEY_PROVIDER_H_
#define LIVING_WEB_DID_KEY_PROVIDER_H_

#include "types.h"
#include "base_shim.h"
#include "crypto_sha2.h"
#include "third_party/ed25519/ed25519.h"

#include <ctime>
#include <iomanip>
#include <memory>
#include <sstream>
#include <unordered_map>

namespace living_web {

class DIDKeyProvider {
 public:
  DIDKeyProvider() = default;
  ~DIDKeyProvider() = default;

  DIDKeyProvider(const DIDKeyProvider&) = delete;
  DIDKeyProvider& operator=(const DIDKeyProvider&) = delete;

  std::unique_ptr<DIDKeyPair> CreateKey(const std::string& display_name) {
    auto key = std::make_unique<DIDKeyPair>();
    key->id = base::Uuid::GenerateRandomV4().AsLowercaseString();
    key->display_name = display_name;
    key->algorithm = "Ed25519";
    key->created_at = CurrentTimestamp();
    key->is_locked = false;

    key->public_key.resize(32);
    key->private_key.resize(64);
    ed25519_create_keypair(key->public_key.data(), key->private_key.data());

    key->did = DeriveDidKey(key->public_key);

    std::string id = key->id;
    auto result = std::make_unique<DIDKeyPair>(*key);
    credentials_[id] = std::move(key);

    if (active_credential_id_.empty())
      active_credential_id_ = id;

    return result;
  }

  std::vector<const DIDKeyPair*> ListCredentials() const {
    std::vector<const DIDKeyPair*> result;
    for (const auto& [id, key] : credentials_)
      result.push_back(key.get());
    return result;
  }

  const DIDKeyPair* GetCredential(const std::string& id) const {
    auto it = credentials_.find(id);
    return it != credentials_.end() ? it->second.get() : nullptr;
  }

  bool DeleteCredential(const std::string& id) {
    auto it = credentials_.find(id);
    if (it == credentials_.end()) return false;
    credentials_.erase(it);
    if (active_credential_id_ == id) active_credential_id_.clear();
    return true;
  }

  const DIDKeyPair* GetActiveCredential() const {
    if (active_credential_id_.empty()) return nullptr;
    return GetCredential(active_credential_id_);
  }

  bool SetActiveCredential(const std::string& id) {
    if (credentials_.find(id) == credentials_.end()) return false;
    active_credential_id_ = id;
    return true;
  }

  std::optional<SignedContentResult> Sign(const std::string& credential_id,
                                           const std::string& data_json) {
    auto it = credentials_.find(credential_id);
    if (it == credentials_.end()) return std::nullopt;

    const auto& key = it->second;
    if (key->is_locked) return std::nullopt;

    std::string timestamp = CurrentTimestamp();
    std::string message_input = data_json + timestamp;
    std::string hash = crypto::SHA256HashString(message_input);

    std::vector<uint8_t> signature(64);
    ed25519_sign(signature.data(),
                 reinterpret_cast<const uint8_t*>(hash.data()),
                 hash.size(), key->private_key.data());

    SignedContentResult result;
    result.author = key->did;
    result.timestamp = timestamp;
    result.data_json = data_json;
    result.proof_key = key->did;
    result.proof_sig = HexEncode(signature);
    return result;
  }

  bool Verify(const std::string& author_did,
              const std::string& data_json,
              const std::string& timestamp,
              const std::string& signature_hex) {
    auto public_key = ExtractPublicKey(author_did);
    if (public_key.size() != 32) return false;

    std::string message_input = data_json + timestamp;
    std::string hash = crypto::SHA256HashString(message_input);

    auto signature = HexDecode(signature_hex);
    if (signature.size() != 64) return false;

    return ed25519_verify(
        signature.data(),
        reinterpret_cast<const uint8_t*>(hash.data()),
        hash.size(), public_key.data()) == 1;
  }

  std::string ResolveDID(const std::string& did) const {
    auto public_key = ExtractPublicKey(did);
    if (public_key.empty()) return "";

    std::string key_hex = HexEncode(public_key);

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

  bool Lock(const std::string& credential_id) {
    auto it = credentials_.find(credential_id);
    if (it == credentials_.end()) return false;
    it->second->is_locked = true;
    return true;
  }

  bool Unlock(const std::string& credential_id) {
    auto it = credentials_.find(credential_id);
    if (it == credentials_.end()) return false;
    it->second->is_locked = false;
    return true;
  }

  // Public hex encode/decode for testing
  static std::string HexEncode(const std::vector<uint8_t>& bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
      result += hex_chars[b >> 4];
      result += hex_chars[b & 0x0f];
    }
    return result;
  }

  static std::vector<uint8_t> HexDecode(const std::string& hex) {
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

 private:
  std::string DeriveDidKey(const std::vector<uint8_t>& public_key) const {
    // Full hex encoding of public key after multicodec prefix
    return "did:key:z6Mk" + HexEncode(public_key);
  }

  std::vector<uint8_t> ExtractPublicKey(const std::string& did) const {
    if (did.find("did:key:z6Mk") != 0) return {};
    std::string hex_part = did.substr(12);  // After "did:key:z6Mk"
    if (hex_part.size() < 64) return {};
    return HexDecode(hex_part.substr(0, 64));
  }

  std::string CurrentTimestamp() const {
    auto now = std::time(nullptr);
    auto* tm = std::gmtime(&now);
    std::ostringstream ss;
    ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
  }

  std::unordered_map<std::string, std::unique_ptr<DIDKeyPair>> credentials_;
  std::string active_credential_id_;
};

}  // namespace living_web

#endif  // LIVING_WEB_DID_KEY_PROVIDER_H_
