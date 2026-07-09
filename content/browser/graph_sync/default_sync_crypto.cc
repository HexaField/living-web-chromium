// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/default_sync_crypto.h"

#include <cstdint>

#include "crypto/sha2.h"
#include "third_party/boringssl/src/include/openssl/aead.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/hmac.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "third_party/ed25519/ed25519.h"

namespace content {

namespace {

// The BoringSSL / //crypto resolutions of the eight Spec 09 primitives. Each is
// the byte-for-byte analogue of the OpenSSL provider used by the standalone
// harness (standalone/default_sync_provider.h::provider_detail::*), so the key
// schedule (§6.3.9) and AEAD envelope (§6.3.10) computed by the shared core
// agree across both build worlds.

// SHA-256 resolves to //crypto, matching every other browser backend
// (graph_backend.cc, group_backend_manager.cc, sync_backend.cc, ...).
std::string BsslSha256(const std::string& data) {
  return crypto::SHA256HashString(data);
}

std::string BsslSha512(const std::string& data) {
  uint8_t out[SHA512_DIGEST_LENGTH];
  SHA512(reinterpret_cast<const uint8_t*>(data.data()), data.size(), out);
  return std::string(reinterpret_cast<char*>(out), SHA512_DIGEST_LENGTH);
}

std::string BsslHmacSha256(const std::string& key, const std::string& data) {
  uint8_t mac[EVP_MAX_MD_SIZE];
  unsigned int mac_len = 0;
  HMAC(EVP_sha256(), key.data(), key.size(),
       reinterpret_cast<const uint8_t*>(data.data()), data.size(), mac,
       &mac_len);
  return std::string(reinterpret_cast<char*>(mac), mac_len);
}

// X25519(scalar, u): scalar multiplication of the 32-byte |scalar| by the point
// with u-coordinate |u|. Returns "" on any failure (e.g. a small-order point).
std::string BsslX25519(const std::string& scalar, const std::string& u) {
  if (scalar.size() != 32 || u.size() != 32)
    return std::string();
  uint8_t out[32];
  if (X25519(out, reinterpret_cast<const uint8_t*>(scalar.data()),
             reinterpret_cast<const uint8_t*>(u.data())) != 1) {
    return std::string();
  }
  return std::string(reinterpret_cast<char*>(out), 32);
}

// AES-128-GCM seal: out = ciphertext ‖ 16-byte tag. EVP_AEAD_CTX_seal writes the
// tag contiguously after the ciphertext, which is exactly the envelope the
// shared core's SealFrame produces and OpenFrame consumes.
bool BsslAes128GcmSeal(const std::string& key,
                       const std::string& nonce,
                       const std::string& aad,
                       const std::string& plaintext,
                       std::string* out) {
  if (key.size() != 16 || nonce.size() != 12)
    return false;
  EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(
      EVP_aead_aes_128_gcm(), reinterpret_cast<const uint8_t*>(key.data()),
      key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH);
  if (!ctx)
    return false;
  std::string sealed;
  sealed.resize(plaintext.size() + EVP_AEAD_max_overhead(EVP_aead_aes_128_gcm()));
  size_t sealed_len = 0;
  const bool ok =
      EVP_AEAD_CTX_seal(
          ctx, reinterpret_cast<uint8_t*>(&sealed[0]), &sealed_len,
          sealed.size(), reinterpret_cast<const uint8_t*>(nonce.data()),
          nonce.size(), reinterpret_cast<const uint8_t*>(plaintext.data()),
          plaintext.size(), reinterpret_cast<const uint8_t*>(aad.data()),
          aad.size()) == 1;
  EVP_AEAD_CTX_free(ctx);
  if (!ok)
    return false;
  sealed.resize(sealed_len);
  *out = std::move(sealed);
  return true;
}

// AES-128-GCM open: input = ciphertext ‖ 16-byte tag. Returns false on auth
// failure.
bool BsslAes128GcmOpen(const std::string& key,
                       const std::string& nonce,
                       const std::string& aad,
                       const std::string& ciphertext,
                       std::string* out) {
  if (key.size() != 16 || nonce.size() != 12 || ciphertext.size() < 16)
    return false;
  EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(
      EVP_aead_aes_128_gcm(), reinterpret_cast<const uint8_t*>(key.data()),
      key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH);
  if (!ctx)
    return false;
  std::string plain;
  plain.resize(ciphertext.size());  // opened text is never larger than input
  size_t plain_len = 0;
  const bool ok =
      EVP_AEAD_CTX_open(
          ctx, reinterpret_cast<uint8_t*>(&plain[0]), &plain_len, plain.size(),
          reinterpret_cast<const uint8_t*>(nonce.data()), nonce.size(),
          reinterpret_cast<const uint8_t*>(ciphertext.data()),
          ciphertext.size(), reinterpret_cast<const uint8_t*>(aad.data()),
          aad.size()) == 1;
  EVP_AEAD_CTX_free(ctx);
  if (!ok)
    return false;  // authentication failed
  plain.resize(plain_len);
  *out = std::move(plain);
  return true;
}

// Ed25519 verify/sign resolve to the vendored wrapper, exactly as the Spec 05
// sync_backend.cc does, so signature bytes match the standalone provider.
bool BsslEd25519Verify(const std::string& public_key,
                       const std::string& message,
                       const std::string& signature) {
  if (public_key.size() != 32 || signature.size() != 64)
    return false;
  return ed25519_verify(
             reinterpret_cast<const uint8_t*>(signature.data()),
             reinterpret_cast<const uint8_t*>(message.data()), message.size(),
             reinterpret_cast<const uint8_t*>(public_key.data())) == 1;
}

std::string BsslEd25519Sign(const std::string& seed, const std::string& message) {
  if (seed.size() < 32)
    return std::string();
  uint8_t sig[64];
  // The vendored signer reads the seed from the first 32 bytes.
  ed25519_sign(sig, reinterpret_cast<const uint8_t*>(message.data()),
               message.size(), reinterpret_cast<const uint8_t*>(seed.data()));
  return std::string(reinterpret_cast<char*>(sig), 64);
}

}  // namespace

living_web::default_sync::SyncCrypto MakeChromiumSyncCrypto() {
  living_web::default_sync::SyncCrypto c;
  c.sha256 = &BsslSha256;
  c.sha512 = &BsslSha512;
  c.hmac_sha256 = &BsslHmacSha256;
  c.x25519 = &BsslX25519;
  c.aes128gcm_seal = &BsslAes128GcmSeal;
  c.aes128gcm_open = &BsslAes128GcmOpen;
  c.ed25519_verify = &BsslEd25519Verify;
  c.ed25519_sign = &BsslEd25519Sign;
  return c;
}

}  // namespace content
