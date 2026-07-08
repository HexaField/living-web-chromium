// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Standalone provider for Spec 09 (Default Sync Module). It supplies the two
// things the Chromium-independent core (content/browser/graph_sync/
// default_sync_module.h) needs from the host world:
//
//   1. `SyncCrypto` — the injected cryptographic primitives, resolved here to
//      OpenSSL (SHA-256/512, HMAC-SHA256, X25519, AES-128-GCM) and the vendored
//      Ed25519 wrapper. The browser backend resolves the same seam to //crypto.
//
//   2. `InProcessRelay` — a modelled §6.1 dumb-pipe relay (subscribe / send /
//      deliver with per-space membership and §7.1 peer discovery). In the
//      browser this is a real WebTransport relay; in the harness it is an
//      in-process broker so the relay protocol can be exercised without a
//      network, exactly as module_runtime_provider.h models the transport.
//
// The MLS ceremony (RFC 9420) that produces each epoch's `exporter_secret` is a
// vendored engine plugged in behind the exporter seam (§6.3.9); this provider
// deliberately does not hand-roll it. Everything downstream of the exporter
// secret — the wire frames, the key schedule, the AEAD envelope, the OR-Set —
// is the shared core and is driven through the `SyncCrypto` supplied here.

#ifndef LIVING_WEB_DEFAULT_SYNC_PROVIDER_H_
#define LIVING_WEB_DEFAULT_SYNC_PROVIDER_H_

#include <algorithm>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "content/browser/graph_sync/default_sync_module.h"
#include "third_party/ed25519/ed25519.h"

namespace living_web {
namespace default_sync {

// ---------------------------------------------------------------------------
// OpenSSL-backed SyncCrypto
// ---------------------------------------------------------------------------

namespace provider_detail {

inline std::string OsslSha256(const std::string& data) {
  unsigned char out[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), out);
  return std::string(reinterpret_cast<char*>(out), SHA256_DIGEST_LENGTH);
}

inline std::string OsslSha512(const std::string& data) {
  unsigned char out[SHA512_DIGEST_LENGTH];
  SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), out);
  return std::string(reinterpret_cast<char*>(out), SHA512_DIGEST_LENGTH);
}

inline std::string OsslHmacSha256(const std::string& key,
                                  const std::string& data) {
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int mac_len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac,
       &mac_len);
  return std::string(reinterpret_cast<char*>(mac), mac_len);
}

// X25519(scalar, u): scalar multiplication of the 32-byte |scalar| by the point
// with u-coordinate |u|. Returns "" on any failure.
inline std::string OsslX25519(const std::string& scalar, const std::string& u) {
  if (scalar.size() != 32 || u.size() != 32)
    return std::string();
  std::string result;
  EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr,
      reinterpret_cast<const unsigned char*>(scalar.data()), 32);
  EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr,
      reinterpret_cast<const unsigned char*>(u.data()), 32);
  if (priv && peer) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (ctx && EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer) == 1) {
      size_t out_len = 32;
      unsigned char out[32];
      if (EVP_PKEY_derive(ctx, out, &out_len) == 1 && out_len == 32)
        result.assign(reinterpret_cast<char*>(out), 32);
    }
    if (ctx)
      EVP_PKEY_CTX_free(ctx);
  }
  if (priv)
    EVP_PKEY_free(priv);
  if (peer)
    EVP_PKEY_free(peer);
  return result;
}

// AES-128-GCM seal: out = ciphertext ‖ 16-byte tag.
inline bool OsslAes128GcmSeal(const std::string& key,
                              const std::string& nonce,
                              const std::string& aad,
                              const std::string& plaintext,
                              std::string* out) {
  if (key.size() != 16 || nonce.size() != 12)
    return false;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return false;
  bool ok = false;
  do {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) !=
        1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
      break;
    if (EVP_EncryptInit_ex(
            ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()),
            reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
      break;
    int len = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx, nullptr, &len,
                          reinterpret_cast<const unsigned char*>(aad.data()),
                          static_cast<int>(aad.size())) != 1)
      break;
    std::string ct;
    ct.resize(plaintext.size());
    int ct_len = 0;
    if (EVP_EncryptUpdate(
            ctx, reinterpret_cast<unsigned char*>(&ct[0]), &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) != 1)
      break;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ct[0]) + len,
                            &len) != 1)
      break;
    ct_len += len;
    ct.resize(ct_len);
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
      break;
    *out = ct + std::string(reinterpret_cast<char*>(tag), 16);
    ok = true;
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

// AES-128-GCM open: input = ciphertext ‖ 16-byte tag. Returns false on auth
// failure.
inline bool OsslAes128GcmOpen(const std::string& key,
                              const std::string& nonce,
                              const std::string& aad,
                              const std::string& ciphertext,
                              std::string* out) {
  if (key.size() != 16 || nonce.size() != 12 || ciphertext.size() < 16)
    return false;
  const size_t body_len = ciphertext.size() - 16;
  const unsigned char* body =
      reinterpret_cast<const unsigned char*>(ciphertext.data());
  const unsigned char* tag = body + body_len;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return false;
  bool ok = false;
  do {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) !=
        1)
      break;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
      break;
    if (EVP_DecryptInit_ex(
            ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.data()),
            reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
      break;
    int len = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx, nullptr, &len,
                          reinterpret_cast<const unsigned char*>(aad.data()),
                          static_cast<int>(aad.size())) != 1)
      break;
    std::string pt;
    pt.resize(body_len);
    int pt_len = 0;
    if (body_len > 0 &&
        EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&pt[0]), &len,
                          body, static_cast<int>(body_len)) != 1)
      break;
    pt_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<unsigned char*>(tag)) != 1)
      break;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&pt[0]) + len,
                            &len) != 1)
      break;  // authentication failed
    pt_len += len;
    pt.resize(pt_len);
    *out = std::move(pt);
    ok = true;
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

inline bool OsslEd25519Verify(const std::string& public_key,
                              const std::string& message,
                              const std::string& signature) {
  if (public_key.size() != 32 || signature.size() != 64)
    return false;
  return ed25519_verify(
             reinterpret_cast<const unsigned char*>(signature.data()),
             reinterpret_cast<const unsigned char*>(message.data()),
             message.size(),
             reinterpret_cast<const unsigned char*>(public_key.data())) == 1;
}

inline std::string OsslEd25519Sign(const std::string& seed,
                                   const std::string& message) {
  if (seed.size() < 32)
    return std::string();
  unsigned char sig[64];
  // The vendored signer reads the seed from the first 32 bytes.
  ed25519_sign(sig, reinterpret_cast<const unsigned char*>(message.data()),
               message.size(),
               reinterpret_cast<const unsigned char*>(seed.data()));
  return std::string(reinterpret_cast<char*>(sig), 64);
}

}  // namespace provider_detail

// Builds the OpenSSL-backed primitive seam consumed by the shared core.
inline SyncCrypto MakeOpenSslSyncCrypto() {
  SyncCrypto c;
  c.sha256 = &provider_detail::OsslSha256;
  c.sha512 = &provider_detail::OsslSha512;
  c.hmac_sha256 = &provider_detail::OsslHmacSha256;
  c.x25519 = &provider_detail::OsslX25519;
  c.aes128gcm_seal = &provider_detail::OsslAes128GcmSeal;
  c.aes128gcm_open = &provider_detail::OsslAes128GcmOpen;
  c.ed25519_verify = &provider_detail::OsslEd25519Verify;
  c.ed25519_sign = &provider_detail::OsslEd25519Sign;
  return c;
}

// ---------------------------------------------------------------------------
// §6.1 / §7.1 — in-process relay model
// ---------------------------------------------------------------------------
//
// A dumb store-and-forward broker: it holds per-space membership and per-session
// inboxes and forwards opaque frame bytes. It has no authority over graph data
// and never inspects encrypted bodies — exactly the trust boundary of §6.1 /
// §6.3.11. Frames are addressed either to a specific session (`to`) or
// broadcast to every other subscriber in the space (`to == nullopt`).
class InProcessRelay {
 public:
  // SUBSCRIBE { spaceUri }. Registers |peer| and returns the space's current
  // member list (§7.1: SUBSCRIBE returns the current members).
  std::vector<PeerRef> Subscribe(const std::string& space_uri,
                                 const PeerRef& peer) {
    Space& s = spaces_[space_uri];
    // Replace any prior registration for this session id.
    for (auto& m : s.members) {
      if (m.session_id == peer.session_id) {
        m = peer;
        return s.members;
      }
    }
    s.members.push_back(peer);
    s.inboxes[peer.session_id];  // ensure an inbox exists
    return s.members;
  }

  // UNSUBSCRIBE { spaceUri }.
  void Unsubscribe(const std::string& space_uri,
                   const std::string& session_id) {
    auto it = spaces_.find(space_uri);
    if (it == spaces_.end())
      return;
    Space& s = it->second;
    s.members.erase(
        std::remove_if(s.members.begin(), s.members.end(),
                       [&](const PeerRef& m) {
                         return m.session_id == session_id;
                       }),
        s.members.end());
    s.inboxes.erase(session_id);
  }

  // SEND { spaceUri, frame }. |to_session| addresses one member; nullopt
  // broadcasts to every member other than |from_session|.
  void Send(const std::string& space_uri,
            const std::string& from_session,
            const std::string& frame_bytes,
            const std::optional<std::string>& to_session = std::nullopt) {
    auto it = spaces_.find(space_uri);
    if (it == spaces_.end())
      return;
    Space& s = it->second;
    if (to_session) {
      auto inbox = s.inboxes.find(*to_session);
      if (inbox != s.inboxes.end())
        inbox->second.push_back(frame_bytes);
      return;
    }
    for (auto& kv : s.inboxes) {
      if (kv.first != from_session)
        kv.second.push_back(frame_bytes);
    }
  }

  // DELIVER — drains and returns the queued frames for |session_id|.
  std::vector<std::string> Deliver(const std::string& space_uri,
                                   const std::string& session_id) {
    std::vector<std::string> out;
    auto it = spaces_.find(space_uri);
    if (it == spaces_.end())
      return out;
    auto inbox = it->second.inboxes.find(session_id);
    if (inbox == it->second.inboxes.end())
      return out;
    out.assign(inbox->second.begin(), inbox->second.end());
    inbox->second.clear();
    return out;
  }

  std::vector<PeerRef> Members(const std::string& space_uri) const {
    auto it = spaces_.find(space_uri);
    return it == spaces_.end() ? std::vector<PeerRef>() : it->second.members;
  }

 private:
  struct Space {
    std::vector<PeerRef> members;
    std::map<std::string, std::deque<std::string>> inboxes;  // session → frames
  };
  std::map<std::string, Space> spaces_;
};

}  // namespace default_sync
}  // namespace living_web

#endif  // LIVING_WEB_DEFAULT_SYNC_PROVIDER_H_
