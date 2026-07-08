// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A thin RAII C++ wrapper over the OpenMLS (RFC 9420) C ABI
// (third_party/mls_ffi/include/mls.h), used by the standalone Spec 09 test
// harness to run a real MLS group ceremony behind the Default Sync Module's
// exporter seam (§6.3.9). This is the harness analogue of the browser's
// //crypto-backed MLS engine: only the standalone build world compiles it, and
// it exists so the shared Spec 09 core's key schedule and AEAD envelope can be
// exercised end-to-end against a genuine RFC 9420 exporter rather than a
// synthetic secret.
//
// Every operation throws std::runtime_error carrying mls_last_error() on
// failure, so tests read as a linear ceremony script.

#ifndef LIVING_WEB_STANDALONE_MLS_ENGINE_H_
#define LIVING_WEB_STANDALONE_MLS_ENGINE_H_

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

#include "mls.h"

namespace living_web {
namespace mls_engine {

// Moves the bytes owned by |buf| into a std::string and frees the buffer. A
// null buffer means the FFI call failed; the thread-local error is raised.
inline std::string TakeBuf(MlsBuf buf) {
  if (buf.data == nullptr) {
    const char* err = mls_last_error();
    throw std::runtime_error(std::string("mls_ffi: ") +
                             (err ? err : "unknown error"));
  }
  std::string out(reinterpret_cast<const char*>(buf.data), buf.len);
  mls_buf_free(buf);
  return out;
}

// One MLS member: owns its crypto provider, signer, credential and (once
// created or joined) its group. Move-only (it wraps a raw FFI handle).
class Member {
 public:
  explicit Member(const std::string& identity)
      : member_(mls_member_new(identity.data(), identity.size())) {
    if (member_ == nullptr) {
      const char* err = mls_last_error();
      throw std::runtime_error(std::string("mls_member_new: ") +
                               (err ? err : "error"));
    }
  }

  ~Member() {
    if (member_) {
      mls_member_free(member_);
    }
  }

  Member(const Member&) = delete;
  Member& operator=(const Member&) = delete;
  Member(Member&& o) noexcept : member_(o.member_) { o.member_ = nullptr; }
  Member& operator=(Member&& o) noexcept {
    if (this != &o) {
      if (member_) {
        mls_member_free(member_);
      }
      member_ = o.member_;
      o.member_ = nullptr;
    }
    return *this;
  }

  // The member's 32-byte Ed25519 signature public key.
  std::string SignaturePublicKey() {
    return TakeBuf(mls_member_signature_public_key(member_));
  }

  // A fresh serialised KeyPackage to hand to a group member for an Add.
  std::string KeyPackage() { return TakeBuf(mls_member_key_package(member_)); }

  // Found a new group with the given 32-byte group_id (§6.3.1).
  void CreateGroup(const std::string& group_id) {
    if (mls_member_create_group(
            member_, reinterpret_cast<const uint8_t*>(group_id.data()),
            group_id.size()) != 0) {
      throw Error("create_group");
    }
  }

  // Add the holder of |key_package|; returns {commit, welcome}.
  std::pair<std::string, std::string> Add(const std::string& key_package) {
    MlsBuf commit{};
    MlsBuf welcome{};
    if (mls_member_add(member_,
                       reinterpret_cast<const uint8_t*>(key_package.data()),
                       key_package.size(), &commit, &welcome) != 0) {
      throw Error("add");
    }
    return {TakeBuf(commit), TakeBuf(welcome)};
  }

  // Join from a Welcome.
  void Join(const std::string& welcome) {
    if (mls_member_join(member_,
                        reinterpret_cast<const uint8_t*>(welcome.data()),
                        welcome.size()) != 0) {
      throw Error("join");
    }
  }

  // Apply a Commit produced by another member.
  void ProcessCommit(const std::string& commit) {
    if (mls_member_process_commit(
            member_, reinterpret_cast<const uint8_t*>(commit.data()),
            commit.size()) != 0) {
      throw Error("process_commit");
    }
  }

  // Issue a self-Update Commit; returns the serialised commit.
  std::string Update() {
    MlsBuf commit{};
    if (mls_member_update(member_, &commit) != 0) {
      throw Error("update");
    }
    return TakeBuf(commit);
  }

  // Remove the member at |leaf_index|; returns the serialised commit.
  std::string Remove(uint32_t leaf_index) {
    MlsBuf commit{};
    if (mls_member_remove(member_, leaf_index, &commit) != 0) {
      throw Error("remove");
    }
    return TakeBuf(commit);
  }

  uint32_t OwnLeafIndex() {
    int64_t v = mls_member_own_leaf_index(member_);
    if (v < 0) {
      throw Error("own_leaf_index");
    }
    return static_cast<uint32_t>(v);
  }

  uint64_t Epoch() {
    int64_t v = mls_member_epoch(member_);
    if (v < 0) {
      throw Error("epoch");
    }
    return static_cast<uint64_t>(v);
  }

  size_t MemberCount() {
    int64_t v = mls_member_count(member_);
    if (v < 0) {
      throw Error("member_count");
    }
    return static_cast<size_t>(v);
  }

  // The RFC 9420 §8.5 exporter (the §6.3.9 seam).
  std::string ExportSecret(const std::string& label,
                           const std::string& context,
                           size_t out_len) {
    return TakeBuf(mls_member_export_secret(
        member_, label.data(), label.size(),
        reinterpret_cast<const uint8_t*>(context.data()), context.size(),
        out_len));
  }

 private:
  std::runtime_error Error(const char* op) const {
    const char* err = mls_last_error();
    return std::runtime_error(std::string("mls_ffi ") + op + ": " +
                              (err ? err : "error"));
  }

  MlsMember* member_;
};

}  // namespace mls_engine
}  // namespace living_web

#endif  // LIVING_WEB_STANDALONE_MLS_ENGINE_H_
