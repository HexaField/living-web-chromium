// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// C++ RAII wrapper over the OpenMLS (RFC 9420) C ABI
// (third_party/mls_ffi/include/mls.h) for the Living Web Default Sync Module
// (Spec 09 §6.3). It is the browser-process analogue of the standalone harness's
// throwing wrapper (standalone/mls_engine.h): Chromium is compiled
// -fno-exceptions, so every operation returns a bool and reports failure through
// last_error() + an out-parameter, rather than throwing.
//
// This is the single owner of the MLS FFI boundary: it converts owned `MlsBuf`
// results into std::string (freeing them), surfaces `mls_last_error` as C++
// error strings, and manages member-handle lifetime — exactly as OxigraphStore
// owns the Oxigraph boundary for Spec 02. The DefaultSyncBackend above it speaks
// std::string and never touches the raw ABI.
//
// The one seam the shared Spec 09 core consumes is ExportSecret() (§6.3.9): the
// RFC 9420 §8.5 exporter output for the current epoch, which byte-for-byte
// equals the core's DeriveSpaceTrafficSecret(). A member is single-threaded (it
// wraps an OpenMLS group that owns its crypto provider); do not share one across
// threads without external synchronisation.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_MLS_ENGINE_H_
#define CONTENT_BROWSER_GRAPH_SYNC_MLS_ENGINE_H_

#include <cstdint>
#include <string>

namespace content {
namespace mls_engine {

// One MLS member: owns its crypto provider, signer, credential and (once created
// or joined) its group. Move-only (it wraps a raw FFI handle). Check ok() after
// construction before use.
class Member {
 public:
  // Creates a member whose BasicCredential carries |identity| (typically the
  // member's did:key) and a fresh Ed25519 signature key pair. Check ok().
  explicit Member(const std::string& identity);
  ~Member();

  Member(const Member&) = delete;
  Member& operator=(const Member&) = delete;
  Member(Member&& other) noexcept;
  Member& operator=(Member&& other) noexcept;

  bool ok() const { return member_ != nullptr; }
  const std::string& last_error() const { return last_error_; }

  // The member's 32-byte Ed25519 signature public key.
  bool SignaturePublicKey(std::string* out);

  // A fresh serialised KeyPackage to hand to a group member for an Add.
  bool KeyPackage(std::string* out);

  // Founds a new group with the given 32-byte |group_id| (§6.3.1).
  bool CreateGroup(const std::string& group_id);

  // Adds the holder of |key_package|; writes the serialised Commit and Welcome
  // (either out-pointer may be null to discard).
  bool Add(const std::string& key_package,
           std::string* out_commit,
           std::string* out_welcome);

  // Joins from a Welcome.
  bool Join(const std::string& welcome);

  // Applies a Commit produced by another member.
  bool ProcessCommit(const std::string& commit);

  // Issues a self-Update Commit; writes the serialised Commit (may be null).
  bool Update(std::string* out_commit);

  // Removes the member at |leaf_index|; writes the serialised Commit (may be
  // null).
  bool Remove(uint32_t leaf_index, std::string* out_commit);

  // The member's own leaf index in the ratchet tree.
  bool OwnLeafIndex(uint32_t* out);

  // The group's current epoch number.
  bool Epoch(uint64_t* out);

  // The number of members in the group.
  bool MemberCount(size_t* out);

  // The RFC 9420 §8.5 exporter (the §6.3.9 seam): the space traffic secret for
  // label="lw-sync space frame", context=spaceUri, out_len=32.
  bool ExportSecret(const std::string& label,
                    const std::string& context,
                    size_t out_len,
                    std::string* out);

 private:
  // Records the thread-local FFI error for |op| into last_error_ and returns
  // false, so callers can `return SetError("add");`.
  bool SetError(const char* op);

  void* member_ = nullptr;  // MlsMember* (opaque FFI handle)
  std::string last_error_;
};

}  // namespace mls_engine
}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_MLS_ENGINE_H_
