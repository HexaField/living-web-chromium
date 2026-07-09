// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/mls_engine.h"

#include <utility>

#include "third_party/mls_ffi/include/mls.h"

namespace content {
namespace mls_engine {

namespace {

// Moves the bytes owned by |buf| into |out| and frees the buffer. A null buffer
// means the FFI call failed. Returns false (and leaves |out| untouched) on
// failure, mirroring standalone/mls_engine.h::TakeBuf but exception-free.
bool TakeBuf(MlsBuf buf, std::string* out) {
  if (buf.data == nullptr)
    return false;
  out->assign(reinterpret_cast<const char*>(buf.data), buf.len);
  mls_buf_free(buf);
  return true;
}

}  // namespace

Member::Member(const std::string& identity)
    : member_(mls_member_new(identity.data(), identity.size())) {
  if (member_ == nullptr)
    SetError("member_new");
}

Member::~Member() {
  if (member_)
    mls_member_free(static_cast<MlsMember*>(member_));
}

Member::Member(Member&& other) noexcept
    : member_(other.member_), last_error_(std::move(other.last_error_)) {
  other.member_ = nullptr;
}

Member& Member::operator=(Member&& other) noexcept {
  if (this != &other) {
    if (member_)
      mls_member_free(static_cast<MlsMember*>(member_));
    member_ = other.member_;
    last_error_ = std::move(other.last_error_);
    other.member_ = nullptr;
  }
  return *this;
}

bool Member::SignaturePublicKey(std::string* out) {
  if (!TakeBuf(mls_member_signature_public_key(static_cast<MlsMember*>(member_)),
               out)) {
    return SetError("signature_public_key");
  }
  return true;
}

bool Member::KeyPackage(std::string* out) {
  if (!TakeBuf(mls_member_key_package(static_cast<MlsMember*>(member_)), out))
    return SetError("key_package");
  return true;
}

bool Member::CreateGroup(const std::string& group_id) {
  if (mls_member_create_group(
          static_cast<MlsMember*>(member_),
          reinterpret_cast<const uint8_t*>(group_id.data()),
          group_id.size()) != 0) {
    return SetError("create_group");
  }
  return true;
}

bool Member::Add(const std::string& key_package,
                 std::string* out_commit,
                 std::string* out_welcome) {
  MlsBuf commit{};
  MlsBuf welcome{};
  if (mls_member_add(static_cast<MlsMember*>(member_),
                     reinterpret_cast<const uint8_t*>(key_package.data()),
                     key_package.size(), &commit, &welcome) != 0) {
    return SetError("add");
  }
  // The FFI guarantees both buffers on success; move each to its out-param.
  if (out_commit)
    out_commit->assign(reinterpret_cast<const char*>(commit.data), commit.len);
  mls_buf_free(commit);
  if (out_welcome) {
    out_welcome->assign(reinterpret_cast<const char*>(welcome.data),
                        welcome.len);
  }
  mls_buf_free(welcome);
  return true;
}

bool Member::Join(const std::string& welcome) {
  if (mls_member_join(static_cast<MlsMember*>(member_),
                      reinterpret_cast<const uint8_t*>(welcome.data()),
                      welcome.size()) != 0) {
    return SetError("join");
  }
  return true;
}

bool Member::ProcessCommit(const std::string& commit) {
  if (mls_member_process_commit(
          static_cast<MlsMember*>(member_),
          reinterpret_cast<const uint8_t*>(commit.data()), commit.size()) != 0) {
    return SetError("process_commit");
  }
  return true;
}

bool Member::Update(std::string* out_commit) {
  MlsBuf commit{};
  if (mls_member_update(static_cast<MlsMember*>(member_), &commit) != 0)
    return SetError("update");
  if (out_commit)
    out_commit->assign(reinterpret_cast<const char*>(commit.data), commit.len);
  mls_buf_free(commit);
  return true;
}

bool Member::Remove(uint32_t leaf_index, std::string* out_commit) {
  MlsBuf commit{};
  if (mls_member_remove(static_cast<MlsMember*>(member_), leaf_index, &commit) !=
      0) {
    return SetError("remove");
  }
  if (out_commit)
    out_commit->assign(reinterpret_cast<const char*>(commit.data), commit.len);
  mls_buf_free(commit);
  return true;
}

bool Member::OwnLeafIndex(uint32_t* out) {
  int64_t v = mls_member_own_leaf_index(static_cast<MlsMember*>(member_));
  if (v < 0)
    return SetError("own_leaf_index");
  *out = static_cast<uint32_t>(v);
  return true;
}

bool Member::Epoch(uint64_t* out) {
  int64_t v = mls_member_epoch(static_cast<MlsMember*>(member_));
  if (v < 0)
    return SetError("epoch");
  *out = static_cast<uint64_t>(v);
  return true;
}

bool Member::MemberCount(size_t* out) {
  int64_t v = mls_member_count(static_cast<MlsMember*>(member_));
  if (v < 0)
    return SetError("member_count");
  *out = static_cast<size_t>(v);
  return true;
}

bool Member::ExportSecret(const std::string& label,
                          const std::string& context,
                          size_t out_len,
                          std::string* out) {
  if (!TakeBuf(mls_member_export_secret(
                   static_cast<MlsMember*>(member_), label.data(), label.size(),
                   reinterpret_cast<const uint8_t*>(context.data()),
                   context.size(), out_len),
               out)) {
    return SetError("export_secret");
  }
  return true;
}

bool Member::SetError(const char* op) {
  const char* err = mls_last_error();
  last_error_ = std::string("mls_ffi ") + op + ": " + (err ? err : "error");
  return false;
}

}  // namespace mls_engine
}  // namespace content
