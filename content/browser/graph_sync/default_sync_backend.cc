// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/default_sync_backend.h"

#include <utility>

#include "content/browser/graph_sync/default_sync_crypto.h"

namespace content {

using default_sync::EncryptedFrame;
using default_sync::FrameKeys;
using default_sync::WireFrame;

DefaultSyncBackend::DefaultSyncBackend()
    : crypto_(MakeChromiumSyncCrypto()) {}

DefaultSyncBackend::~DefaultSyncBackend() = default;

std::string DefaultSyncBackend::ModuleContentHash(
    const std::string& wasm_binary) const {
  return default_sync::DefaultModuleContentHash(wasm_binary, crypto_.sha256);
}

// ---- §6.3 group ceremony ---------------------------------------------------

bool DefaultSyncBackend::FoundSpace(const std::string& space_uri,
                                    const std::string& identity) {
  if (spaces_.count(space_uri)) {
    last_error_ = "space_exists";
    return false;
  }
  std::string group_id;
  if (!default_sync::GroupIdFromSpaceUri(space_uri, &group_id)) {
    last_error_ = "invalid_space_uri";
    return false;
  }
  auto member = std::make_unique<mls_engine::Member>(identity);
  if (!member->ok()) {
    last_error_ = member->last_error();
    return false;
  }
  if (!member->CreateGroup(group_id)) {
    last_error_ = member->last_error();
    return false;
  }
  SpaceState state;
  state.member = std::move(member);
  spaces_.emplace(space_uri, std::move(state));
  return true;
}

bool DefaultSyncBackend::PrepareJoin(const std::string& space_uri,
                                     const std::string& identity,
                                     std::string* out_key_package) {
  if (spaces_.count(space_uri)) {
    last_error_ = "space_exists";
    return false;
  }
  auto member = std::make_unique<mls_engine::Member>(identity);
  if (!member->ok()) {
    last_error_ = member->last_error();
    return false;
  }
  if (out_key_package && !member->KeyPackage(out_key_package)) {
    last_error_ = member->last_error();
    return false;
  }
  SpaceState state;
  state.member = std::move(member);
  spaces_.emplace(space_uri, std::move(state));
  return true;
}

bool DefaultSyncBackend::JoinSpace(const std::string& space_uri,
                                   const std::string& welcome) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->Join(welcome)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::AddMember(const std::string& space_uri,
                                   const std::string& key_package,
                                   std::string* out_commit,
                                   std::string* out_welcome) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->Add(key_package, out_commit, out_welcome)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::RemoveMember(const std::string& space_uri,
                                      uint32_t leaf_index,
                                      std::string* out_commit) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->Remove(leaf_index, out_commit)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::RotateKey(const std::string& space_uri,
                                   std::string* out_commit) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->Update(out_commit)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::ProcessCommit(const std::string& space_uri,
                                       const std::string& commit) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->ProcessCommit(commit)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::KeyPackage(const std::string& space_uri,
                                    std::string* out) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->KeyPackage(out)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

// ---- §6.3.9 / §6.3.10 frame encryption -------------------------------------

bool DefaultSyncBackend::SealFrame(const std::string& space_uri,
                                   const WireFrame& plain,
                                   EncryptedFrame* out) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (plain.space_uri != space_uri) {
    last_error_ = "space_uri_mismatch";
    return false;
  }
  FrameKeys keys;
  uint64_t epoch = 0;
  if (!FrameKeysForCurrentEpoch(space_uri, state, &keys, &epoch))
    return false;
  const uint64_t seq = state->send_seq;
  if (!default_sync::SealFrame(keys, plain, epoch, seq, crypto_, out)) {
    last_error_ = "seal_failed";
    return false;
  }
  ++state->send_seq;  // consume the sequence number only on a successful seal
  return true;
}

bool DefaultSyncBackend::OpenFrame(const std::string& space_uri,
                                   const EncryptedFrame& enc,
                                   WireFrame* out) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  FrameKeys keys;
  uint64_t epoch = 0;
  if (!FrameKeysForCurrentEpoch(space_uri, state, &keys, &epoch))
    return false;
  // The exporter yields only the current epoch's secret; a frame from any other
  // epoch cannot be opened and MUST be discarded (§6.3.10). The epoch is also
  // bound into the AEAD associated data, so a mismatch would fail the tag anyway;
  // rejecting up front gives a precise error.
  if (enc.epoch != epoch) {
    last_error_ = "epoch_mismatch";
    return false;
  }
  if (!default_sync::OpenFrame(keys, enc, crypto_, out)) {
    last_error_ = "open_failed";  // AEAD authentication failed
    return false;
  }
  return true;
}

// ---- §8 OR-Set merge / §9 snapshot promotion -------------------------------

void DefaultSyncBackend::MergeDiff(const std::string& space_uri,
                                   const default_sync::DiffWire& diff) {
  if (SpaceState* state = Find(space_uri))
    state->or_set.ApplyDiff(diff);
}

bool DefaultSyncBackend::Contains(const std::string& space_uri,
                                  const std::string& triple_id) {
  SpaceState* state = Find(space_uri);
  return state && state->or_set.Contains(triple_id);
}

size_t DefaultSyncBackend::Size(const std::string& space_uri) {
  SpaceState* state = Find(space_uri);
  return state ? state->or_set.Size() : 0u;
}

bool DefaultSyncBackend::ShouldPromoteSnapshot(uint32_t diffs_since_snapshot,
                                               uint32_t threshold) const {
  return default_sync::ShouldPromote(diffs_since_snapshot, threshold);
}

// ---- introspection ---------------------------------------------------------

bool DefaultSyncBackend::SignaturePublicKey(const std::string& space_uri,
                                            std::string* out) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->SignaturePublicKey(out)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::LocalLeafIndex(const std::string& space_uri,
                                        uint32_t* out) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->OwnLeafIndex(out)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::Epoch(const std::string& space_uri, uint64_t* out) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->Epoch(out)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

bool DefaultSyncBackend::MemberCount(const std::string& space_uri,
                                     size_t* out) {
  SpaceState* state = Find(space_uri);
  if (!state)
    return false;
  if (!state->member->MemberCount(out)) {
    last_error_ = state->member->last_error();
    return false;
  }
  return true;
}

// ---- private ---------------------------------------------------------------

DefaultSyncBackend::SpaceState* DefaultSyncBackend::Find(
    const std::string& space_uri) {
  auto it = spaces_.find(space_uri);
  if (it == spaces_.end()) {
    last_error_ = "unknown_space";
    return nullptr;
  }
  return &it->second;
}

bool DefaultSyncBackend::FrameKeysForCurrentEpoch(const std::string& space_uri,
                                                  SpaceState* state,
                                                  FrameKeys* out_keys,
                                                  uint64_t* out_epoch) {
  uint64_t epoch = 0;
  if (!state->member->Epoch(&epoch)) {
    last_error_ = state->member->last_error();
    return false;
  }
  if (!state->keys_epoch || *state->keys_epoch != epoch) {
    std::string space_traffic_secret;
    if (!state->member->ExportSecret(default_sync::kSpaceFrameExporterLabel,
                                     space_uri, 32, &space_traffic_secret)) {
      last_error_ = state->member->last_error();
      return false;
    }
    state->keys = default_sync::DeriveFrameKeys(space_traffic_secret, crypto_);
    state->keys_epoch = epoch;
  }
  *out_keys = state->keys;
  *out_epoch = epoch;
  return true;
}

}  // namespace content
