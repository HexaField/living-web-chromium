// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Browser-process backend for the Living Web Default Sync Module (Spec 09 —
// drafts/09_default-sync-module.md §6.3). It is the module-runtime peer of the
// standalone harness: it owns, per encrypted space, a real RFC 9420 MLS group
// (through content/browser/graph_sync/mls_engine.h) and drives the shared,
// Chromium-independent Spec 09 core (default_sync_module.h) to seal/open the
// §6.3.10 AEAD frame envelope and to merge §8 OR-Set graph state.
//
// The two crypto seams are resolved to Chromium here: the eight SyncCrypto
// primitives come from MakeChromiumSyncCrypto() (//crypto + BoringSSL), and the
// per-epoch exporter secret comes from the OpenMLS engine. Everything between —
// the key schedule (§6.3.9) and the frame envelope (§6.3.10) — is the shared
// core, so the bytes this backend encrypts are identical to the harness's.
//
// A backend instance is single-threaded (each MLS member owns its own crypto
// provider and group state); it lives on the sequence that runs the module.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_BACKEND_H_
#define CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_BACKEND_H_

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "content/browser/graph_sync/default_sync_module.h"
#include "content/browser/graph_sync/mls_engine.h"

namespace content {

// Owns the encrypted-sync state of every space this node participates in.
class DefaultSyncBackend {
 public:
  DefaultSyncBackend();
  ~DefaultSyncBackend();

  DefaultSyncBackend(const DefaultSyncBackend&) = delete;
  DefaultSyncBackend& operator=(const DefaultSyncBackend&) = delete;

  const std::string& last_error() const { return last_error_; }

  // §4.1 — the default module's content hash, "sha256-"+hex(SHA-256(wasm)).
  std::string ModuleContentHash(const std::string& wasm_binary) const;

  // ---- §6.3 group ceremony -------------------------------------------------

  // Founds a new encrypted space: creates the local MLS member identified by
  // |identity| (a did:key) and the group whose group_id is the 32-byte authority
  // of |space_uri| (§6.3.1). Fails if |space_uri| is malformed or the space is
  // already known.
  bool FoundSpace(const std::string& space_uri, const std::string& identity);

  // Prepares to join |space_uri|: creates the local member |identity| and writes
  // its KeyPackage through |out_key_package|, to hand to an existing member for
  // an Add. Follow with JoinSpace() once the resulting Welcome arrives.
  bool PrepareJoin(const std::string& space_uri,
                   const std::string& identity,
                   std::string* out_key_package);

  // Completes joining |space_uri| from |welcome| (requires a prior PrepareJoin).
  bool JoinSpace(const std::string& space_uri, const std::string& welcome);

  // Adds the holder of |key_package| to |space_uri|; writes the Commit (deliver
  // to existing members via ProcessCommit) and Welcome (deliver to the new
  // member via JoinSpace). Either out-pointer may be null.
  bool AddMember(const std::string& space_uri,
                 const std::string& key_package,
                 std::string* out_commit,
                 std::string* out_welcome);

  // Removes the member at |leaf_index| from |space_uri|; writes the Commit.
  bool RemoveMember(const std::string& space_uri,
                    uint32_t leaf_index,
                    std::string* out_commit);

  // Rotates the local leaf in |space_uri| (a self-Update Commit); writes it.
  bool RotateKey(const std::string& space_uri, std::string* out_commit);

  // Applies a Commit produced by another member of |space_uri|.
  bool ProcessCommit(const std::string& space_uri, const std::string& commit);

  // A fresh KeyPackage from the local member of |space_uri| (e.g. to re-add
  // after a Remove). Prefer PrepareJoin() for the initial join.
  bool KeyPackage(const std::string& space_uri, std::string* out);

  // ---- §6.3.9 / §6.3.10 frame encryption -----------------------------------

  // Seals |plain|'s payload for |space_uri| under the current epoch's frame keys
  // and the next send-sequence number (§6.3.10). |plain.space_uri| must equal
  // |space_uri|.
  bool SealFrame(const std::string& space_uri,
                 const default_sync::WireFrame& plain,
                 default_sync::EncryptedFrame* out);

  // Opens |enc| for |space_uri| under the current epoch's frame keys. Fails if
  // |enc.epoch| is not the local member's current epoch (the secret for a past
  // epoch is not retained) or the AEAD tag does not verify.
  bool OpenFrame(const std::string& space_uri,
                 const default_sync::EncryptedFrame& enc,
                 default_sync::WireFrame* out);

  // ---- §8 OR-Set merge / §9 snapshot promotion -----------------------------

  // Merges a DIFF into |space_uri|'s OR-Set (§8.1); commutative and idempotent.
  void MergeDiff(const std::string& space_uri,
                 const default_sync::DiffWire& diff);

  // Whether a triple is live in |space_uri|'s merged set.
  bool Contains(const std::string& space_uri, const std::string& triple_id);

  // The number of live triples in |space_uri|'s merged set.
  size_t Size(const std::string& space_uri);

  // §9.2 — whether the diff chain has reached the snapshot-promotion threshold.
  bool ShouldPromoteSnapshot(
      uint32_t diffs_since_snapshot,
      uint32_t threshold = default_sync::kDefaultSnapshotThreshold) const;

  // ---- introspection (ceremony wiring / tests) -----------------------------

  bool SignaturePublicKey(const std::string& space_uri, std::string* out);
  bool LocalLeafIndex(const std::string& space_uri, uint32_t* out);
  bool Epoch(const std::string& space_uri, uint64_t* out);
  bool MemberCount(const std::string& space_uri, size_t* out);

 private:
  // Per-space encrypted-sync state.
  struct SpaceState {
    std::unique_ptr<mls_engine::Member> member;
    uint64_t send_seq = 0;
    default_sync::OrSet or_set;
    // Frame keys cached for the epoch they were derived at, so a burst of frames
    // in one epoch runs a single exporter call (§6.3.9).
    std::optional<uint64_t> keys_epoch;
    default_sync::FrameKeys keys;
  };

  // Looks up |space_uri|; sets last_error_ + returns null if unknown.
  SpaceState* Find(const std::string& space_uri);

  // Fills |out_keys| with the frame keys for |state|'s current epoch (deriving +
  // caching on an epoch change) and |out_epoch| with that epoch. |space_uri| is
  // the exporter context (§6.3.9).
  bool FrameKeysForCurrentEpoch(const std::string& space_uri,
                                SpaceState* state,
                                default_sync::FrameKeys* out_keys,
                                uint64_t* out_epoch);

  default_sync::SyncCrypto crypto_;
  std::map<std::string, SpaceState> spaces_;
  std::string last_error_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_BACKEND_H_
