// C ABI for the RFC 9420 (Messaging Layer Security) engine behind the Living
// Web Default Sync Module (Spec 09 — drafts/09_default-sync-module.md).
//
// Spec 09 §6.3 mounts a *real* MLS group per encrypted space: the ceremony
// (group creation, Add/Remove/Update Commits, Welcomes, the ratchet tree) is
// RFC 9420 and is NOT hand-rolled — it is delivered by OpenMLS through a thin
// Rust staticlib in third_party/mls_ffi, built with cargo, exactly as Spec 02's
// RDF substrate is delivered by Oxigraph. This header is the single source of
// truth for the boundary; it mirrors the `#[no_mangle] extern "C"` surface of
// `src/lib.rs` exactly. Keep the two in lockstep.
//
// The seam to the Chromium-independent Spec 09 core
// (content/browser/graph_sync/default_sync_module.h) is the epoch's exporter
// output (§6.3.9): `mls_member_export_secret(m, "lw-sync space frame",
// spaceUri, 32)` returns exactly the RFC 9420 §8.5 MLS-Exporter value that the
// core's DeriveSpaceTrafficSecret() computes — i.e. the 32-byte space traffic
// secret. The core then derives the AES-128-GCM frame key/nonce (§6.3.9) and
// seals/opens frames (§6.3.10). Both build worlds therefore agree on the wire
// bytes and the key schedule; only the ceremony differs (OpenMLS here, the
// browser's //crypto-backed engine in the overlay).
//
// Ownership:
//   * every `MlsBuf` returned by value owns heap memory and MUST be released
//     with `mls_buf_free`;
//   * every `MlsMember*` MUST be released with `mls_member_free`;
//   * `mls_last_error` returns detail for the most recent failed call on the
//     current thread, valid only until the next call on that thread.
//
// All operations are synchronous. A member owns its own crypto provider and
// in-memory group state; a member is single-threaded (do not share one
// `MlsMember*` across threads without external synchronisation).

#ifndef LIVING_WEB_THIRD_PARTY_MLS_FFI_MLS_H_
#define LIVING_WEB_THIRD_PARTY_MLS_FFI_MLS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// An owned byte buffer handed across the ABI. `data` is NULL on failure (call
// mls_last_error for detail). Release every non-null buffer with mls_buf_free.
typedef struct {
  uint8_t* data;
  size_t len;
  size_t cap;
} MlsBuf;

// An opaque MLS member: a signature key pair + basic credential + crypto
// provider, and (once created or joined) one MLS group.
typedef struct MlsMember MlsMember;

// Most recent error on the calling thread, or NULL if the last call succeeded.
// Valid until the next FFI call on this thread; do not free.
const char* mls_last_error(void);

// Releases a buffer previously returned by value from this library.
void mls_buf_free(MlsBuf buf);

// ---- member lifecycle ------------------------------------------------------

// Creates a member whose BasicCredential carries |identity| (|identity_len|
// bytes; typically the member's did:key). Generates a fresh Ed25519 signature
// key pair. Returns NULL on failure.
MlsMember* mls_member_new(const char* identity, size_t identity_len);

// Releases a member and its group state.
void mls_member_free(MlsMember* member);

// The member's 32-byte Ed25519 signature public key. Null buffer on error.
MlsBuf mls_member_signature_public_key(MlsMember* member);

// A fresh KeyPackage for this member, serialised as an MLS PublicMessage
// (`MlsMessageOut`) so a group member can add it. Null buffer on error.
MlsBuf mls_member_key_package(MlsMember* member);

// ---- group ceremony --------------------------------------------------------

// This member founds a new MLS group whose group_id is the |group_id_len|-byte
// |group_id| (Spec 09 §6.3.1 — the 32-byte SHA-256 authority of the space://
// URI). The ratchet-tree extension is enabled so Welcomes are self-contained.
// 0 on success, -1 on error.
int mls_member_create_group(MlsMember* member,
                            const uint8_t* group_id,
                            size_t group_id_len);

// This member (which MUST already be in a group) adds the holder of
// |key_package| (|kp_len| bytes, as produced by mls_member_key_package),
// committing the Add and merging it. Writes the serialised Commit through
// |out_commit| (deliver to existing members via mls_member_process_commit) and
// the serialised Welcome through |out_welcome| (deliver to the new member via
// mls_member_join). Either out-pointer MAY be NULL to discard it. 0 / -1.
int mls_member_add(MlsMember* member,
                   const uint8_t* key_package,
                   size_t kp_len,
                   MlsBuf* out_commit,
                   MlsBuf* out_welcome);

// This member (not yet in a group) joins from |welcome| (|welcome_len| bytes).
// The ratchet tree travels inside the Welcome. 0 / -1.
int mls_member_join(MlsMember* member,
                    const uint8_t* welcome,
                    size_t welcome_len);

// This member applies a Commit (|commit_len| bytes) produced by another member,
// advancing to the new epoch. 0 / -1.
int mls_member_process_commit(MlsMember* member,
                              const uint8_t* commit,
                              size_t commit_len);

// This member issues a self-Update Commit (rotates its own leaf), committing
// and merging it. Writes the serialised Commit through |out_commit| (deliver to
// the other members). |out_commit| MAY be NULL. 0 / -1.
int mls_member_update(MlsMember* member, MlsBuf* out_commit);

// This member removes the member at leaf |leaf_index|, committing and merging
// the Remove. Writes the serialised Commit through |out_commit| (deliver to the
// remaining members). |out_commit| MAY be NULL. 0 / -1.
int mls_member_remove(MlsMember* member,
                      uint32_t leaf_index,
                      MlsBuf* out_commit);

// ---- introspection ---------------------------------------------------------

// The member's own leaf index in the ratchet tree, or -1 if not in a group.
int64_t mls_member_own_leaf_index(MlsMember* member);

// The group's current epoch number, or -1 if not in a group.
int64_t mls_member_epoch(MlsMember* member);

// The number of members in the group, or -1 if not in a group.
int64_t mls_member_count(MlsMember* member);

// ---- the exporter seam (§6.3.9) --------------------------------------------

// The RFC 9420 §8.5 MLS-Exporter for the current epoch:
//   ExpandWithLabel(DeriveSecret(exporter_secret, |label|), "exported",
//                   Hash(|context|), |out_len|).
// |label| is |label_len| UTF-8 bytes; |context| is |context_len| bytes (MAY be
// NULL with |context_len| 0). Called by the Spec 09 core with
// label="lw-sync space frame", context=spaceUri, out_len=32 to obtain the space
// traffic secret. Null buffer on error.
MlsBuf mls_member_export_secret(MlsMember* member,
                                const char* label,
                                size_t label_len,
                                const uint8_t* context,
                                size_t context_len,
                                size_t out_len);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIVING_WEB_THIRD_PARTY_MLS_FFI_MLS_H_
