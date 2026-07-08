// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Default Sync Module — the Chromium-independent core of Spec 09
// (drafts/09_default-sync-module.md). Like every other spec core in this repo
// (namespace `living_web`, pure-std, no Chromium and no OpenSSL) it is shared
// byte-for-byte by the browser default-sync backend and the standalone harness
// (standalone/default_sync_provider.h) so the wire bytes — and, critically, the
// AEAD associated-data of an encrypted frame (§6.3.10 step 4) — never diverge
// between the two build worlds.
//
// What lives here (everything spec-pinned and testable without a live MLS
// engine or transport):
//   * §4.1  module identity (content hash).
//   * §5    the CBOR wire-frame vocabulary (DIFF/PULL/PULL_DENIED/SNAPSHOT/
//           SIGNAL/MODULE_UPDATE/PEER_HELLO/PEER_BYE) and their payloads.
//   * §6.3.1 group_id ← space:// authority; §6.3.2 cipher-suite constants.
//   * §6.3.3 the deterministic did:key(Ed25519) → X25519 derivation, and the
//           §6.3.4-check-4 encryption-key binding, both directions.
//   * §6.3.9 the MLS key schedule glue (HKDF-Expand, ExpandWithLabel,
//           DeriveSecret, MLS-Exporter per RFC 9420 §8.5, the space traffic
//           secret, and the frame key/nonce).
//   * §6.3.10 the AEAD envelope: per-frame nonce, the deterministic-CBOR
//           associated data, seal/open, and the encrypted-frame codec.
//   * §8    the OR-Set CRDT, chain-root rule, and the §8.4 flow tie-break.
//   * §9    the snapshot-promotion threshold.
//
// The MLS ceremony itself (RFC 9420: group creation, Add/Remove/Update Commits,
// Welcomes, the ratchet tree) is delivered by a vendored MLS engine behind the
// `exporter_secret` seam: this core consumes the epoch's 32-byte exporter secret
// (§6.3.9) as a plain string and derives everything downstream, so the whole
// wire+key-schedule surface is testable against a synthetic exporter secret and
// the real engine plugs in unchanged.
//
// All hashing/curve/AEAD primitives are injected via `SyncCrypto` — this core
// performs no cryptography itself, exactly so it stays Chromium- and
// OpenSSL-independent (the browser resolves them to //crypto, the harness to
// OpenSSL). The one exception is the Edwards→Montgomery public-key map
// (§6.3.3), which is pure field arithmetic with no library dependency and is
// implemented here so a leaf's encryption_key can be checked against a peer's
// did:key with only the peer's public key in hand.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_MODULE_H_
#define CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_MODULE_H_

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph_sync/cbor.h"

namespace living_web {
namespace default_sync {

// ===========================================================================
// §4.1 — Module identity
// ===========================================================================

// The default module's content hash: "sha256-" + lowercase-hex(SHA-256(wasm)).
// |sha256| is the injected raw-32-byte SHA-256 primitive.
std::string DefaultModuleContentHash(
    const std::string& wasm_binary,
    const std::function<std::string(const std::string&)>& sha256);

// ===========================================================================
// §5 — Wire protocol
// ===========================================================================

// §5.1 frame types. PULL_DENIED (§5.4.1) is modelled as a first-class type.
enum class FrameType {
  kDiff,
  kPull,
  kPullDenied,
  kSnapshot,
  kSignal,
  kModuleUpdate,
  kPeerHello,
  kPeerBye,
};

// The wire token for a frame type ("DIFF", "PULL", …) and its inverse.
const char* FrameTypeToToken(FrameType type);
bool FrameTypeFromToken(const std::string& token, FrameType* out);

// A (did, sessionId) routing endpoint (§5.1 `from` / `to`, §6.2 routing
// metadata). Encoded as the CBOR map {"did", "sessionId"}.
struct PeerRef {
  std::string did;
  std::string session_id;

  bool operator==(const PeerRef& o) const {
    return did == o.did && session_id == o.session_id;
  }
};

// The common §5.1 envelope. |payload| is the type-specific body as a CBOR value
// (built with the payload helpers below); in an encrypted space it is what gets
// sealed into `enc.ct` (§6.3.10) rather than sent in the clear.
struct WireFrame {
  FrameType type = FrameType::kSignal;
  std::string space_uri;
  PeerRef from;
  std::optional<PeerRef> to;  // nullopt == broadcast within the space
  cbor::Value payload;
};

// Deterministic CBOR encode/decode of an *open-space* frame (§5.1): the map
// {type, spaceUri, from, to, payload}. Decode is strict (rejects a frame whose
// type token or shape is unknown).
std::string EncodeOpenFrame(const WireFrame& frame);
bool DecodeOpenFrame(const std::string& in, WireFrame* out);

// ---- §5.2 DIFF — the OR-Set/wire projection of a GraphDiff -----------------
//
// The DIFF payload is a CBOR GraphDiff ([[CONTEXT-SYNC]] §5.1). This core carries
// the projection the module actually reasons about: the graph id, the diff's
// content-address `revision` (which is the OR-Set add-tag, §8.1), the causal
// `dependencies` (§8.2), and the added/removed triples. A removal names, per
// §8.1, the add-tags it observed for that triple (the provider computes them
// from the causal closure). Rich per-triple provenance stays in the provider's
// full GraphDiff; this projection is what merges.

struct DiffRemoval {
  Triple triple;
  std::vector<std::string> removed_tags;  // add-tags (revisions) being removed
};

struct DiffWire {
  std::string graph_did;
  std::string revision;                    // this diff's add-tag
  std::vector<std::string> dependencies;   // observed DAG heads (§8.2)
  std::vector<Triple> additions;
  std::vector<DiffRemoval> removals;
  std::string author;
  std::string timestamp;
};

cbor::Value DiffToCbor(const DiffWire& diff);
bool DiffFromCbor(const cbor::Value& v, DiffWire* out);

// ---- §5.3 / §5.4 / §5.4.1 / §5.5 / §5.6 / §5.7 payloads ---------------------

struct PullPayload {
  std::string graph_did;
  std::optional<std::string> from_revision;         // null == want a SNAPSHOT
  std::string author_did;
  std::optional<cbor::Value> capability_proof;       // OPTIONAL (§5.3)
};
cbor::Value PullToCbor(const PullPayload& p);
bool PullFromCbor(const cbor::Value& v, PullPayload* out);

struct PullDeniedPayload {
  std::string graph_did;
  std::string reason;                       // §5.4.1 reason token
  std::optional<std::string> constraint_id;  // OPTIONAL urn:c:…
};
cbor::Value PullDeniedToCbor(const PullDeniedPayload& p);
bool PullDeniedFromCbor(const cbor::Value& v, PullDeniedPayload* out);

// §5.4.1 reason tokens.
inline constexpr char kReasonMountContextRequired[] = "mountContext_required";
inline constexpr char kReasonMountContextInvalid[] = "mountContext_invalid";
inline constexpr char kReasonCredentialRequired[] = "credential_required";
inline constexpr char kReasonRateLimited[] = "rate_limited";

struct SnapshotPayload {
  std::string graph_did;
  std::string snapshot;  // GraphSnapshot bytes ([[PERSONAL-LINKED-DATA-GRAPHS]] §5)
};
cbor::Value SnapshotToCbor(const SnapshotPayload& p);
bool SnapshotFromCbor(const cbor::Value& v, SnapshotPayload* out);

struct ModuleUpdatePayload {
  std::string new_hash;
  std::string space_uri;
  std::vector<std::string> distribution_urls;
};
cbor::Value ModuleUpdateToCbor(const ModuleUpdatePayload& p);
bool ModuleUpdateFromCbor(const cbor::Value& v, ModuleUpdatePayload* out);

// §5.5 SIGNAL — opaque application bytes; §5.7 PEER_HELLO / PEER_BYE — {peer}.
cbor::Value SignalToCbor(const std::string& opaque_bytes);
bool SignalFromCbor(const cbor::Value& v, std::string* out);
cbor::Value PeerAnnounceToCbor(const PeerRef& peer);
bool PeerAnnounceFromCbor(const cbor::Value& v, PeerRef* out);

// ===========================================================================
// §6.3 — Injected cryptographic primitives
// ===========================================================================
//
// Resolved per build world (OpenSSL in the harness, //crypto in the browser).
// Byte-oriented: keys, digests, points and ciphertexts are raw `std::string`s.
struct SyncCrypto {
  // Raw 32-byte SHA-256 of |data|.
  std::function<std::string(const std::string& data)> sha256;
  // Raw 64-byte SHA-512 of |data|.
  std::function<std::string(const std::string& data)> sha512;
  // Raw 32-byte HMAC-SHA256 of |data| under |key|.
  std::function<std::string(const std::string& key, const std::string& data)>
      hmac_sha256;
  // X25519 scalar multiplication: 32-byte |scalar| by the point whose
  // u-coordinate is the 32-byte |u|. Returns the 32-byte result, or "" on error.
  std::function<std::string(const std::string& scalar, const std::string& u)>
      x25519;
  // AES-128-GCM seal: 16-byte |key|, 12-byte |nonce|, |aad|, |plaintext| →
  // ciphertext with the 16-byte tag appended. Returns false on failure.
  std::function<bool(const std::string& key,
                     const std::string& nonce,
                     const std::string& aad,
                     const std::string& plaintext,
                     std::string* out)>
      aes128gcm_seal;
  // AES-128-GCM open: the inverse. Returns false on authentication failure.
  std::function<bool(const std::string& key,
                     const std::string& nonce,
                     const std::string& aad,
                     const std::string& ciphertext,
                     std::string* out)>
      aes128gcm_open;
  // Ed25519 verify: 32-byte |public_key|, |message|, 64-byte |signature|.
  std::function<bool(const std::string& public_key,
                     const std::string& message,
                     const std::string& signature)>
      ed25519_verify;
  // Ed25519 sign: 32-byte |seed| (RFC 8032 private key), |message| → 64-byte
  // signature. MAY be null where signing is not needed.
  std::function<std::string(const std::string& seed, const std::string& message)>
      ed25519_sign;
};

// The X25519 base point u = 9 (§6.3.3): 0x09 followed by 31 zero bytes.
std::string X25519BasePoint();

// ===========================================================================
// §6.3.1 group_id / §6.3.2 cipher suite
// ===========================================================================

// The single MLS cipher suite and protocol version pinned by §6.3.2:
// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001) and mls10 (0x0001).
inline constexpr uint16_t kMlsCipherSuite = 0x0001;
inline constexpr uint16_t kMlsProtocolVersion = 0x0001;

// The exporter label pinned by §6.3.9.
inline constexpr char kSpaceFrameExporterLabel[] = "lw-sync space frame";

// §6.3.1 — the MLS group_id is the 32-byte SHA-256 digest whose lowercase hex is
// the authority of the `space://<sha256-hex>` URI. Returns false if |space_uri|
// is not a `space://` URI with a 64-char lowercase-hex authority.
bool GroupIdFromSpaceUri(const std::string& space_uri, std::string* group_id_32);

// ===========================================================================
// §6.3.3 — did:key(Ed25519) → X25519, and the §6.3.4-check-4 binding
// ===========================================================================

// The X25519 private scalar: clamp(SHA-512(ed25519_seed)[0..32)) per RFC 7748
// §5. |ed25519_seed| is the 32-byte Ed25519 private key (RFC 8032 seed).
std::string DeriveX25519PrivateScalar(const std::string& ed25519_seed_32,
                                      const SyncCrypto& crypto);

// The X25519 public key from a private scalar: X25519(scalar, 9) (§6.3.3 step 3).
std::string DeriveX25519Public(const std::string& x25519_private_32,
                               const SyncCrypto& crypto);

// The Edwards→Montgomery public-key map u = (1+y)/(1−y) mod p (§6.3.3 step 3,
// RFC 7748 §4.1) — pure field arithmetic, no injected primitive. Lets a member
// derive a *peer's* X25519 encryption key from only the peer's Ed25519 public
// key. Returns false for a non-canonical input or the excluded y = 1 point.
bool Ed25519PubToX25519Pub(const std::string& ed25519_public_32,
                           std::string* x25519_public_32);

// §6.3.4 check 4 — a leaf's `encryption_key` MUST equal the X25519 key derived
// from the credential's did:key. True iff |leaf_encryption_key_32| equals
// Ed25519PubToX25519Pub(|credential_ed25519_public_32|).
bool VerifyEncryptionKeyBinding(const std::string& credential_ed25519_public_32,
                                const std::string& leaf_encryption_key_32);

// ===========================================================================
// §6.3.9 — Epoch key schedule and wire-frame key derivation
// ===========================================================================

// HKDF-Expand(PRK, info, L) with HMAC-SHA256 (RFC 5869 §2.3). Returns "" if
// |length| exceeds 255*32.
std::string HkdfExpandSha256(const std::string& prk,
                             const std::string& info,
                             size_t length,
                             const SyncCrypto& crypto);

// MLS ExpandWithLabel (RFC 9420 §5.2): HKDF-Expand(secret, KDFLabel, length)
// where KDFLabel = I2OSP(length,2) ‖ vec("MLS 1.0 "+label) ‖ vec(context), and
// vec(x) is x prefixed by its length as an RFC 9420 §2.1.2 (QUIC) varint.
std::string ExpandWithLabel(const std::string& secret,
                            const std::string& label,
                            const std::string& context,
                            size_t length,
                            const SyncCrypto& crypto);

// MLS DeriveSecret (RFC 9420 §8.1): ExpandWithLabel(secret, label, "", 32).
std::string DeriveSecret(const std::string& secret,
                         const std::string& label,
                         const SyncCrypto& crypto);

// MLS-Exporter (RFC 9420 §8.5):
//   ExpandWithLabel(DeriveSecret(exporter_secret, label), "exported",
//                   SHA-256(context), length).
// NB: Spec 09 §6.3.9 inlines a simplified formula that omits the DeriveSecret /
// "exported" wrapping; that parenthetical contradicts the §8.5 definition it
// cites. The RFC form is implemented here (it is what a real RFC 9420 engine's
// exporter yields, which the exporter seam must match) and the draft is amended
// to match — see SPEC_COMPLIANCE.md.
std::string MlsExporter(const std::string& exporter_secret,
                        const std::string& label,
                        const std::string& context,
                        size_t length,
                        const SyncCrypto& crypto);

// §6.3.9 — the 32-byte space traffic secret for the current epoch:
//   MLS-Exporter("lw-sync space frame", spaceUri_bytes, 32).
std::string DeriveSpaceTrafficSecret(const std::string& exporter_secret,
                                     const std::string& space_uri,
                                     const SyncCrypto& crypto);

// §6.3.9 — the AEAD key/nonce for the epoch, derived from the space traffic
// secret: key = ExpandWithLabel(sts,"key","",16); nonce = ExpandWithLabel(
// sts,"nonce","",12).
struct FrameKeys {
  std::string key;    // 16-byte AES-128 key
  std::string nonce;  // 12-byte base nonce
};
FrameKeys DeriveFrameKeys(const std::string& space_traffic_secret,
                          const SyncCrypto& crypto);

// Convenience: exporter_secret + spaceUri → FrameKeys, in one call.
FrameKeys DeriveFrameKeysFromExporter(const std::string& exporter_secret,
                                      const std::string& space_uri,
                                      const SyncCrypto& crypto);

// ===========================================================================
// §6.3.10 — Message encryption
// ===========================================================================

// The per-frame nonce N = base_nonce XOR I2OSP(seq, 12) (§6.3.10 step 3).
std::string FrameNonce(const std::string& base_nonce_12, uint64_t seq);

// The AEAD associated data A (§6.3.10 step 4): the deterministic CBOR encoding
// of [ type, spaceUri, from.did, from.sessionId,
//      (to==null ? null : [to.did, to.sessionId]), epoch, seq ].
std::string FrameAad(FrameType type,
                     const std::string& space_uri,
                     const PeerRef& from,
                     const std::optional<PeerRef>& to,
                     uint64_t epoch,
                     uint64_t seq);

// The §6.3.10 encrypted envelope: the routing header in the clear plus
// {epoch, seq, ct}. |ct| includes the 16-byte GCM tag.
struct EncryptedFrame {
  FrameType type = FrameType::kSignal;
  std::string space_uri;
  PeerRef from;
  std::optional<PeerRef> to;
  uint64_t epoch = 0;
  uint64_t seq = 0;
  std::string ct;
};

// Seal |plain|'s payload under |keys| for (epoch, seq) (§6.3.10 steps 1–5). The
// routing header is copied from |plain|. Returns false if the AEAD seal fails.
bool SealFrame(const FrameKeys& keys,
               const WireFrame& plain,
               uint64_t epoch,
               uint64_t seq,
               const SyncCrypto& crypto,
               EncryptedFrame* out);

// Open |enc| under |keys| (§6.3.10 decryption). Recomputes N and A from the
// received header; on AEAD failure returns false (the frame MUST be discarded).
// On success |out| carries the routing header and the recovered payload.
bool OpenFrame(const FrameKeys& keys,
               const EncryptedFrame& enc,
               const SyncCrypto& crypto,
               WireFrame* out);

// Deterministic CBOR codec for the encrypted envelope (the map
// {type, spaceUri, from, to, enc:{epoch, seq, ct}}).
std::string EncodeEncryptedFrame(const EncryptedFrame& frame);
bool DecodeEncryptedFrame(const std::string& in, EncryptedFrame* out);

// ===========================================================================
// §8 — Merge semantics (OR-Set)
// ===========================================================================

// §8.1 — the Observed-Remove Set. Triple identity is the canonical N-Triples
// line (SerializeTripleNt). A triple is present iff it has at least one add-tag
// that has not been removed. Applying diffs is commutative, associative and
// idempotent, so any delivery order converges.
class OrSet {
 public:
  // Applies one diff: each addition adds tag = |diff.revision| for its triple;
  // each removal tombstones the named add-tags for its triple.
  void ApplyDiff(const DiffWire& diff);

  // Lower-level ops (the provider uses these when it already has identities).
  void Add(const std::string& triple_id, const std::string& tag);
  void Remove(const std::string& triple_id, const std::string& tag);

  bool Contains(const std::string& triple_id) const;
  std::vector<std::string> Members() const;  // sorted triple identities
  size_t Size() const;

 private:
  // triple identity → live add-tags, and → tombstoned add-tags.
  std::map<std::string, std::set<std::string>> added_;
  std::map<std::string, std::set<std::string>> removed_;
};

// §8.2 — a chain-root diff has no dependencies. It is only legal as the first
// diff after a SNAPSHOT or the first diff for a graph; receivers MUST reject a
// chain-root whose graph already carries unrelated diffs.
bool IsChainRoot(const DiffWire& diff);
bool AcceptChainRoot(const DiffWire& diff, bool graph_has_unrelated_diffs);

// §8.4 — concurrent flow-state transitions tie-break on the reifier hash:
// the lexicographically smaller hash wins. Returns <0 if |a| wins, >0 if |b|
// wins, 0 if equal.
int CompareReifierHash(const std::string& hash_a, const std::string& hash_b);
const std::string& FlowStateWinner(const std::string& hash_a,
                                   const std::string& hash_b);

// ===========================================================================
// §9 — Snapshot promotion
// ===========================================================================

// §9.2 — the default promotion threshold (diffs per graph since last snapshot).
inline constexpr uint32_t kDefaultSnapshotThreshold = 1000;

// True when a graph's diff chain has reached the promotion threshold.
bool ShouldPromote(uint32_t diffs_since_snapshot,
                   uint32_t threshold = kDefaultSnapshotThreshold);

}  // namespace default_sync
}  // namespace living_web

#endif  // CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_MODULE_H_
