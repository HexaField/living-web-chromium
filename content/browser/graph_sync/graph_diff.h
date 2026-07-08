// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GraphDiff identity + sync-space derivation core for the Graph Synchronisation
// Protocol (Spec 05).
//
// This is the Chromium-independent core shared by the standalone harness
// (standalone/sync_provider.h) and the browser-process sync backend
// (content/browser/graph_sync/sync_backend.cc), so the bytes a diff's `revision`
// and `commitId` are hashed over — and the input a `space://` URI is derived
// from — never diverge between the two build worlds. It defines:
//
//   * the sync predicate vocabulary (§4.3, §7, group://syncModule per
//     GROUP-IDENTITY §4.5) and the topology / mount-mode / sync-state enums with
//     their wire tokens (§5.5, §6.2, §7.2);
//   * the `revision` and `commitId` pre-images (§5.2.2, pinned exactly by
//     SPEC_COMPLIANCE amendment 05/§5.2.2.1): the exact byte strings a diff is
//     content-addressed by, so a tamper of any bound field (triples,
//     dependencies, author, timestamp, leaf capability) changes the identity;
//   * the `sort(dependencies)` ordering (§5.2.1);
//   * the sync-space derivation input (§7.3) for the four topologies.
//
// Like did_graph.cc, rdf_serialization.cc and zcap.cc, this translation unit has
// NO Chromium dependencies (only the C++ standard library) — in particular it
// performs no hashing itself, because the SHA-256 primitive resolves to a
// different header in the two worlds (standalone/crypto_sha2.h vs //crypto). The
// caller applies `crypto::SHA256HashString` to the returned pre-images and
// `ToLowerHex` to the digest; both helpers are identical across worlds, so the
// content addresses are byte-identical.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_GRAPH_DIFF_H_
#define CONTENT_BROWSER_GRAPH_SYNC_GRAPH_DIFF_H_

#include <string>
#include <vector>

// The sync predicate vocabulary this spec keys off — `group://syncModule`
// (§4.3, §6.1, §6.2) and `context://participates_in` (§7.3, §16.5) — is defined
// once by the Spec 03 DID-document model and reused verbatim here rather than
// re-declared, so the two translation units cannot drift (and cannot collide
// when both headers land in the same TU). did_graph.h is likewise pure-std.
#include "content/browser/did/did_graph.h"

namespace living_web {

// ---- sync predicate vocabulary (§4.3, §7) ----------------------------------

// The scheme of a derived sync-space identifier (§7.3).
inline constexpr char kSpaceScheme[] = "space://";

// ---- topology (§7.2) -------------------------------------------------------

enum class SpaceTopology {
  kUnified,
  kPrivacyTiered,
  kFullyPartitioned,
  kCustom,
};

inline const char* SpaceTopologyToken(SpaceTopology t) {
  switch (t) {
    case SpaceTopology::kUnified:
      return "unified";
    case SpaceTopology::kPrivacyTiered:
      return "privacy-tiered";
    case SpaceTopology::kFullyPartitioned:
      return "fully-partitioned";
    case SpaceTopology::kCustom:
      return "custom";
  }
  return "unified";
}

inline SpaceTopology SpaceTopologyFromToken(const std::string& t) {
  if (t == "privacy-tiered")
    return SpaceTopology::kPrivacyTiered;
  if (t == "fully-partitioned")
    return SpaceTopology::kFullyPartitioned;
  if (t == "custom")
    return SpaceTopology::kCustom;
  return SpaceTopology::kUnified;
}

// ---- mount mode (§6.2) -----------------------------------------------------

enum class MountMode { kRead, kWrite, kGovernance };

inline const char* MountModeToken(MountMode m) {
  switch (m) {
    case MountMode::kRead:
      return "read";
    case MountMode::kWrite:
      return "write";
    case MountMode::kGovernance:
      return "governance";
  }
  return "read";
}

inline MountMode MountModeFromToken(const std::string& t) {
  if (t == "write")
    return MountMode::kWrite;
  if (t == "governance")
    return MountMode::kGovernance;
  return MountMode::kRead;  // §6.2 default
}

// ---- sync state (§5.5) -----------------------------------------------------

enum class GraphSyncState {
  kIdle,
  kResolving,
  kConnecting,
  kSyncing,
  kSynced,
  kError,
};

inline const char* GraphSyncStateToken(GraphSyncState s) {
  switch (s) {
    case GraphSyncState::kIdle:
      return "idle";
    case GraphSyncState::kResolving:
      return "resolving";
    case GraphSyncState::kConnecting:
      return "connecting";
    case GraphSyncState::kSyncing:
      return "syncing";
    case GraphSyncState::kSynced:
      return "synced";
    case GraphSyncState::kError:
      return "error";
  }
  return "idle";
}

// ---- hex ------------------------------------------------------------------

// Lowercase-hex encoding of arbitrary bytes. Shared so that `revision`,
// `commitId` and the `space://` suffix format the SHA-256 digest identically in
// both build worlds (mirrors the `graph://` content-address hex of Spec 02 §5.2).
std::string ToLowerHex(const std::string& bytes);

// ---- dependencies (§5.2.1) -------------------------------------------------

// The canonical ordering of a diff's `dependencies` (DAG heads) bound into
// `revision`: lexicographic ascending over the revision hex strings, with
// duplicates removed. A stable order is REQUIRED so two peers that observed the
// same head set compute the same `revision`.
std::vector<std::string> SortDependencies(const std::vector<std::string>& deps);

// ---- revision / commitId pre-images (§5.2.2, amendment 05/§5.2.2.1) ---------

// The exact byte string SHA-256'd to produce `revision` — the *triple-set*
// identity (§5.2.2). Length-framed and domain-separated so the field boundaries
// are unambiguous even though the canonical N-Quads blocks contain LFs (the
// draft's bare `||` concatenation is pinned to this construction by
// SPEC_COMPLIANCE amendment 05/§5.2.2.1). |canonical_additions| and
// |canonical_removals| are the rdfc-1.0 canonical N-Quads of the additions and
// removals (triples-with-reifiers), each possibly empty. |sorted_dependencies|
// MUST already be SortDependencies()-ordered.
//
// Layout:
//   "living-web/sync/revision/v1" LF
//   graphDid LF
//   decimal(len(canonical_additions)) LF canonical_additions
//   decimal(len(canonical_removals))  LF canonical_removals
//   decimal(count(sorted_dependencies)) LF
//   ( dep LF ) *                       // each dependency revision, in order
std::string BuildRevisionPreimage(
    const std::string& graph_did,
    const std::string& canonical_additions,
    const std::string& canonical_removals,
    const std::vector<std::string>& sorted_dependencies);

// The exact byte string SHA-256'd to produce `commitId` — the *commit* identity
// (§5.2.2): it binds `revision` to the author, timestamp, and the leaf ZCAP id
// that authorises the commit (`capabilityProof.chain[0]`, or "" when the proof
// is omitted). None of these fields contain LF, so a versioned LF-joined framing
// is unambiguous.
//
// Layout:
//   "living-web/sync/commit/v1" LF
//   revision LF
//   author LF
//   timestamp LF
//   leaf_zcap_id                       // no trailing LF; may be empty
std::string BuildCommitIdPreimage(const std::string& revision,
                                  const std::string& author,
                                  const std::string& timestamp,
                                  const std::string& leaf_zcap_id);

// The message bytes a diff's `signature` is produced over (§5.2.2): the UTF-8
// encoding of the lowercase-hex `commitId`. `commitId` is already a SHA-256
// digest, so it is signed directly rather than re-hashed (pinned by
// SPEC_COMPLIANCE amendment 05/§5.2.2.1). The caller feeds the returned bytes to
// signRaw (Ed25519) and verifies with ed25519_verify.
inline std::string BuildSignatureMessage(const std::string& commit_id) {
  return commit_id;
}

// ---- sync-space derivation (§7.3) ------------------------------------------

// The derivation input SHA-256'd to produce a `space://<sha256-hex>` URI (§7.3).
// The topology selects the shape:
//   unified          -> "lwsync:unified:"   + namespace_id
//   privacy (public) -> "lwsync:public:"    + namespace_id     (|restricted|=false)
//   privacy (restr.) -> "lwsync:dedicated:" + graph_did        (|restricted|=true)
//   fully-partitioned-> "lwsync:dedicated:" + graph_did
//   custom           -> "lwsync:named:"     + custom_name
// |namespace_id| is typically the DID of the root graph the graph participates
// in (§7.3); it falls back to |graph_did| when the graph names no root.
std::string BuildSpaceDerivationInput(SpaceTopology topology,
                                      bool restricted,
                                      const std::string& namespace_id,
                                      const std::string& graph_did,
                                      const std::string& custom_name);

}  // namespace living_web

#endif  // CONTENT_BROWSER_GRAPH_SYNC_GRAPH_DIFF_H_
