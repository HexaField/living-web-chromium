// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// did:graph codec and DID-document model for the Decentralised Group Identity
// specification (Spec 03). The `did:graph` method-specific identifier uses the
// SAME multibase Ed25519 encoding as did:key (§4.1) — only the method prefix
// differs — so this module reuses the shared did:key codec
// (content/browser/did/did_key_codec.*) for the byte-level work and adds:
//
//   * the did:graph derive/parse pair and a method-agnostic Ed25519 parser
//     (a reifier author or DID-document controller may be did:key OR did:graph);
//   * the DID-document predicate IRIs (§16) and capability-section vocabulary;
//   * the in-memory DID-document model (§4.4) projected from a host graph's
//     did://* triples, including the [[DID-CORE]] JSON-LD projection §4.4
//     requires.
//
// Like did_key_codec, this translation unit has NO Chromium dependencies (only
// the C++ standard library plus the did:key codec) so it is shared verbatim
// between the browser-process group service and the standalone harness.

#ifndef CONTENT_BROWSER_DID_DID_GRAPH_H_
#define CONTENT_BROWSER_DID_DID_GRAPH_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace living_web {

// ---- DID-document membership + capability-section predicates (§4.4, §16) ----
inline constexpr char kDidVerificationMethod[] = "did://verificationMethod";
inline constexpr char kDidCapabilityInvocation[] = "did://capabilityInvocation";
inline constexpr char kDidCapabilityDelegation[] = "did://capabilityDelegation";
inline constexpr char kDidAssertionMethod[] = "did://assertionMethod";
inline constexpr char kDidAuthentication[] = "did://authentication";

// ---- per-verification-method attribute predicates (§4.4, §16) ----
inline constexpr char kDidVmType[] = "did://verificationMethod/type";
inline constexpr char kDidVmController[] = "did://verificationMethod/controller";
inline constexpr char kDidVmPublicKeyMultibase[] =
    "did://verificationMethod/publicKeyMultibase";

// ---- deactivation (§4.9, §16) ----
inline constexpr char kDidDeactivated[] = "did://deactivated";

// ---- governed DID-document update actions (§4.6, §16) ----
inline constexpr char kDidDocAddMethod[] = "did-document://add-method";
inline constexpr char kDidDocRemoveMethod[] = "did-document://remove-method";
inline constexpr char kDidDocGrantSection[] = "did-document://grant-section";
inline constexpr char kDidDocRevokeSection[] = "did-document://revoke-section";

// ---- binding + seed + metadata predicates (§4.3, §4.5, §6.1, §16) ----
inline constexpr char kGroupDidIdentity[] = "group://didIdentity";
inline constexpr char kGroupSyncModule[] = "group://syncModule";
inline constexpr char kGroupForkedFrom[] = "group://forkedFrom";
inline constexpr char kGroupForkedAtRevision[] = "group://forkedAtRevision";
inline constexpr char kGroupForkedTo[] = "group://forkedTo";
inline constexpr char kGroupName[] = "group://name";
inline constexpr char kGroupDescription[] = "group://description";
inline constexpr char kGroupAvatar[] = "group://avatar";
inline constexpr char kGroupCreated[] = "group://created";
inline constexpr char kGroupCreator[] = "group://creator";
inline constexpr char kGroupParticipationOpen[] = "group://participation_open";
inline constexpr char kGroupParticipationRequiresCredential[] =
    "group://participation_requires_credential";
inline constexpr char kGroupParticipationMaxCount[] =
    "group://participation_max_count";

// ---- participation predicates (§6.2, §16) ----
inline constexpr char kContextParticipatesIn[] = "context://participates_in";
inline constexpr char kContextAcceptsParticipation[] =
    "context://accepts_participation";

// The Ed25519 verificationMethod type token used throughout (§4.4).
inline constexpr char kEd25519VerificationKey2020[] =
    "Ed25519VerificationKey2020";

// The four capability sections a verification method may be referenced from
// (§5.1). There is deliberately no aggregate/threshold section — a signature by
// any current method in the relevant section is a signature by the DID.
enum class DIDCapabilitySection {
  kCapabilityInvocation,
  kCapabilityDelegation,
  kAssertionMethod,
  kAuthentication,
};

// The did:// membership predicate recording that a method is in |section|.
const char* SectionPredicate(DIDCapabilitySection section);

// The DIDCapabilitySection IDL/wire token, e.g. "capabilityInvocation".
const char* SectionToken(DIDCapabilitySection section);

// Parse a DIDCapabilitySection wire token; nullopt if unrecognised.
std::optional<DIDCapabilitySection> SectionFromToken(const std::string& token);

namespace did_graph {

inline constexpr char kMethodPrefix[] = "did:graph:";

// did:graph:z || base58btc(0xed01 || pk), mirroring did:key (§4.1). |public_key|
// MUST be 32 bytes; nullopt otherwise.
std::optional<std::string> DeriveDidGraphEd25519(
    const std::vector<uint8_t>& public_key);

// Parses a "did:graph:z..." URI (a #fragment / ?query / /path is ignored for key
// extraction), validates the Ed25519 multicodec prefix, and returns the raw
// 32-byte public key. nullopt on any malformation.
std::optional<std::vector<uint8_t>> ParseDidGraphEd25519(const std::string& did);

// True iff |did| begins with the "did:graph:" method prefix.
bool IsDidGraph(const std::string& did);

}  // namespace did_graph

// Parses a did:key OR did:graph Ed25519 identifier into its raw 32-byte public
// key. Used wherever an author/controller may be of either method (reifier
// signature verification, DID-document controllers). nullopt on any other input.
std::optional<std::vector<uint8_t>> ParseAnyDidEd25519(const std::string& did);

// Decodes a `publicKeyMultibase` value (e.g. "z6Mk...") into the raw 32-byte
// Ed25519 key, validating the 0xed01 multicodec prefix. nullopt on malformation.
std::optional<std::vector<uint8_t>> DecodePublicKeyMultibase(
    const std::string& multibase);

// Strips any #fragment / ?query / /path from a DID URL, returning the bare DID.
// (A did:key / did:graph method-specific id contains none of these delimiters,
// so the first occurrence marks the end of the bare DID.)
std::string BareDid(const std::string& did_url);

// ---- DID-document model (§4.4) ---------------------------------------------

// One verificationMethod entry. |id| is "<did>#<publicKeyMultibase>" (§4.4, with
// the fragment being the method's own multibase key — see SPEC_COMPLIANCE
// amendment 03/§4.4).
struct VerificationMethod {
  std::string id;
  std::string type = kEd25519VerificationKey2020;
  std::string controller;
  std::string public_key_multibase;

  bool operator==(const VerificationMethod& o) const {
    return id == o.id && type == o.type && controller == o.controller &&
           public_key_multibase == o.public_key_multibase;
  }
};

// A resolved did:graph DID document (§4.4): the projection of a host graph's
// did://* triples for a single DID. The capability sections carry verification-
// method ids that MUST also appear in |verification_method|.
struct DidDocument {
  std::string id;
  std::vector<VerificationMethod> verification_method;
  std::vector<std::string> capability_invocation;
  std::vector<std::string> capability_delegation;
  std::vector<std::string> assertion_method;
  std::vector<std::string> authentication;
  bool deactivated = false;
  // "local" | "mounted-read" | "external" | "cached" (§4.7).
  std::string trust_level;

  const std::vector<std::string>& Section(DIDCapabilitySection section) const;
  std::vector<std::string>& Section(DIDCapabilitySection section);

  // True iff |method_id| is currently referenced by |section|.
  bool InSection(DIDCapabilitySection section,
                 const std::string& method_id) const;

  // The verificationMethod entry with |method_id|, or nullptr.
  const VerificationMethod* FindMethod(const std::string& method_id) const;

  // The number of distinct methods referenced by |section| (the brick-state
  // guard of §5.4 counts capabilityDelegation membership).
  size_t SectionSize(DIDCapabilitySection section) const;

  // Projects this document to a [[DID-CORE]] JSON-LD DID document (§4.4).
  std::string ToJsonLd() const;
};

}  // namespace living_web

#endif  // CONTENT_BROWSER_DID_DID_GRAPH_H_
