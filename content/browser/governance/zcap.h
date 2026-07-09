// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// ZCAP-LD canonicalisation core for the Graph Capability Framework (Spec 04).
//
// This is the Chromium-independent core shared by the standalone harness
// (standalone/capability_provider.h) and the browser-process governance service
// (content/browser/governance/governance_backend.cc), so the bytes a delegation
// proof is signed over — and the immutable-caveats / actions-subset attenuation
// decisions of §8 — never diverge between the two. It defines:
//
//   * the `governance://` and `zcap://` predicate vocabulary (§4, §16) and the
//     `urn:living-web:zcap:BootstrapRoot` sentinel (§4.3);
//   * the delegation-proof pre-image (§4.5.3 amendment): the exact byte string a
//     ZCAP's proofValue signs, so a tamper of any signed field (invoker, parent,
//     actions, resource, caveats) invalidates the signature;
//   * the framework-core action set (§4.5.4) and the actions-subset test (§8);
//   * a dependency-free JSON scanner sufficient for the `caveats` array — element
//     splitting for the §8 immutable-caveats check and targeted field extraction
//     for the core `expiry` caveat (§9.2).
//
// Like did_graph.cc and rdf_serialization.cc, this translation unit has NO
// Chromium dependencies (only the C++ standard library) so it is shared verbatim
// between the browser service and the standalone harness.

#ifndef CONTENT_BROWSER_GOVERNANCE_ZCAP_H_
#define CONTENT_BROWSER_GOVERNANCE_ZCAP_H_

#include <optional>
#include <string>
#include <vector>

namespace living_web {

// ---- governance:// predicates (§4, §16) -----------------------------------
inline constexpr char kGovEntryType[] = "governance://entry_type";
inline constexpr char kGovConstraintKind[] = "governance://constraint_kind";
inline constexpr char kGovHasConstraint[] = "governance://has_constraint";
inline constexpr char kGovRootCapability[] = "governance://root_capability";
inline constexpr char kGovEnforcementMode[] = "governance://enforcement_mode";
inline constexpr char kGovCapabilityPredicates[] =
    "governance://capability_predicates";
inline constexpr char kGovHasZcap[] = "governance://has_zcap";
inline constexpr char kGovRevokesCapability[] =
    "governance://revokes_capability";

// The object value written by `governance://entry_type` for a constraint (§4.1).
inline constexpr char kGovConstraintEntryType[] = "governance://constraint";

// The natively-recognised constraint kind (§4.1, §4.5). All others plug in
// (§9.3) and fail closed when unregistered (§13.8).
inline constexpr char kConstraintKindCapability[] = "capability";

// ---- zcap:// predicates (§4.5.3 amendment) ---------------------------------
// The draft carries the ZCAP-LD document flattened into triples. §4.5.3/§4.3
// give the field set with a `zcap = https://w3id.org/zcap/v1#` CURIE prefix,
// while §15.1's worked example writes `zcap://invoker` etc. The substrate's
// uniform predicate convention is the `scheme://` form (prov://, did://,
// group://, context://), so the flattened representation is pinned to `zcap://`
// (SPEC_COMPLIANCE amendment 04/§4.5.3).
inline constexpr char kRdfType[] =
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
inline constexpr char kZcapDelegation[] = "zcap://Delegation";
inline constexpr char kZcapInvoker[] = "zcap://invoker";
inline constexpr char kZcapParentCapability[] = "zcap://parentCapability";
inline constexpr char kZcapActions[] = "zcap://actions";
inline constexpr char kZcapResource[] = "zcap://resource";
inline constexpr char kZcapCaveats[] = "zcap://caveats";
inline constexpr char kZcapProofValue[] = "zcap://proofValue";
inline constexpr char kZcapProofPurpose[] = "zcap://proofPurpose";
inline constexpr char kZcapProofMethod[] = "zcap://proofMethod";
inline constexpr char kZcapCreated[] = "zcap://created";

// The §4.3 bootstrap sentinel: a capability whose parentCapability is this value
// is a constitutionalised root; the chain walk (§7 step 6.5.4) terminates there.
inline constexpr char kBootstrapRoot[] = "urn:living-web:zcap:BootstrapRoot";

// The proofPurpose every delegation and root capability carries (§4.3, §4.5.3).
inline constexpr char kProofPurposeCapabilityDelegation[] =
    "capabilityDelegation";

// ---- framework-core actions (§4.5.4) ---------------------------------------
inline constexpr char kActionCreateLink[] = "createLink";
inline constexpr char kActionRemoveLink[] = "removeLink";
inline constexpr char kActionUpdateGovernance[] = "updateGovernance";
inline constexpr char kActionUpdateDIDDocument[] = "updateDIDDocument";
inline constexpr char kActionDelegateCapability[] = "delegateCapability";
inline constexpr char kActionMountContext[] = "mountContext";
inline constexpr char kActionForkGraph[] = "forkGraph";
inline constexpr char kActionAnnounceFork[] = "announceFork";

// The default action set a root capability is minted with (§4.3, §15.1): the
// framework-core actions only. Extension actions (e.g. updateSHACL from
// SHAPE-VALIDATION, updateFlow from GRAPH-FLOWS) are NOT granted by default and
// must be delegated explicitly (SPEC_COMPLIANCE amendment 04/§4.3 — the draft's
// §4.3 example erroneously lists updateSHACL, contradicting §4.5.4 and §15.1).
std::vector<std::string> DefaultRootActions();

// ---- delegation-proof pre-image (§4.5.3 amendment) -------------------------

// The signed fields of a ZCAP delegation. `caveats` is the verbatim JSON string
// carried by `zcap://caveats` ("" when the capability has no caveats).
struct ZcapProofFields {
  std::string id;
  std::string invoker;
  std::string parent_capability;
  std::string actions;  // verbatim comma-separated string
  std::string resource;
  std::string caveats;  // verbatim JSON array literal, or "" if absent
  std::string proof_purpose;
  std::string created;  // RFC 3339
};

// The exact byte string a delegation's `zcap://proofValue` signs: a versioned
// tag followed by every signed field, one per line (LF-joined, no trailer). DIDs,
// IRIs and the RFC-3339 timestamp contain no LF; `actions` is comma-separated
// tokens; `caveats` is compact JSON whose string members escape control
// characters — so the field boundaries are unambiguous. The caller applies
// SHA-256 to the returned string and signs the digest with `signRaw`
// (mirroring Spec 02 §3.2.1). Verifying recomputes this pre-image and checks the
// Ed25519 signature against the key named by `zcap://proofMethod`.
std::string BuildDelegationProofPreimage(const ZcapProofFields& fields);

// ---- actions (§4.5.4, §8) --------------------------------------------------

// Splits a comma-separated actions string into trimmed, non-empty tokens.
std::vector<std::string> ParseActions(const std::string& raw);

// Joins actions with ',' (no spaces) — the canonical stored form.
std::string JoinActions(const std::vector<std::string>& actions);

// True iff |action| is one of the comma-separated tokens in |actions_raw|.
bool ActionInSet(const std::string& action, const std::string& actions_raw);

// §8 actions attenuation: every token of |child_raw| is a token of |parent_raw|
// (child.actions ⊆ parent.actions).
bool ActionsSubset(const std::string& child_raw, const std::string& parent_raw);

// ---- caveats JSON (§8 immutable-caveats, §9.2 expiry) ----------------------

// Splits a JSON array's top-level elements into their verbatim substrings.
// Returns false if |json| is not a well-formed JSON array. An empty array yields
// an empty vector and true. Nested objects/arrays and escaped strings inside
// elements are preserved intact.
bool SplitJsonArray(const std::string& json, std::vector<std::string>* out);

// The value of a top-level string field of a JSON object, unescaped; nullopt if
// the object is malformed, the field is absent, or its value is not a string.
std::optional<std::string> JsonStringField(const std::string& object,
                                            const std::string& field);

// The verbatim raw substring of a top-level field's value (object, array,
// string, or primitive); nullopt if malformed or absent.
std::optional<std::string> JsonRawField(const std::string& object,
                                        const std::string& field);

// §8 immutable-caveats attenuation: every caveat element present on the parent
// appears byte-identically among the child's caveat elements. An empty/absent
// parent caveat set trivially satisfies this; a malformed array fails closed.
bool CaveatsAttenuationOk(const std::string& parent_raw,
                          const std::string& child_raw);

}  // namespace living_web

#endif  // CONTENT_BROWSER_GOVERNANCE_ZCAP_H_
