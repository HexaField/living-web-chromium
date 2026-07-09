// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GovernanceBackend — the browser-process port of the Graph Capability Framework
// (Spec 04). A faithful C++ port of living_web::GovernanceEngine
// (standalone/capability_provider.h) onto the browser cores content::GraphBackend
// (the Spec 02 host graph authority is constituted over) and content::
// DIDKeyProvider (which stores the credentials whose keys sign delegations). The
// two ports share the Chromium-independent byte-critical core content/browser/
// governance/zcap.{h,cc} — the delegation-proof pre-image, the actions-subset and
// immutable-caveats attenuation tests, and the caveat-JSON scanner — so the bytes
// a proof signs, and every attenuation decision, are identical between the
// standalone conformance harness and this backend.
//
// Authority is *constituted*: every graph mints a root capability at creation
// (§4.3) whose parent is the BootstrapRoot sentinel, delegations attenuate
// downward (§8), and a write is accepted only if the author holds a valid
// capability chain terminating at the graph's own root (§7). Three enforcement
// modes (§5) select whether capability checks are skipped (open), advisory
// (announced), or mandatory (enforced). Non-capability constraint kinds and
// non-core caveat types plug in (§9.3) and fail closed when unregistered (§13.8,
// §13.9).
//
// GovernanceBackend is a per-realm object (like living_web::GovernanceEngine, it
// carries the realm-wide plug-in registry and operates on any GraphBackend* W
// passed to each call); PersonalGraphManager owns one and shares it with every
// PersonalGraphHost so the §11 renderer surface and the §2 enforcement hook run
// against a single registry.

#ifndef CONTENT_BROWSER_GOVERNANCE_GOVERNANCE_BACKEND_H_
#define CONTENT_BROWSER_GOVERNANCE_GOVERNANCE_BACKEND_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/governance/zcap.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/rdf_serialization.h"

namespace content {

// ---- enforcement mode (§5.1) -----------------------------------------------

enum class EnforcementMode { kOpen, kAnnounced, kEnforced };

inline std::string EnforcementModeToken(EnforcementMode m) {
  switch (m) {
    case EnforcementMode::kOpen: return "open";
    case EnforcementMode::kAnnounced: return "announced";
    case EnforcementMode::kEnforced: return "enforced";
  }
  return "open";
}

inline EnforcementMode EnforcementModeFromToken(const std::string& t) {
  if (t == "announced") return EnforcementMode::kAnnounced;
  if (t == "enforced") return EnforcementMode::kEnforced;
  return EnforcementMode::kOpen;  // §5.1 default
}

// ---- §11 API result / info types -------------------------------------------

// The §11 GovernanceValidationResult dictionary.
struct GovernanceValidationResult {
  bool allowed = true;
  std::string rejected_by;      // constraint id (empty when allowed)
  std::string constraint_kind;  // "capability" | <plug-in kind>
  std::string reason;
  std::string mode;             // current enforcement mode
};

// The §11 GraphConstraint dictionary. |properties| carries every defining triple
// of the constraint subject except entry_type/constraint_kind, so a plug-in
// handler can read the predicates its kind declares.
struct GraphConstraint {
  std::string id;
  std::string kind;
  std::string scope;  // the graph DID this constraint is bound to
  std::vector<std::pair<std::string, std::string>> properties;

  std::optional<std::string> Property(const std::string& predicate) const {
    for (const auto& kv : properties)
      if (kv.first == predicate)
        return kv.second;
    return std::nullopt;
  }
};

// The §11 CapabilityInfo dictionary.
struct CapabilityInfo {
  std::string id;
  std::vector<std::string> actions;
  std::string resource;
  std::string caveats;  // verbatim JSON array literal, or "" if absent
  std::optional<std::string> expires;
};

// ---- plug-in surfaces (§9.3) -----------------------------------------------

// One caveat element parsed out of a ZCAP's caveats array.
struct Caveat {
  std::string type;
  std::string value_raw;  // verbatim JSON of the "value" member ("" if absent)
  std::string raw;        // verbatim JSON of the whole caveat object
};

// The §9.3 ValidationContext passed to plug-in handlers.
struct ValidationContext {
  raw_ptr<GraphBackend> graph = nullptr;
  std::string graph_did;
  std::string graph_iri;
  std::string author_did;
  std::string action;
  bool is_non_triple_op = false;
  std::string now;  // RFC 3339 evaluation instant
  // The id of the ZCAP delegation whose caveats are being evaluated. Threaded
  // through so caveat handlers that key per-delegation state — the Spec 08
  // rateLimit / cardinality counters, keyed (zcap.id, author) — can identify the
  // capability. Empty for root-capability / non-delegated evaluation.
  std::string zcap_id;
};

// The result a plug-in handler returns.
struct HandlerResult {
  bool allowed = true;
  std::string reason;
};

// §9.3 constraint-kind handler: evaluates a non-capability constraint kind
// (temporal, content, credential, … — all supplied by CONSTRAINT-VOCABULARY /
// applications). |triple| is nullopt for non-triple operations.
class ConstraintKindHandler {
 public:
  virtual ~ConstraintKindHandler() = default;
  virtual std::string kind() const = 0;
  virtual HandlerResult Validate(const std::optional<living_web::Triple>& triple,
                                 const GraphConstraint& constraint,
                                 const ValidationContext& ctx) = 0;
};

// §9.3 caveat handler: evaluates a non-core caveat type attached to a delegation.
class CaveatHandler {
 public:
  virtual ~CaveatHandler() = default;
  virtual std::string type() const = 0;
  // §7.1: caveats reporting false here are skipped for non-triple operations.
  virtual bool appliesToNonTripleOps() const = 0;
  virtual HandlerResult Evaluate(const Caveat& caveat,
                                 const std::optional<living_web::Triple>& triple,
                                 const std::string& action,
                                 const ValidationContext& ctx) = 0;
};

// A delegation request handed to GovernanceBackend::Delegate.
struct DelegationRequest {
  std::string parent_capability;
  std::string invoker;
  std::vector<std::string> actions;
  std::optional<std::string> resource;  // defaults to parent.resource
  std::string caveats;                  // verbatim JSON array, "" if none
};

namespace gov_detail {

// The framework-flattened ZCAP reconstructed from a graph subject's triples.
struct Zcap {
  std::string id;
  std::string invoker;
  std::string parent_capability;
  std::string actions;   // comma-separated
  std::string resource;
  std::string caveats;   // verbatim JSON array, "" if absent
  std::string proof_value;
  std::string proof_purpose;
  std::string proof_method;
  std::string created;
  bool present = false;  // saw rdf:type zcap://Delegation
};

// The fragment (after '#') of a DID-URL / verification-method id; "" if none.
inline std::string Fragment(const std::string& method_id) {
  size_t h = method_id.find('#');
  if (h == std::string::npos)
    return std::string();
  return method_id.substr(h + 1);
}

// The signed-field projection a proof is computed over (§4.5.3.1 amendment).
inline living_web::ZcapProofFields ToFields(const Zcap& z) {
  living_web::ZcapProofFields f;
  f.id = z.id;
  f.invoker = z.invoker;
  f.parent_capability = z.parent_capability;
  f.actions = z.actions;
  f.resource = z.resource;
  f.caveats = z.caveats;
  f.proof_purpose = z.proof_purpose;
  f.created = z.created;
  return f;
}

}  // namespace gov_detail

// ---- GovernanceBackend (§4–§13) --------------------------------------------

class GovernanceBackend {
 public:
  explicit GovernanceBackend(DIDKeyProvider* identity);

  GovernanceBackend(const GovernanceBackend&) = delete;
  GovernanceBackend& operator=(const GovernanceBackend&) = delete;

  ~GovernanceBackend();

  const std::string& last_error() const { return last_error_; }

  // ---- plug-in registration (§9.3) ----

  void RegisterConstraintKind(std::unique_ptr<ConstraintKindHandler> h) {
    kind_handlers_[h->kind()] = std::move(h);
  }

  void RegisterCaveatType(std::unique_ptr<CaveatHandler> h) {
    caveat_handlers_[h->type()] = std::move(h);
  }

  // §4.5.4.1: register a predicate-prefix → action mapping. Rejects a prefix that
  // overlaps (is a prefix of, or is prefixed by) an existing registration.
  bool RegisterActionPrefix(const std::string& prefix,
                            const std::string& action);

  // ---- §4.3 bootstrap: mint the root capability ----

  // Mints and writes the graph's root capability, signed by |creator_cred_id|
  // (its DID becomes the root invoker). |actions| defaults to the framework-core
  // set (§4.3 amendment — no updateSHACL). Fails if the graph has no DID (§4.5.2)
  // or the credential is unknown. Returns the new cap id via |out_cap_id|.
  bool MintRootCapability(GraphBackend* W,
                          const std::string& creator_cred_id,
                          const std::optional<std::vector<std::string>>& actions,
                          std::string* out_cap_id);

  // §8.1.5 group delegateCapability support: returns the graph's existing root
  // capability id, or lazily mints one (framework-core actions) when absent —
  // §4.3 root minting is not automatic on Spec 03 group creation, so a group's
  // first delegation constitutes its root here. |creator_cred_id| MUST be the
  // graph's constitutional key (its DID == the graph DID) so the root invoker is
  // the graph DID and capabilityDelegation delegates can delegate from it (§7).
  // Returns "" on failure (see last_error()).
  std::string EnsureRootCapability(GraphBackend* W,
                                   const std::string& creator_cred_id);

  // ---- §4.5.1 install the capability constraint ----

  // Binds a `capability` constraint to the graph. |predicates|, if given, limits
  // capability checking to those predicates (§4.5.1); absent/empty means every
  // predicate is governed. If a capability constraint already exists, the caller
  // must currently hold `updateGovernance` (§5.2). Returns the constraint id.
  bool InstallCapabilityConstraint(
      GraphBackend* W,
      const std::string& author_cred_id,
      const std::optional<std::vector<std::string>>& predicates,
      std::string* out_constraint_id);

  // ---- §4.5.3 delegation ----

  // Issues a delegated capability. The signer must be the parent's invoker (or,
  // for a graph-DID parent invoker, a current capabilityDelegation delegate),
  // the parent must carry `delegateCapability`, and the child must attenuate the
  // parent (§8: actions ⊆, resource ==, caveats immutable).
  bool Delegate(GraphBackend* W,
                const std::string& signer_cred_id,
                const DelegationRequest& req,
                std::string* out_cap_id);

  // ---- §4.5.5 revocation ----

  // Writes a `revokes_capability` triple. The revoker must be an ancestor invoker
  // of the target (or a capabilityDelegation delegate of a graph-DID ancestor),
  // and the revocation MUST NOT brick governance (§13.10).
  bool Revoke(GraphBackend* W,
              const std::string& revoker_cred_id,
              const std::string& zcap_id);

  // ---- §11 governance API ----

  // §11.1 canAddTriple: would |author_did| be permitted to add |triple|?
  GovernanceValidationResult CanAddTriple(GraphBackend* W,
                                          const living_web::Triple& triple,
                                          const std::string& author_did) {
    return Validate(W, triple, author_did, std::nullopt, /*is_non_triple=*/false);
  }

  // §7.1 non-triple authorisation (e.g. mountContext read-mount).
  GovernanceValidationResult CanPerformAction(GraphBackend* W,
                                              const std::string& action,
                                              const std::string& author_did) {
    return Validate(W, std::nullopt, author_did, action, /*is_non_triple=*/true);
  }

  // §11.2 constraintsFor: the constraints bound to the graph (per-graph; no
  // inheritance). |context_did| is accepted for API parity but constraints are
  // always those of the target graph W.
  std::vector<GraphConstraint> ConstraintsFor(GraphBackend* W,
                                              const std::string& /*context_did*/) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid)
      return {};
    return CollectConstraints(W, *wdid);
  }

  // §11.3 myCapabilities: valid, non-revoked, non-expired capabilities held by
  // |author_did| for this graph.
  std::vector<CapabilityInfo> MyCapabilities(GraphBackend* W,
                                             const std::string& author_did);

  // §11.4 enforcementMode.
  EnforcementMode GetEnforcementMode(GraphBackend* W) {
    return EnforcementModeFromToken(GetEnforcementModeToken(W));
  }

  // §11.4 setEnforcementMode: requires updateGovernance when a capability
  // constraint is installed (§5.2). Replaces any existing mode triple.
  bool SetEnforcementMode(GraphBackend* W,
                          const std::string& author_cred_id,
                          EnforcementMode mode);

  // The core validate(triple, ctx) of §7 + §6.3, exposed for consumers (§11.5).
  GovernanceValidationResult Validate(
      GraphBackend* W,
      const std::optional<living_web::Triple>& triple,
      const std::string& author_did,
      const std::optional<std::string>& action_override,
      bool is_non_triple);

  // ---- browser integration helpers (§11 / §8.1.5) ----

  // The current identity's DID (the active credential's), or "" when none. The
  // §11 renderer surface resolves "the current identity" (§11.1 canAddTriple,
  // §11.3 myCapabilities) through this, so the renderer never names an author.
  std::string ActiveAuthorDid() const;

  // The current identity's internal credential id, or "" when none. §11.4
  // setEnforcementMode authors its governance write as the active credential.
  std::string ActiveCredentialId() const;

  // The Spec 01 SignedContent framing group.delegateCapability (§8.1.5) returns
  // for a freshly issued ZCAP: |author| is the delegation proof's signer DID,
  // |timestamp| the ZCAP's created instant, |data_json| the flattened ZCAP-LD
  // object that was signed, and |proof_method|/|proof_value| the §4.5.3.1 proof.
  struct DelegationRecord {
    std::string author;
    std::string timestamp;
    std::string data_json;
    std::string proof_method;
    std::string proof_value;
  };

  // Resolves |cap_id| in |W| and fills |out| with its SignedContent projection.
  // False when |cap_id| is not a present delegation in |W|.
  bool ResolveDelegationRecord(GraphBackend* W,
                               const std::string& cap_id,
                               DelegationRecord* out);

 private:
  // ---- ZCAP resolution / serialisation ----

  std::vector<living_web::Triple> ZcapTriples(const gov_detail::Zcap& z) const;
  gov_detail::Zcap ResolveZcap(GraphBackend* W, const std::string& cap_id);
  bool SignZcap(const DIDKeyPair* signer, gov_detail::Zcap* z);

  // ---- proof verification (§7 step 6.5.2, §13.1) ----

  bool VerifyProofRaw(const gov_detail::Zcap& z,
                      const std::vector<uint8_t>& pubkey);
  bool VerifyProofBy(GraphBackend* W, const gov_detail::Zcap& z,
                     const std::string& signer);
  bool VerifyBootstrapProof(GraphBackend* W, const std::string& W_did,
                            const gov_detail::Zcap& z);

  // ---- chain walk (§7 step 6.5) ----

  bool WalkChain(GraphBackend* W, gov_detail::Zcap cap, int depth);

  static bool AttenuationOk(const gov_detail::Zcap& child,
                            const gov_detail::Zcap& parent) {
    return living_web::ActionsSubset(child.actions, parent.actions) &&
           child.resource == parent.resource &&
           living_web::CaveatsAttenuationOk(parent.caveats, child.caveats);
  }

  // ---- §7 candidate evaluation ----

  bool RunCapabilityAlgorithm(GraphBackend* W, const std::string& W_did,
                              const std::string& W_iri,
                              const std::optional<living_web::Triple>& triple,
                              const std::string& author_did,
                              const std::string& action, bool is_non_triple,
                              std::string* reason);

  // §7 step 5 eligibility: |author| is the invoker, or an invocation delegate of
  // a graph-DID invoker.
  bool Eligible(GraphBackend* W, const gov_detail::Zcap& z,
                const std::string& author);

  // ---- caveats (§9) ----

  bool EvaluateCaveats(const std::string& caveats_raw,
                       const std::optional<living_web::Triple>& triple,
                       const std::string& action, const ValidationContext& ctx,
                       const std::string& zcap_id, std::string* reason);

  static std::optional<std::string> ExpiryOf(const std::string& caveats_raw);

  // ---- revocation (§4.5.5) ----

  bool IsRevoked(GraphBackend* W, const std::string& cap_id);
  bool ValidRevoker(GraphBackend* W, const std::string& revoker,
                    const std::string& cap_id);
  std::vector<std::string> AncestorInvokers(GraphBackend* W,
                                            const std::string& cap_id);

  // ---- §13.10 brick-state ----

  bool WouldBrickGovernance(GraphBackend* W, const std::string& W_did,
                            const std::set<std::string>& pending);
  bool InvokerHasCurrentDelegate(GraphBackend* W, const std::string& invoker);

  // ---- shared helpers ----

  std::vector<std::string> AllCapabilityIds(GraphBackend* W);
  std::string RootCapabilityId(GraphBackend* W, const std::string& W_did);
  bool AgentInSection(GraphBackend* W, const std::string& graph_did,
                      living_web::DIDCapabilitySection section,
                      const std::string& agent_did);
  bool SignerActsAs(GraphBackend* W, const DIDKeyPair* signer,
                    const std::string& principal);
  bool AuthoriseGovernance(GraphBackend* W, const std::string& W_did,
                           const std::string& author_did);
  bool HasCapabilityConstraint(GraphBackend* W, const std::string& W_did);
  std::vector<GraphConstraint> CollectConstraints(GraphBackend* W,
                                                  const std::string& W_did);
  std::string GetEnforcementModeToken(GraphBackend* W);

  bool IsImmutableSeedPredicate(const std::string& predicate) const {
    return predicate == living_web::kGroupSyncModule ||
           predicate == living_web::kGroupForkedFrom ||
           predicate == living_web::kGroupForkedAtRevision;
  }

  std::string DeriveAction(const std::string& predicate, bool is_removal) const {
    for (const auto& pa : action_prefixes_)
      if (!predicate.empty() && predicate.rfind(pa.first, 0) == 0)
        return pa.second;
    return is_removal ? living_web::kActionRemoveLink
                      : living_web::kActionCreateLink;
  }

  // §6.3 audit attribution: deny-wins with lexicographically greater id tiebreak.
  static void MergeReject(GovernanceValidationResult* res, const std::string& id,
                          const std::string& kind, const std::string& reason) {
    if (res->allowed || id > res->rejected_by) {
      res->rejected_by = id;
      res->constraint_kind = kind;
      res->reason = reason;
    }
    res->allowed = false;
  }

  raw_ptr<DIDKeyProvider> identity_;  // Not owned.
  std::map<std::string, std::unique_ptr<ConstraintKindHandler>> kind_handlers_;
  std::map<std::string, std::unique_ptr<CaveatHandler>> caveat_handlers_;
  std::vector<std::pair<std::string, std::string>> action_prefixes_;
  std::set<std::string> pending_revocations_;  // transient (brick-state eval only)
  std::string last_error_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GOVERNANCE_GOVERNANCE_BACKEND_H_
