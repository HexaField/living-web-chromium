// Capability Framework provider - standalone implementation.
//
// Implements the Graph Capability Framework (Spec 04): ZCAP-LD authority at the
// data layer. Authority is *constituted* — every graph mints a root capability at
// creation (§4.3), delegations attenuate downward (§8), and a write is accepted
// only if the author holds a valid capability chain terminating at the graph's own
// BootstrapRoot (§7). Three enforcement modes (§5) select whether capability
// checks are skipped (open), advisory (announced), or mandatory (enforced).
// Non-capability constraint kinds and non-core caveat types plug in (§9.3) and
// fail closed when unregistered (§13.8, §13.9).
//
// The byte-critical core — the delegation-proof pre-image, the actions-subset and
// immutable-caveats attenuation tests, and the caveat-JSON scanner — lives in the
// Chromium-independent module content/browser/governance/zcap.{h,cc} so the bytes
// a proof signs, and every attenuation decision, are identical between this
// harness and the browser governance backend. This header composes that core with
// the Spec 02 Graph, the Spec 03 group/DID-document helpers, and the Spec 01
// signing primitive (signRaw) into the governance engine of §4–§13.
#ifndef LIVING_WEB_CAPABILITY_PROVIDER_H_
#define LIVING_WEB_CAPABILITY_PROVIDER_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "content/browser/did/did_graph.h"
#include "content/browser/governance/zcap.h"
#include "content/browser/graph/rdf_serialization.h"
#include "standalone/did_key_provider.h"
#include "standalone/graph_provider.h"
#include "standalone/group_provider.h"
#include "third_party/ed25519/ed25519.h"

namespace living_web {

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
  Graph* graph = nullptr;
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
  virtual HandlerResult Validate(const std::optional<Triple>& triple,
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
                                 const std::optional<Triple>& triple,
                                 const std::string& action,
                                 const ValidationContext& ctx) = 0;
};

// A delegation request handed to GovernanceEngine::Delegate.
struct DelegationRequest {
  std::string parent_capability;
  std::string invoker;
  std::vector<std::string> actions;
  std::optional<std::string> resource;  // defaults to parent.resource
  std::string caveats;                  // verbatim JSON array, "" if none
};

namespace cap_detail {

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
inline ZcapProofFields ToFields(const Zcap& z) {
  ZcapProofFields f;
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

}  // namespace cap_detail

// ---- GovernanceEngine (§4–§13) ---------------------------------------------

class GovernanceEngine {
 public:
  explicit GovernanceEngine(DIDKeyProvider* identity) : identity_(identity) {
    // §4.5.4.1 framework-core prefix registry. `did://` is registered in addition
    // to the draft's nominal `did-document://` because GROUP-IDENTITY §4.4 stores
    // the DID document as `did://*` triples (SPEC_COMPLIANCE amendment 04/§4.5.4.1
    // — the two names denote the same predicate family and both map to
    // updateDIDDocument).
    action_prefixes_.push_back({"governance://", kActionUpdateGovernance});
    action_prefixes_.push_back({"did-document://", kActionUpdateDIDDocument});
    action_prefixes_.push_back({"did://", kActionUpdateDIDDocument});
  }

  GovernanceEngine(const GovernanceEngine&) = delete;
  GovernanceEngine& operator=(const GovernanceEngine&) = delete;

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
  bool RegisterActionPrefix(const std::string& prefix, const std::string& action) {
    for (const auto& pa : action_prefixes_) {
      if (prefix.rfind(pa.first, 0) == 0 || pa.first.rfind(prefix, 0) == 0) {
        last_error_ = "prefix_overlap";
        return false;
      }
    }
    action_prefixes_.push_back({prefix, action});
    return true;
  }

  // ---- §4.3 bootstrap: mint the root capability ----

  // Mints and writes the graph's root capability, signed by |creator_cred_id|
  // (its DID becomes the root invoker). |actions| defaults to the framework-core
  // set (§4.3 amendment — no updateSHACL). Fails if the graph has no DID (§4.5.2)
  // or the credential is unknown. On success writes the flattened ZCAP triples,
  // the `governance://root_capability` binding, and a `has_zcap` link to the
  // creator, and returns the new cap id via |out_cap_id|.
  bool MintRootCapability(Graph* W,
                          const std::string& creator_cred_id,
                          const std::optional<std::vector<std::string>>& actions,
                          std::string* out_cap_id) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid || wdid->empty()) {
      last_error_ = "InvalidStateError";  // §4.5.2 null-did graph
      return false;
    }
    const DIDKeyPair* creator = identity_->GetCredential(creator_cred_id);
    if (!creator) {
      last_error_ = "InvalidStateError";
      return false;
    }
    cap_detail::Zcap z;
    z.id = "urn:uuid:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
    z.invoker = creator->did;
    z.parent_capability = kBootstrapRoot;
    z.actions = JoinActions(actions ? *actions : DefaultRootActions());
    z.resource = *wdid;
    z.caveats = "";  // the root carries no caveats
    z.proof_purpose = kProofPurposeCapabilityDelegation;
    z.proof_method =
        creator->did + "#" + *did_key::Ed25519PublicKeyMultibase(creator->public_key);
    z.created = graph_detail::NowRfc3339();

    if (!SignZcap(creator, &z))
      return false;

    std::vector<Triple> t = ZcapTriples(z);
    t.push_back(group_detail::T_iri(*wdid, kGovRootCapability, z.id));
    t.push_back(group_detail::T_iri(z.invoker, kGovHasZcap, z.id));

    group_detail::ScopedActive active(identity_, creator->id);
    if (!W->AddTriples(t)) {
      last_error_ = W->last_error();
      return false;
    }
    if (out_cap_id)
      *out_cap_id = z.id;
    return true;
  }

  // ---- §4.5.1 install the capability constraint ----

  // Binds a `capability` constraint to the graph. |predicates|, if given, limits
  // capability checking to those predicates (§4.5.1); absent/empty means every
  // predicate is governed. If a capability constraint already exists, the caller
  // must currently hold `updateGovernance` (§5.2). Returns the constraint id.
  bool InstallCapabilityConstraint(
      Graph* W,
      const std::string& author_cred_id,
      const std::optional<std::vector<std::string>>& predicates,
      std::string* out_constraint_id) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid || wdid->empty()) {
      last_error_ = "InvalidStateError";
      return false;
    }
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author) {
      last_error_ = "InvalidStateError";
      return false;
    }
    if (HasCapabilityConstraint(W, *wdid) &&
        !AuthoriseGovernance(W, *wdid, author->did)) {
      last_error_ = "not_authorised";
      return false;
    }
    std::string cid =
        "urn:uuid:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
    std::vector<Triple> t;
    t.push_back(group_detail::T_iri(cid, kGovEntryType, kGovConstraintEntryType));
    t.push_back(
        group_detail::T_lit(cid, kGovConstraintKind, kConstraintKindCapability));
    if (predicates && !predicates->empty())
      t.push_back(group_detail::T_lit(cid, kGovCapabilityPredicates,
                                      JoinActions(*predicates)));
    t.push_back(group_detail::T_iri(*wdid, kGovHasConstraint, cid));

    group_detail::ScopedActive active(identity_, author->id);
    if (!W->AddTriples(t)) {
      last_error_ = W->last_error();
      return false;
    }
    if (out_constraint_id)
      *out_constraint_id = cid;
    return true;
  }

  // ---- §4.5.3 delegation ----

  // Issues a delegated capability. The signer must be the parent's invoker (or,
  // for a graph-DID parent invoker, a current capabilityDelegation delegate),
  // the parent must carry `delegateCapability`, and the child must attenuate the
  // parent (§8: actions ⊆, resource ==, caveats immutable). Writes the flattened
  // child ZCAP plus a `has_zcap` link to the child invoker.
  bool Delegate(Graph* W,
                const std::string& signer_cred_id,
                const DelegationRequest& req,
                std::string* out_cap_id) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid || wdid->empty()) {
      last_error_ = "InvalidStateError";
      return false;
    }
    const DIDKeyPair* signer = identity_->GetCredential(signer_cred_id);
    if (!signer) {
      last_error_ = "InvalidStateError";
      return false;
    }
    cap_detail::Zcap parent = ResolveZcap(W, req.parent_capability);
    if (!parent.present) {
      last_error_ = "unknown_parent";
      return false;
    }
    if (!SignerActsAs(W, signer, parent.invoker)) {
      last_error_ = "not_authorised";
      return false;
    }
    if (!ActionInSet(kActionDelegateCapability, parent.actions)) {
      last_error_ = "missing_delegate_capability";
      return false;
    }
    std::string resource = req.resource ? *req.resource : parent.resource;
    if (resource != parent.resource) {
      last_error_ = "attenuation_resource";  // §8 resource equality
      return false;
    }
    std::string actions = JoinActions(req.actions);
    if (!ActionsSubset(actions, parent.actions)) {
      last_error_ = "attenuation_actions";  // §8 child.actions ⊆ parent.actions
      return false;
    }
    if (!CaveatsAttenuationOk(parent.caveats, req.caveats)) {
      last_error_ = "attenuation_caveats";  // §8 immutable caveats
      return false;
    }
    cap_detail::Zcap z;
    z.id = "urn:uuid:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
    z.invoker = req.invoker;
    z.parent_capability = parent.id;
    z.actions = actions;
    z.resource = resource;
    z.caveats = req.caveats;
    z.proof_purpose = kProofPurposeCapabilityDelegation;
    z.proof_method =
        signer->did + "#" + *did_key::Ed25519PublicKeyMultibase(signer->public_key);
    z.created = graph_detail::NowRfc3339();

    if (!SignZcap(signer, &z))
      return false;

    std::vector<Triple> t = ZcapTriples(z);
    t.push_back(group_detail::T_iri(req.invoker, kGovHasZcap, z.id));

    group_detail::ScopedActive active(identity_, signer->id);
    if (!W->AddTriples(t)) {
      last_error_ = W->last_error();
      return false;
    }
    if (out_cap_id)
      *out_cap_id = z.id;
    return true;
  }

  // ---- §4.5.5 revocation ----

  // Writes a `revokes_capability` triple. The revoker must be an ancestor invoker
  // of the target (or a capabilityDelegation delegate of a graph-DID ancestor),
  // and the revocation MUST NOT brick governance (§13.10).
  bool Revoke(Graph* W,
              const std::string& revoker_cred_id,
              const std::string& zcap_id) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid || wdid->empty()) {
      last_error_ = "InvalidStateError";
      return false;
    }
    const DIDKeyPair* revoker = identity_->GetCredential(revoker_cred_id);
    if (!revoker) {
      last_error_ = "InvalidStateError";
      return false;
    }
    cap_detail::Zcap target = ResolveZcap(W, zcap_id);
    if (!target.present) {
      last_error_ = "unknown_capability";
      return false;
    }
    if (!ValidRevoker(W, revoker->did, zcap_id)) {
      last_error_ = "not_authorised_to_revoke";
      return false;
    }
    std::set<std::string> pending{zcap_id};
    if (WouldBrickGovernance(W, *wdid, pending)) {
      last_error_ = "would_brick_governance";  // §13.10
      return false;
    }
    group_detail::ScopedActive active(identity_, revoker->id);
    if (!W->AddTriples(
            {group_detail::T_iri(revoker->did, kGovRevokesCapability, zcap_id)})) {
      last_error_ = W->last_error();
      return false;
    }
    return true;
  }

  // ---- §11 governance API ----

  // §11.1 canAddTriple: would |author_did| be permitted to add |triple|?
  GovernanceValidationResult CanAddTriple(Graph* W,
                                          const Triple& triple,
                                          const std::string& author_did) {
    return Validate(W, triple, author_did, std::nullopt, /*is_non_triple=*/false);
  }

  // §7.1 non-triple authorisation (e.g. mountContext read-mount).
  GovernanceValidationResult CanPerformAction(Graph* W,
                                              const std::string& action,
                                              const std::string& author_did) {
    return Validate(W, std::nullopt, author_did, action, /*is_non_triple=*/true);
  }

  // §11.2 constraintsFor: the constraints bound to the graph (per-graph; no
  // inheritance). |context_did| is accepted for API parity but constraints are
  // always those of the target graph W.
  std::vector<GraphConstraint> ConstraintsFor(Graph* W,
                                              const std::string& /*context_did*/) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid)
      return {};
    return CollectConstraints(W, *wdid);
  }

  // §11.3 myCapabilities: valid, non-revoked, non-expired capabilities held by
  // |author_did| for this graph.
  std::vector<CapabilityInfo> MyCapabilities(Graph* W,
                                             const std::string& author_did) {
    std::vector<CapabilityInfo> out;
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid)
      return out;
    std::string now = graph_detail::NowRfc3339();
    ValidationContext ctx;
    ctx.graph = W;
    ctx.graph_did = *wdid;
    ctx.author_did = author_did;
    ctx.is_non_triple_op = true;
    ctx.now = now;
    for (const std::string& cid : AllCapabilityIds(W)) {
      cap_detail::Zcap z = ResolveZcap(W, cid);
      if (!z.present || !Eligible(W, z, author_did))
        continue;
      if (IsRevoked(W, z.id))
        continue;
      std::string reason;
      if (!EvaluateCaveats(z.caveats, std::nullopt, "", ctx, z.id, &reason))
        continue;
      if (!WalkChain(W, z, 0))
        continue;
      CapabilityInfo info;
      info.id = z.id;
      info.actions = ParseActions(z.actions);
      info.resource = z.resource;
      info.caveats = z.caveats;
      if (auto exp = ExpiryOf(z.caveats))
        info.expires = *exp;
      out.push_back(std::move(info));
    }
    return out;
  }

  // §11.4 enforcementMode.
  EnforcementMode GetEnforcementMode(Graph* W) {
    return EnforcementModeFromToken(GetEnforcementModeToken(W));
  }

  // §11.4 setEnforcementMode: requires updateGovernance when a capability
  // constraint is installed (§5.2). Replaces any existing mode triple.
  bool SetEnforcementMode(Graph* W,
                          const std::string& author_cred_id,
                          EnforcementMode mode) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid || wdid->empty()) {
      last_error_ = "InvalidStateError";
      return false;
    }
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author) {
      last_error_ = "InvalidStateError";
      return false;
    }
    if (HasCapabilityConstraint(W, *wdid) &&
        !AuthoriseGovernance(W, *wdid, author->did)) {
      last_error_ = "not_authorised";
      return false;
    }
    group_detail::ScopedActive active(identity_, author->id);
    // enforcement_mode is single-valued: clear any prior value first.
    std::vector<Triple> existing;
    TripleQuery q;
    q.subject = *wdid;
    q.predicate = kGovEnforcementMode;
    if (W->QueryTriples(q, &existing)) {
      for (const auto& t : existing) {
        bool removed = false;
        W->RemoveTriple(t, &removed);
      }
    }
    if (!W->AddTriples({group_detail::T_lit(*wdid, kGovEnforcementMode,
                                            EnforcementModeToken(mode))})) {
      last_error_ = W->last_error();
      return false;
    }
    return true;
  }

  // The core validate(triple, ctx) of §7 + §6.3, exposed for consumers (§11.5).
  GovernanceValidationResult Validate(Graph* W,
                                      const std::optional<Triple>& triple,
                                      const std::string& author_did,
                                      const std::optional<std::string>& action_override,
                                      bool is_non_triple) {
    GovernanceValidationResult res;
    res.allowed = true;
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    std::string W_did = wdid.value_or("");
    std::string mode = GetEnforcementModeToken(W);
    res.mode = mode;

    ValidationContext ctx;
    ctx.graph = W;
    ctx.graph_did = W_did;
    std::string iri;
    if (W && W->GetIri(&iri))
      ctx.graph_iri = iri;
    ctx.author_did = author_did;
    ctx.is_non_triple_op = is_non_triple;
    ctx.now = graph_detail::NowRfc3339();

    // §10 immutable-seed guard — all modes, before any capability logic.
    if (triple && triple->subject == W_did && IsImmutableSeedPredicate(triple->predicate)) {
      res.allowed = false;
      res.rejected_by = W_did;
      res.constraint_kind = "capability";
      res.reason = "immutable_seed_predicate";
      return res;
    }

    std::string action = action_override
                             ? *action_override
                             : DeriveAction(triple ? triple->predicate : std::string(),
                                            /*is_removal=*/false);
    ctx.action = action;

    std::vector<GraphConstraint> constraints = CollectConstraints(W, W_did);

    // §7 capability constraints.
    std::vector<const GraphConstraint*> caps;
    for (const auto& c : constraints)
      if (c.kind == kConstraintKindCapability)
        caps.push_back(&c);

    if (!caps.empty() && mode != "open") {
      bool covered = true;  // §7 step 4 predicate-coverage (triple ops only)
      if (triple && !is_non_triple) {
        bool any_restricted = false, in_some = false;
        for (const auto* c : caps) {
          auto preds = c->Property(kGovCapabilityPredicates);
          if (preds && !preds->empty()) {
            any_restricted = true;
            for (const auto& p : ParseActions(*preds))
              if (p == triple->predicate)
                in_some = true;
          }
        }
        if (any_restricted && !in_some)
          covered = false;
      }
      if (covered) {
        std::string reason;
        bool ok = RunCapabilityAlgorithm(W, W_did, ctx.graph_iri, triple,
                                         author_did, action, is_non_triple, &reason);
        if (!ok && mode == "enforced") {
          // Attribute to a capability constraint (lexicographically greatest id).
          std::string attrib = caps.front()->id;
          for (const auto* c : caps)
            if (c->id > attrib)
              attrib = c->id;
          MergeReject(&res, attrib, "capability", reason);
        }
        // announced mode: computed but never rejects (§5.1).
      }
    }

    // Non-capability constraint kinds — all modes, deny-wins (§5.3, §6.3).
    for (const auto& c : constraints) {
      if (c.kind == kConstraintKindCapability)
        continue;
      auto it = kind_handlers_.find(c.kind);
      if (it == kind_handlers_.end()) {
        MergeReject(&res, c.id, c.kind, "unknown_constraint_kind");  // §13.8
        continue;
      }
      HandlerResult r = it->second->Validate(triple, c, ctx);
      if (!r.allowed)
        MergeReject(&res, c.id, c.kind, r.reason);
    }
    return res;
  }

 private:
  // ---- ZCAP resolution / serialisation ----

  std::vector<Triple> ZcapTriples(const cap_detail::Zcap& z) const {
    std::vector<Triple> t;
    t.push_back(group_detail::T_iri(z.id, kRdfType, kZcapDelegation));
    t.push_back(group_detail::T_iri(z.id, kZcapInvoker, z.invoker));
    t.push_back(group_detail::T_iri(z.id, kZcapParentCapability, z.parent_capability));
    t.push_back(group_detail::T_lit(z.id, kZcapActions, z.actions));
    t.push_back(group_detail::T_iri(z.id, kZcapResource, z.resource));
    if (!z.caveats.empty())
      t.push_back(group_detail::T_lit(z.id, kZcapCaveats, z.caveats));
    t.push_back(group_detail::T_lit(z.id, kZcapProofValue, z.proof_value));
    t.push_back(group_detail::T_lit(z.id, kZcapProofPurpose, z.proof_purpose));
    t.push_back(group_detail::T_iri(z.id, kZcapProofMethod, z.proof_method));
    t.push_back(
        group_detail::T_lit(z.id, kZcapCreated, z.created, kXsdDateTime));
    return t;
  }

  cap_detail::Zcap ResolveZcap(Graph* W, const std::string& cap_id) {
    cap_detail::Zcap z;
    z.id = cap_id;
    TripleQuery q;
    q.subject = cap_id;
    std::vector<Triple> ts;
    if (!W->QueryTriples(q, &ts))
      return z;
    std::string actions;
    for (const auto& t : ts) {
      const std::string& p = t.predicate;
      auto iri = [&]() { return t.object.is_literal() ? std::string()
                                                       : t.object.iri_or_bnode; };
      auto lit = [&]() {
        return t.object.is_literal() ? t.object.literal->lexical : std::string();
      };
      if (p == kRdfType) {
        if (iri() == kZcapDelegation)
          z.present = true;
      } else if (p == kZcapInvoker) {
        z.invoker = iri();
      } else if (p == kZcapParentCapability) {
        z.parent_capability = iri();
      } else if (p == kZcapActions) {
        // Tolerate both the single comma-string form and one-triple-per-action.
        if (!actions.empty())
          actions += ",";
        actions += lit();
      } else if (p == kZcapResource) {
        z.resource = iri();
      } else if (p == kZcapCaveats) {
        z.caveats = lit();
      } else if (p == kZcapProofValue) {
        z.proof_value = lit();
      } else if (p == kZcapProofPurpose) {
        z.proof_purpose = lit();
      } else if (p == kZcapProofMethod) {
        z.proof_method = iri();
      } else if (p == kZcapCreated) {
        z.created = lit();
      }
    }
    z.actions = actions;
    return z;
  }

  bool SignZcap(const DIDKeyPair* signer, cap_detail::Zcap* z) {
    std::string preimage = BuildDelegationProofPreimage(cap_detail::ToFields(*z));
    std::string hash = crypto::SHA256HashString(preimage);
    auto sig = identity_->SignRaw(
        signer->id, std::vector<uint8_t>(hash.begin(), hash.end()));
    if (!sig) {
      last_error_ = "InvalidStateError";
      return false;
    }
    z->proof_value = did_key::MultibaseEncode(*sig);
    return true;
  }

  // ---- proof verification (§7 step 6.5.2, §13.1) ----

  bool VerifyProofRaw(const cap_detail::Zcap& z,
                      const std::vector<uint8_t>& pubkey) {
    if (pubkey.size() != 32)
      return false;
    std::string preimage = BuildDelegationProofPreimage(cap_detail::ToFields(z));
    std::string hash = crypto::SHA256HashString(preimage);
    auto sig = did_key::MultibaseDecode(z.proof_value);
    if (!sig || sig->size() != 64)
      return false;
    return ed25519_verify(sig->data(),
                          reinterpret_cast<const uint8_t*>(hash.data()),
                          hash.size(), pubkey.data()) == 1;
  }

  // The proof of |z| must verify against |signer|'s key — either |signer|'s own
  // did:key, or (if |signer| is a graph DID) a current capabilityDelegation
  // delegate on its DID document (§13.1). Binds authority to the actual key,
  // never to a self-declared proofMethod.
  bool VerifyProofBy(Graph* W, const cap_detail::Zcap& z,
                     const std::string& signer) {
    if (did_graph::IsDidGraph(signer)) {
      DidDocument doc;
      group_detail::ProjectDidDocument(W, signer, &doc);
      for (const auto& m : doc.capability_delegation) {
        auto key = DecodePublicKeyMultibase(cap_detail::Fragment(m));
        if (key && VerifyProofRaw(z, *key))
          return true;
      }
      return false;
    }
    auto key = ParseAnyDidEd25519(signer);
    return key && VerifyProofRaw(z, *key);
  }

  // §4.3 bootstrap-proof re-verification, evaluated purely from W (§6.1, §13.4 —
  // the parent graph's key never has standing in the child). Accepts a proof by
  // the root invoker's own key (standalone case) or by a current
  // capabilityDelegation delegate on W's own DID document.
  bool VerifyBootstrapProof(Graph* W, const std::string& W_did,
                            const cap_detail::Zcap& z) {
    auto ikey = ParseAnyDidEd25519(z.invoker);
    if (ikey && VerifyProofRaw(z, *ikey))
      return true;
    DidDocument doc;
    group_detail::ProjectDidDocument(W, W_did, &doc);
    for (const auto& m : doc.capability_delegation) {
      auto key = DecodePublicKeyMultibase(cap_detail::Fragment(m));
      if (key && VerifyProofRaw(z, *key))
        return true;
    }
    return false;
  }

  // ---- chain walk (§7 step 6.5) ----

  bool WalkChain(Graph* W, cap_detail::Zcap cap, int depth) {
    std::string W_did = W->did().value_or("");
    while (true) {
      if (depth > 10)  // step 6.5.1
        return false;
      if (cap.parent_capability == kBootstrapRoot) {  // step 6.5.4
        if (cap.id != RootCapabilityId(W, W_did))
          return false;
        return VerifyBootstrapProof(W, W_did, cap);
      }
      cap_detail::Zcap parent = ResolveZcap(W, cap.parent_capability);  // step 6.5.5
      if (!parent.present)
        return false;
      if (!VerifyProofBy(W, cap, parent.invoker))  // step 6.5.2
        return false;
      if (!ActionInSet(kActionDelegateCapability, parent.actions))  // step 6.5.3
        return false;
      if (!AttenuationOk(cap, parent))  // step 6.5.6
        return false;
      if (IsRevoked(W, parent.id))  // step 6.5.7
        return false;
      cap = parent;  // step 6.5.8
      ++depth;
    }
  }

  static bool AttenuationOk(const cap_detail::Zcap& child,
                            const cap_detail::Zcap& parent) {
    return ActionsSubset(child.actions, parent.actions) &&
           child.resource == parent.resource &&
           CaveatsAttenuationOk(parent.caveats, child.caveats);
  }

  // ---- §7 candidate evaluation ----

  bool RunCapabilityAlgorithm(Graph* W, const std::string& W_did,
                              const std::string& W_iri,
                              const std::optional<Triple>& triple,
                              const std::string& author_did,
                              const std::string& action, bool is_non_triple,
                              std::string* reason) {
    ValidationContext ctx;
    ctx.graph = W;
    ctx.graph_did = W_did;
    ctx.graph_iri = W_iri;
    ctx.author_did = author_did;
    ctx.action = action;
    ctx.is_non_triple_op = is_non_triple;
    ctx.now = graph_detail::NowRfc3339();

    *reason = "no_matching_capability";
    for (const std::string& cid : AllCapabilityIds(W)) {
      cap_detail::Zcap z = ResolveZcap(W, cid);
      if (!z.present || !Eligible(W, z, author_did))
        continue;
      if (!ActionInSet(action, z.actions)) {  // step 6.1
        *reason = "no_matching_capability";
        continue;
      }
      if (z.resource != W_did && (W_iri.empty() || z.resource != W_iri)) {  // 6.2
        *reason = "resource_mismatch";
        continue;
      }
      if (IsRevoked(W, z.id)) {  // step 6.3
        *reason = "revoked";
        continue;
      }
      std::string cav_reason;
      if (!EvaluateCaveats(z.caveats, triple, action, ctx, z.id,
                           &cav_reason)) {  // 6.4
        *reason = cav_reason;
        continue;
      }
      if (!WalkChain(W, z, 0)) {  // step 6.5
        *reason = "chain_broken";
        continue;
      }
      return true;  // step 7 — a candidate succeeded
    }
    return false;
  }

  // §7 step 5 eligibility: |author| is the invoker, or an invocation delegate of
  // a graph-DID invoker.
  bool Eligible(Graph* W, const cap_detail::Zcap& z, const std::string& author) {
    if (z.invoker == author)
      return true;
    if (did_graph::IsDidGraph(z.invoker) &&
        AgentInSection(W, z.invoker, DIDCapabilitySection::kCapabilityInvocation,
                       author))
      return true;
    return false;
  }

  // ---- caveats (§9) ----

  bool EvaluateCaveats(const std::string& caveats_raw,
                       const std::optional<Triple>& triple,
                       const std::string& action, const ValidationContext& ctx,
                       const std::string& zcap_id, std::string* reason) {
    if (caveats_raw.empty())
      return true;
    std::vector<std::string> elems;
    if (!SplitJsonArray(caveats_raw, &elems)) {
      *reason = "caveat_malformed";
      return false;  // fail-closed
    }
    // Expose the owning delegation's id to per-delegation caveat handlers (the
    // Spec 08 rateLimit / cardinality counters key on it) without disturbing the
    // caller's context.
    ValidationContext local = ctx;
    local.zcap_id = zcap_id;
    for (const std::string& e : elems) {
      auto type = JsonStringField(e, "type");
      if (!type) {
        *reason = "caveat_malformed";
        return false;
      }
      if (*type == "expiry") {  // §9.2 core caveat — applies to non-triple ops too
        auto val = JsonRawField(e, "value");
        auto exp = val ? JsonStringField(*val, "expiresAt") : std::nullopt;
        if (!exp || local.now >= *exp) {
          *reason = "caveat_failed:expiry";
          return false;
        }
        continue;
      }
      auto it = caveat_handlers_.find(*type);
      if (it == caveat_handlers_.end()) {  // §13.9 fail-closed
        *reason = "unknown_caveat:" + *type;
        return false;
      }
      if (local.is_non_triple_op && !it->second->appliesToNonTripleOps())
        continue;  // §7.1 skip
      Caveat cav;
      cav.type = *type;
      cav.value_raw = JsonRawField(e, "value").value_or("");
      cav.raw = e;
      HandlerResult r = it->second->Evaluate(cav, triple, action, local);
      if (!r.allowed) {
        *reason = "caveat_failed:" + *type;
        return false;
      }
    }
    return true;
  }

  static std::optional<std::string> ExpiryOf(const std::string& caveats_raw) {
    if (caveats_raw.empty())
      return std::nullopt;
    std::vector<std::string> elems;
    if (!SplitJsonArray(caveats_raw, &elems))
      return std::nullopt;
    for (const std::string& e : elems) {
      auto type = JsonStringField(e, "type");
      if (type && *type == "expiry") {
        auto val = JsonRawField(e, "value");
        if (val)
          return JsonStringField(*val, "expiresAt");
      }
    }
    return std::nullopt;
  }

  // ---- revocation (§4.5.5) ----

  bool IsRevoked(Graph* W, const std::string& cap_id) {
    if (pending_revocations_.count(cap_id))
      return true;
    TripleQuery q;
    q.predicate = kGovRevokesCapability;
    std::vector<Triple> ts;
    if (!W->QueryTriples(q, &ts))
      return false;
    for (const auto& t : ts) {
      if (t.object.is_literal() || t.object.iri_or_bnode != cap_id)
        continue;
      if (ValidRevoker(W, t.subject, cap_id))
        return true;
    }
    return false;
  }

  // §4.5.5 authority to revoke: R (or, for a graph-DID ancestor invoker, a
  // capabilityDelegation delegate of it) is any ancestor of |cap_id|.
  bool ValidRevoker(Graph* W, const std::string& revoker,
                    const std::string& cap_id) {
    for (const std::string& inv : AncestorInvokers(W, cap_id)) {
      if (inv == revoker)
        return true;
      if (did_graph::IsDidGraph(inv) &&
          AgentInSection(W, inv, DIDCapabilitySection::kCapabilityDelegation,
                         revoker))
        return true;
    }
    return false;
  }

  // The invoker of every ancestor of |cap_id| (parent → root), bounded to depth
  // 10. Does not call IsRevoked (no mutual recursion).
  std::vector<std::string> AncestorInvokers(Graph* W, const std::string& cap_id) {
    std::vector<std::string> out;
    cap_detail::Zcap cur = ResolveZcap(W, cap_id);
    if (!cur.present)
      return out;
    int depth = 0;
    while (depth++ < 10) {
      if (cur.parent_capability == kBootstrapRoot)
        break;
      cap_detail::Zcap parent = ResolveZcap(W, cur.parent_capability);
      if (!parent.present)
        break;
      out.push_back(parent.invoker);
      cur = parent;
    }
    return out;
  }

  // ---- §13.10 brick-state ----

  // True iff, in the post-state where |pending| ids are additionally revoked, the
  // graph would have zero valid capabilities carrying updateGovernance whose chain
  // terminates at the root and that are exercisable by a current delegate.
  bool WouldBrickGovernance(Graph* W, const std::string& W_did,
                            const std::set<std::string>& pending) {
    pending_revocations_ = pending;
    struct Clear {
      std::set<std::string>* p;
      ~Clear() { p->clear(); }
    } clear{&pending_revocations_};

    ValidationContext ctx;
    ctx.graph = W;
    ctx.graph_did = W_did;
    ctx.is_non_triple_op = true;
    ctx.now = graph_detail::NowRfc3339();

    for (const std::string& cid : AllCapabilityIds(W)) {
      cap_detail::Zcap z = ResolveZcap(W, cid);
      if (!z.present)
        continue;
      if (!ActionInSet(kActionUpdateGovernance, z.actions))
        continue;
      if (IsRevoked(W, z.id))
        continue;
      std::string reason;
      if (!EvaluateCaveats(z.caveats, std::nullopt, kActionUpdateGovernance, ctx,
                           z.id, &reason))
        continue;
      if (!WalkChain(W, z, 0))
        continue;
      if (InvokerHasCurrentDelegate(W, z.invoker))
        return false;  // a governance capability survives → not bricked
    }
    return true;
  }

  bool InvokerHasCurrentDelegate(Graph* W, const std::string& invoker) {
    if (!did_graph::IsDidGraph(invoker))
      return true;  // a did:key agent is itself the exerciser
    DidDocument doc;
    group_detail::ProjectDidDocument(W, invoker, &doc);
    return !doc.capability_invocation.empty();
  }

  // ---- shared helpers ----

  std::vector<std::string> AllCapabilityIds(Graph* W) {
    std::set<std::string> ids;
    TripleQuery q;
    q.predicate = kGovHasZcap;
    std::vector<Triple> ts;
    if (W->QueryTriples(q, &ts))
      for (const auto& t : ts)
        if (!t.object.is_literal())
          ids.insert(t.object.iri_or_bnode);
    return std::vector<std::string>(ids.begin(), ids.end());
  }

  std::string RootCapabilityId(Graph* W, const std::string& W_did) {
    return group_detail::FirstIriOf(W, W_did, kGovRootCapability).value_or("");
  }

  // Whether |agent_did|'s key matches any verification method listed in |section|
  // of |graph_did|'s DID document.
  bool AgentInSection(Graph* W, const std::string& graph_did,
                      DIDCapabilitySection section, const std::string& agent_did) {
    auto akey = ParseAnyDidEd25519(agent_did);
    if (!akey)
      return false;
    for (const auto& o :
         group_detail::QueryObjects(W, graph_did, SectionPredicate(section))) {
      if (o.is_literal())
        continue;
      auto key = DecodePublicKeyMultibase(cap_detail::Fragment(o.iri_or_bnode));
      if (key && *key == *akey)
        return true;
    }
    return false;
  }

  // A signer may act as |principal| when delegating/authorising: it is |principal|
  // itself, or a capabilityDelegation delegate of a graph-DID principal.
  bool SignerActsAs(Graph* W, const DIDKeyPair* signer,
                    const std::string& principal) {
    if (signer->did == principal)
      return true;
    if (did_graph::IsDidGraph(principal) &&
        AgentInSection(W, principal, DIDCapabilitySection::kCapabilityDelegation,
                       signer->did))
      return true;
    return false;
  }

  // Authorise an updateGovernance act by |author_did| under enforced semantics,
  // independent of the current mode (§5.2 mode-change / constraint-install gate).
  bool AuthoriseGovernance(Graph* W, const std::string& W_did,
                           const std::string& author_did) {
    std::string iri;
    W->GetIri(&iri);
    std::string reason;
    return RunCapabilityAlgorithm(W, W_did, iri, std::nullopt, author_did,
                                  kActionUpdateGovernance,
                                  /*is_non_triple=*/true, &reason);
  }

  bool HasCapabilityConstraint(Graph* W, const std::string& W_did) {
    for (const auto& c : CollectConstraints(W, W_did))
      if (c.kind == kConstraintKindCapability)
        return true;
    return false;
  }

  std::vector<GraphConstraint> CollectConstraints(Graph* W,
                                                  const std::string& W_did) {
    std::vector<GraphConstraint> out;
    if (!W)
      return out;
    for (const auto& o : group_detail::QueryObjects(W, W_did, kGovHasConstraint)) {
      if (o.is_literal())
        continue;
      const std::string& cid = o.iri_or_bnode;
      auto kind = group_detail::FirstLiteralOf(W, cid, kGovConstraintKind);
      if (!kind)
        continue;  // a constraint MUST declare a kind (§4.1)
      GraphConstraint gc;
      gc.id = cid;
      gc.scope = W_did;
      gc.kind = *kind;
      TripleQuery q;
      q.subject = cid;
      std::vector<Triple> ts;
      if (W->QueryTriples(q, &ts)) {
        for (const auto& t : ts) {
          if (t.predicate == kGovConstraintKind || t.predicate == kGovEntryType)
            continue;
          std::string val = t.object.is_literal() ? t.object.literal->lexical
                                                  : t.object.iri_or_bnode;
          gc.properties.push_back({t.predicate, val});
        }
      }
      out.push_back(std::move(gc));
      if (out.size() >= 1000)  // §13.7 constraint-flooding bound
        break;
    }
    return out;
  }

  std::string GetEnforcementModeToken(Graph* W) {
    if (!W)
      return "open";
    std::optional<std::string> wdid = W->did();
    if (!wdid)
      return "open";
    return group_detail::FirstLiteralOf(W, *wdid, kGovEnforcementMode)
        .value_or("open");
  }

  bool IsImmutableSeedPredicate(const std::string& predicate) const {
    return predicate == kGroupSyncModule || predicate == kGroupForkedFrom ||
           predicate == kGroupForkedAtRevision;
  }

  std::string DeriveAction(const std::string& predicate, bool is_removal) const {
    for (const auto& pa : action_prefixes_)
      if (!predicate.empty() && predicate.rfind(pa.first, 0) == 0)
        return pa.second;
    return is_removal ? kActionRemoveLink : kActionCreateLink;
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

  DIDKeyProvider* identity_;
  std::map<std::string, std::unique_ptr<ConstraintKindHandler>> kind_handlers_;
  std::map<std::string, std::unique_ptr<CaveatHandler>> caveat_handlers_;
  std::vector<std::pair<std::string, std::string>> action_prefixes_;
  std::set<std::string> pending_revocations_;  // transient (brick-state eval only)
  std::string last_error_;
};

}  // namespace living_web

#endif  // LIVING_WEB_CAPABILITY_PROVIDER_H_
