// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/governance/governance_backend.h"

#include <ctime>
#include <iomanip>
#include <sstream>

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/uuid.h"
#include "base/values.h"
#include "crypto/sha2.h"
#include "third_party/ed25519/ed25519.h"

namespace content {

namespace {

// RFC 3339 UTC timestamp, matching the file-local helper in graph_backend.cc and
// group_backend.cc so governance writes stamp identically to graph/group writes.
std::string NowRfc3339() {
  auto now = std::time(nullptr);
  auto* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

std::string NewUrnUuid() {
  return "urn:uuid:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
}

}  // namespace

GovernanceBackend::GovernanceBackend(DIDKeyProvider* identity)
    : identity_(identity) {
  // §4.5.4.1 framework-core prefix registry. `did://` is registered in addition
  // to the draft's nominal `did-document://` because GROUP-IDENTITY §4.4 stores
  // the DID document as `did://*` triples (SPEC_COMPLIANCE amendment 04/§4.5.4.1
  // — the two names denote the same predicate family and both map to
  // updateDIDDocument).
  action_prefixes_.push_back({"governance://", living_web::kActionUpdateGovernance});
  action_prefixes_.push_back({"did-document://", living_web::kActionUpdateDIDDocument});
  action_prefixes_.push_back({"did://", living_web::kActionUpdateDIDDocument});
}

GovernanceBackend::~GovernanceBackend() = default;

bool GovernanceBackend::RegisterActionPrefix(const std::string& prefix,
                                             const std::string& action) {
  for (const auto& pa : action_prefixes_) {
    if (prefix.rfind(pa.first, 0) == 0 || pa.first.rfind(prefix, 0) == 0) {
      last_error_ = "prefix_overlap";
      return false;
    }
  }
  action_prefixes_.push_back({prefix, action});
  return true;
}

// ---- §4.3 bootstrap: mint the root capability ------------------------------

bool GovernanceBackend::MintRootCapability(
    GraphBackend* W,
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
  gov_detail::Zcap z;
  z.id = NewUrnUuid();
  z.invoker = creator->did;
  z.parent_capability = living_web::kBootstrapRoot;
  z.actions = living_web::JoinActions(
      actions ? *actions : living_web::DefaultRootActions());
  z.resource = *wdid;
  z.caveats = "";  // the root carries no caveats
  z.proof_purpose = living_web::kProofPurposeCapabilityDelegation;
  z.proof_method =
      creator->did + "#" +
      *living_web::did_key::Ed25519PublicKeyMultibase(creator->public_key);
  z.created = NowRfc3339();

  if (!SignZcap(creator, &z))
    return false;

  std::vector<living_web::Triple> t = ZcapTriples(z);
  t.push_back(group_detail::T_iri(*wdid, living_web::kGovRootCapability, z.id));
  t.push_back(group_detail::T_iri(z.invoker, living_web::kGovHasZcap, z.id));

  group_detail::ScopedActive active(identity_, creator->id);
  if (!W->AddTriples(t)) {
    last_error_ = W->last_error();
    return false;
  }
  if (out_cap_id)
    *out_cap_id = z.id;
  return true;
}

std::string GovernanceBackend::EnsureRootCapability(
    GraphBackend* W,
    const std::string& creator_cred_id) {
  std::optional<std::string> wdid = W ? W->did() : std::nullopt;
  if (!wdid || wdid->empty()) {
    last_error_ = "InvalidStateError";
    return std::string();
  }
  if (std::string existing = RootCapabilityId(W, *wdid); !existing.empty())
    return existing;
  std::string root;
  if (!MintRootCapability(W, creator_cred_id, std::nullopt, &root))
    return std::string();
  return root;
}

// ---- §4.5.1 install the capability constraint ------------------------------

bool GovernanceBackend::InstallCapabilityConstraint(
    GraphBackend* W,
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
  std::string cid = NewUrnUuid();
  std::vector<living_web::Triple> t;
  t.push_back(group_detail::T_iri(cid, living_web::kGovEntryType,
                                  living_web::kGovConstraintEntryType));
  t.push_back(group_detail::T_lit(cid, living_web::kGovConstraintKind,
                                  living_web::kConstraintKindCapability));
  if (predicates && !predicates->empty())
    t.push_back(group_detail::T_lit(cid, living_web::kGovCapabilityPredicates,
                                    living_web::JoinActions(*predicates)));
  t.push_back(group_detail::T_iri(*wdid, living_web::kGovHasConstraint, cid));

  group_detail::ScopedActive active(identity_, author->id);
  if (!W->AddTriples(t)) {
    last_error_ = W->last_error();
    return false;
  }
  if (out_constraint_id)
    *out_constraint_id = cid;
  return true;
}

// ---- §4.5.3 delegation -----------------------------------------------------

bool GovernanceBackend::Delegate(GraphBackend* W,
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
  gov_detail::Zcap parent = ResolveZcap(W, req.parent_capability);
  if (!parent.present) {
    last_error_ = "unknown_parent";
    return false;
  }
  if (!SignerActsAs(W, signer, parent.invoker)) {
    last_error_ = "not_authorised";
    return false;
  }
  if (!living_web::ActionInSet(living_web::kActionDelegateCapability,
                               parent.actions)) {
    last_error_ = "missing_delegate_capability";
    return false;
  }
  std::string resource = req.resource ? *req.resource : parent.resource;
  if (resource != parent.resource) {
    last_error_ = "attenuation_resource";  // §8 resource equality
    return false;
  }
  std::string actions = living_web::JoinActions(req.actions);
  if (!living_web::ActionsSubset(actions, parent.actions)) {
    last_error_ = "attenuation_actions";  // §8 child.actions ⊆ parent.actions
    return false;
  }
  if (!living_web::CaveatsAttenuationOk(parent.caveats, req.caveats)) {
    last_error_ = "attenuation_caveats";  // §8 immutable caveats
    return false;
  }
  gov_detail::Zcap z;
  z.id = NewUrnUuid();
  z.invoker = req.invoker;
  z.parent_capability = parent.id;
  z.actions = actions;
  z.resource = resource;
  z.caveats = req.caveats;
  z.proof_purpose = living_web::kProofPurposeCapabilityDelegation;
  z.proof_method =
      signer->did + "#" +
      *living_web::did_key::Ed25519PublicKeyMultibase(signer->public_key);
  z.created = NowRfc3339();

  if (!SignZcap(signer, &z))
    return false;

  std::vector<living_web::Triple> t = ZcapTriples(z);
  t.push_back(group_detail::T_iri(req.invoker, living_web::kGovHasZcap, z.id));

  group_detail::ScopedActive active(identity_, signer->id);
  if (!W->AddTriples(t)) {
    last_error_ = W->last_error();
    return false;
  }
  if (out_cap_id)
    *out_cap_id = z.id;
  return true;
}

// ---- §4.5.5 revocation -----------------------------------------------------

bool GovernanceBackend::Revoke(GraphBackend* W,
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
  gov_detail::Zcap target = ResolveZcap(W, zcap_id);
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
  if (!W->AddTriples({group_detail::T_iri(
          revoker->did, living_web::kGovRevokesCapability, zcap_id)})) {
    last_error_ = W->last_error();
    return false;
  }
  return true;
}

// ---- §11.3 myCapabilities --------------------------------------------------

std::vector<CapabilityInfo> GovernanceBackend::MyCapabilities(
    GraphBackend* W,
    const std::string& author_did) {
  std::vector<CapabilityInfo> out;
  std::optional<std::string> wdid = W ? W->did() : std::nullopt;
  if (!wdid)
    return out;
  std::string now = NowRfc3339();
  ValidationContext ctx;
  ctx.graph = W;
  ctx.graph_did = *wdid;
  ctx.author_did = author_did;
  ctx.is_non_triple_op = true;
  ctx.now = now;
  for (const std::string& cid : AllCapabilityIds(W)) {
    gov_detail::Zcap z = ResolveZcap(W, cid);
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
    info.actions = living_web::ParseActions(z.actions);
    info.resource = z.resource;
    info.caveats = z.caveats;
    if (auto exp = ExpiryOf(z.caveats))
      info.expires = *exp;
    out.push_back(std::move(info));
  }
  return out;
}

// ---- browser integration helpers (§11 / §8.1.5) ----------------------------

std::string GovernanceBackend::ActiveAuthorDid() const {
  const DIDKeyPair* active = identity_->GetActiveCredential();
  return active ? active->did : std::string();
}

std::string GovernanceBackend::ActiveCredentialId() const {
  const DIDKeyPair* active = identity_->GetActiveCredential();
  return active ? active->id : std::string();
}

bool GovernanceBackend::ResolveDelegationRecord(GraphBackend* W,
                                                const std::string& cap_id,
                                                DelegationRecord* out) {
  if (!W || !out)
    return false;
  gov_detail::Zcap z = ResolveZcap(W, cap_id);
  if (!z.present)
    return false;

  // The flattened ZCAP-LD object whose fields the §4.5.3.1 proof was computed
  // over. |actions| is projected as a JSON array (the wire/renderer shape) and
  // |caveats| is spliced in as parsed JSON so the document round-trips as a
  // structured object rather than a nested string literal.
  base::Value::Dict doc;
  doc.Set("id", z.id);
  doc.Set("invoker", z.invoker);
  doc.Set("parentCapability", z.parent_capability);
  base::Value::List actions;
  for (const std::string& a : living_web::ParseActions(z.actions))
    actions.Append(a);
  doc.Set("actions", std::move(actions));
  doc.Set("resource", z.resource);
  if (!z.caveats.empty()) {
    std::optional<base::Value> caveats = base::JSONReader::Read(z.caveats);
    if (caveats && caveats->is_list())
      doc.Set("caveats", std::move(*caveats));
  }
  doc.Set("proofPurpose", z.proof_purpose);
  doc.Set("created", z.created);

  std::string data_json;
  if (!base::JSONWriter::Write(doc, &data_json))
    return false;

  // The proof's signer DID is the verification method's DID (fragment stripped).
  std::string signer = z.proof_method;
  size_t hash = signer.find('#');
  if (hash != std::string::npos)
    signer = signer.substr(0, hash);

  out->author = signer;
  out->timestamp = z.created;
  out->data_json = std::move(data_json);
  out->proof_method = z.proof_method;
  out->proof_value = z.proof_value;
  return true;
}

// ---- §11.4 setEnforcementMode ----------------------------------------------

bool GovernanceBackend::SetEnforcementMode(GraphBackend* W,
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
  std::vector<living_web::Triple> existing;
  TripleQuery q;
  q.subject = *wdid;
  q.predicate = living_web::kGovEnforcementMode;
  if (W->QueryTriples(q, &existing)) {
    for (const auto& t : existing) {
      bool removed = false;
      W->RemoveTriple(t, &removed);
    }
  }
  if (!W->AddTriples({group_detail::T_lit(*wdid, living_web::kGovEnforcementMode,
                                          EnforcementModeToken(mode))})) {
    last_error_ = W->last_error();
    return false;
  }
  return true;
}

// ---- §7 + §6.3 core validate -----------------------------------------------

GovernanceValidationResult GovernanceBackend::Validate(
    GraphBackend* W,
    const std::optional<living_web::Triple>& triple,
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
  ctx.now = NowRfc3339();

  // §10 immutable-seed guard — all modes, before any capability logic.
  if (triple && triple->subject == W_did &&
      IsImmutableSeedPredicate(triple->predicate)) {
    res.allowed = false;
    res.rejected_by = W_did;
    res.constraint_kind = "capability";
    res.reason = "immutable_seed_predicate";
    return res;
  }

  std::string action =
      action_override
          ? *action_override
          : DeriveAction(triple ? triple->predicate : std::string(),
                         /*is_removal=*/false);
  ctx.action = action;

  std::vector<GraphConstraint> constraints = CollectConstraints(W, W_did);

  // §7 capability constraints.
  std::vector<const GraphConstraint*> caps;
  for (const auto& c : constraints)
    if (c.kind == living_web::kConstraintKindCapability)
      caps.push_back(&c);

  if (!caps.empty() && mode != "open") {
    bool covered = true;  // §7 step 4 predicate-coverage (triple ops only)
    if (triple && !is_non_triple) {
      bool any_restricted = false, in_some = false;
      for (const auto* c : caps) {
        auto preds = c->Property(living_web::kGovCapabilityPredicates);
        if (preds && !preds->empty()) {
          any_restricted = true;
          for (const auto& p : living_web::ParseActions(*preds))
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
                                       author_did, action, is_non_triple,
                                       &reason);
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
    if (c.kind == living_web::kConstraintKindCapability)
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

// ---- ZCAP resolution / serialisation ---------------------------------------

std::vector<living_web::Triple> GovernanceBackend::ZcapTriples(
    const gov_detail::Zcap& z) const {
  std::vector<living_web::Triple> t;
  t.push_back(group_detail::T_iri(z.id, living_web::kRdfType,
                                  living_web::kZcapDelegation));
  t.push_back(group_detail::T_iri(z.id, living_web::kZcapInvoker, z.invoker));
  t.push_back(group_detail::T_iri(z.id, living_web::kZcapParentCapability,
                                  z.parent_capability));
  t.push_back(group_detail::T_lit(z.id, living_web::kZcapActions, z.actions));
  t.push_back(group_detail::T_iri(z.id, living_web::kZcapResource, z.resource));
  if (!z.caveats.empty())
    t.push_back(group_detail::T_lit(z.id, living_web::kZcapCaveats, z.caveats));
  t.push_back(
      group_detail::T_lit(z.id, living_web::kZcapProofValue, z.proof_value));
  t.push_back(
      group_detail::T_lit(z.id, living_web::kZcapProofPurpose, z.proof_purpose));
  t.push_back(
      group_detail::T_iri(z.id, living_web::kZcapProofMethod, z.proof_method));
  t.push_back(group_detail::T_lit(z.id, living_web::kZcapCreated, z.created,
                                  living_web::kXsdDateTime));
  return t;
}

gov_detail::Zcap GovernanceBackend::ResolveZcap(GraphBackend* W,
                                                const std::string& cap_id) {
  gov_detail::Zcap z;
  z.id = cap_id;
  TripleQuery q;
  q.subject = cap_id;
  std::vector<living_web::Triple> ts;
  if (!W->QueryTriples(q, &ts))
    return z;
  std::string actions;
  for (const auto& t : ts) {
    const std::string& p = t.predicate;
    auto iri = [&]() {
      return t.object.is_literal() ? std::string() : t.object.iri_or_bnode;
    };
    auto lit = [&]() {
      return t.object.is_literal() ? t.object.literal->lexical : std::string();
    };
    if (p == living_web::kRdfType) {
      if (iri() == living_web::kZcapDelegation)
        z.present = true;
    } else if (p == living_web::kZcapInvoker) {
      z.invoker = iri();
    } else if (p == living_web::kZcapParentCapability) {
      z.parent_capability = iri();
    } else if (p == living_web::kZcapActions) {
      // Tolerate both the single comma-string form and one-triple-per-action.
      if (!actions.empty())
        actions += ",";
      actions += lit();
    } else if (p == living_web::kZcapResource) {
      z.resource = iri();
    } else if (p == living_web::kZcapCaveats) {
      z.caveats = lit();
    } else if (p == living_web::kZcapProofValue) {
      z.proof_value = lit();
    } else if (p == living_web::kZcapProofPurpose) {
      z.proof_purpose = lit();
    } else if (p == living_web::kZcapProofMethod) {
      z.proof_method = iri();
    } else if (p == living_web::kZcapCreated) {
      z.created = lit();
    }
  }
  z.actions = actions;
  return z;
}

bool GovernanceBackend::SignZcap(const DIDKeyPair* signer, gov_detail::Zcap* z) {
  std::string preimage =
      living_web::BuildDelegationProofPreimage(gov_detail::ToFields(*z));
  std::string hash = crypto::SHA256HashString(preimage);
  auto sig = identity_->SignRaw(
      signer->id, std::vector<uint8_t>(hash.begin(), hash.end()));
  if (!sig) {
    last_error_ = "InvalidStateError";
    return false;
  }
  z->proof_value = living_web::did_key::MultibaseEncode(*sig);
  return true;
}

// ---- proof verification (§7 step 6.5.2, §13.1) -----------------------------

bool GovernanceBackend::VerifyProofRaw(const gov_detail::Zcap& z,
                                       const std::vector<uint8_t>& pubkey) {
  if (pubkey.size() != 32)
    return false;
  std::string preimage =
      living_web::BuildDelegationProofPreimage(gov_detail::ToFields(z));
  std::string hash = crypto::SHA256HashString(preimage);
  auto sig = living_web::did_key::MultibaseDecode(z.proof_value);
  if (!sig || sig->size() != 64)
    return false;
  return ed25519_verify(sig->data(),
                        reinterpret_cast<const uint8_t*>(hash.data()),
                        hash.size(), pubkey.data()) == 1;
}

bool GovernanceBackend::VerifyProofBy(GraphBackend* W, const gov_detail::Zcap& z,
                                      const std::string& signer) {
  if (living_web::did_graph::IsDidGraph(signer)) {
    living_web::DidDocument doc;
    group_detail::ProjectDidDocument(W, signer, &doc);
    for (const auto& m : doc.capability_delegation) {
      auto key =
          living_web::DecodePublicKeyMultibase(gov_detail::Fragment(m));
      if (key && VerifyProofRaw(z, *key))
        return true;
    }
    return false;
  }
  auto key = living_web::ParseAnyDidEd25519(signer);
  return key && VerifyProofRaw(z, *key);
}

bool GovernanceBackend::VerifyBootstrapProof(GraphBackend* W,
                                             const std::string& W_did,
                                             const gov_detail::Zcap& z) {
  auto ikey = living_web::ParseAnyDidEd25519(z.invoker);
  if (ikey && VerifyProofRaw(z, *ikey))
    return true;
  living_web::DidDocument doc;
  group_detail::ProjectDidDocument(W, W_did, &doc);
  for (const auto& m : doc.capability_delegation) {
    auto key = living_web::DecodePublicKeyMultibase(gov_detail::Fragment(m));
    if (key && VerifyProofRaw(z, *key))
      return true;
  }
  return false;
}

// ---- chain walk (§7 step 6.5) ----------------------------------------------

bool GovernanceBackend::WalkChain(GraphBackend* W, gov_detail::Zcap cap,
                                  int depth) {
  std::string W_did = W->did().value_or("");
  while (true) {
    if (depth > 10)  // step 6.5.1
      return false;
    if (cap.parent_capability == living_web::kBootstrapRoot) {  // step 6.5.4
      if (cap.id != RootCapabilityId(W, W_did))
        return false;
      return VerifyBootstrapProof(W, W_did, cap);
    }
    gov_detail::Zcap parent =
        ResolveZcap(W, cap.parent_capability);  // step 6.5.5
    if (!parent.present)
      return false;
    if (!VerifyProofBy(W, cap, parent.invoker))  // step 6.5.2
      return false;
    if (!living_web::ActionInSet(living_web::kActionDelegateCapability,
                                 parent.actions))  // step 6.5.3
      return false;
    if (!AttenuationOk(cap, parent))  // step 6.5.6
      return false;
    if (IsRevoked(W, parent.id))  // step 6.5.7
      return false;
    cap = parent;  // step 6.5.8
    ++depth;
  }
}

// ---- §7 candidate evaluation -----------------------------------------------

bool GovernanceBackend::RunCapabilityAlgorithm(
    GraphBackend* W, const std::string& W_did, const std::string& W_iri,
    const std::optional<living_web::Triple>& triple,
    const std::string& author_did, const std::string& action, bool is_non_triple,
    std::string* reason) {
  ValidationContext ctx;
  ctx.graph = W;
  ctx.graph_did = W_did;
  ctx.graph_iri = W_iri;
  ctx.author_did = author_did;
  ctx.action = action;
  ctx.is_non_triple_op = is_non_triple;
  ctx.now = NowRfc3339();

  *reason = "no_matching_capability";
  for (const std::string& cid : AllCapabilityIds(W)) {
    gov_detail::Zcap z = ResolveZcap(W, cid);
    if (!z.present || !Eligible(W, z, author_did))
      continue;
    if (!living_web::ActionInSet(action, z.actions)) {  // step 6.1
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

bool GovernanceBackend::Eligible(GraphBackend* W, const gov_detail::Zcap& z,
                                 const std::string& author) {
  if (z.invoker == author)
    return true;
  if (living_web::did_graph::IsDidGraph(z.invoker) &&
      AgentInSection(W, z.invoker,
                     living_web::DIDCapabilitySection::kCapabilityInvocation,
                     author))
    return true;
  return false;
}

// ---- caveats (§9) ----------------------------------------------------------

bool GovernanceBackend::EvaluateCaveats(
    const std::string& caveats_raw,
    const std::optional<living_web::Triple>& triple, const std::string& action,
    const ValidationContext& ctx, const std::string& zcap_id,
    std::string* reason) {
  if (caveats_raw.empty())
    return true;
  std::vector<std::string> elems;
  if (!living_web::SplitJsonArray(caveats_raw, &elems)) {
    *reason = "caveat_malformed";
    return false;  // fail-closed
  }
  // Expose the owning delegation's id to per-delegation caveat handlers (the
  // Spec 08 rateLimit / cardinality counters key on it) without disturbing the
  // caller's context.
  ValidationContext local = ctx;
  local.zcap_id = zcap_id;
  for (const std::string& e : elems) {
    auto type = living_web::JsonStringField(e, "type");
    if (!type) {
      *reason = "caveat_malformed";
      return false;
    }
    if (*type == "expiry") {  // §9.2 core caveat — applies to non-triple ops too
      auto val = living_web::JsonRawField(e, "value");
      auto exp =
          val ? living_web::JsonStringField(*val, "expiresAt") : std::nullopt;
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
    cav.value_raw = living_web::JsonRawField(e, "value").value_or("");
    cav.raw = e;
    HandlerResult r = it->second->Evaluate(cav, triple, action, local);
    if (!r.allowed) {
      *reason = "caveat_failed:" + *type;
      return false;
    }
  }
  return true;
}

std::optional<std::string> GovernanceBackend::ExpiryOf(
    const std::string& caveats_raw) {
  if (caveats_raw.empty())
    return std::nullopt;
  std::vector<std::string> elems;
  if (!living_web::SplitJsonArray(caveats_raw, &elems))
    return std::nullopt;
  for (const std::string& e : elems) {
    auto type = living_web::JsonStringField(e, "type");
    if (type && *type == "expiry") {
      auto val = living_web::JsonRawField(e, "value");
      if (val)
        return living_web::JsonStringField(*val, "expiresAt");
    }
  }
  return std::nullopt;
}

// ---- revocation (§4.5.5) ---------------------------------------------------

bool GovernanceBackend::IsRevoked(GraphBackend* W, const std::string& cap_id) {
  if (pending_revocations_.count(cap_id))
    return true;
  TripleQuery q;
  q.predicate = living_web::kGovRevokesCapability;
  std::vector<living_web::Triple> ts;
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

bool GovernanceBackend::ValidRevoker(GraphBackend* W, const std::string& revoker,
                                     const std::string& cap_id) {
  for (const std::string& inv : AncestorInvokers(W, cap_id)) {
    if (inv == revoker)
      return true;
    if (living_web::did_graph::IsDidGraph(inv) &&
        AgentInSection(W, inv,
                       living_web::DIDCapabilitySection::kCapabilityDelegation,
                       revoker))
      return true;
  }
  return false;
}

std::vector<std::string> GovernanceBackend::AncestorInvokers(
    GraphBackend* W,
    const std::string& cap_id) {
  std::vector<std::string> out;
  gov_detail::Zcap cur = ResolveZcap(W, cap_id);
  if (!cur.present)
    return out;
  int depth = 0;
  while (depth++ < 10) {
    if (cur.parent_capability == living_web::kBootstrapRoot)
      break;
    gov_detail::Zcap parent = ResolveZcap(W, cur.parent_capability);
    if (!parent.present)
      break;
    out.push_back(parent.invoker);
    cur = parent;
  }
  return out;
}

// ---- §13.10 brick-state ----------------------------------------------------

bool GovernanceBackend::WouldBrickGovernance(
    GraphBackend* W,
    const std::string& W_did,
    const std::set<std::string>& pending) {
  pending_revocations_ = pending;
  struct Clear {
    raw_ptr<std::set<std::string>> p;
    ~Clear() { p->clear(); }
  } clear{&pending_revocations_};

  ValidationContext ctx;
  ctx.graph = W;
  ctx.graph_did = W_did;
  ctx.is_non_triple_op = true;
  ctx.now = NowRfc3339();

  for (const std::string& cid : AllCapabilityIds(W)) {
    gov_detail::Zcap z = ResolveZcap(W, cid);
    if (!z.present)
      continue;
    if (!living_web::ActionInSet(living_web::kActionUpdateGovernance, z.actions))
      continue;
    if (IsRevoked(W, z.id))
      continue;
    std::string reason;
    if (!EvaluateCaveats(z.caveats, std::nullopt,
                         living_web::kActionUpdateGovernance, ctx, z.id,
                         &reason))
      continue;
    if (!WalkChain(W, z, 0))
      continue;
    if (InvokerHasCurrentDelegate(W, z.invoker))
      return false;  // a governance capability survives → not bricked
  }
  return true;
}

bool GovernanceBackend::InvokerHasCurrentDelegate(GraphBackend* W,
                                                  const std::string& invoker) {
  if (!living_web::did_graph::IsDidGraph(invoker))
    return true;  // a did:key agent is itself the exerciser
  living_web::DidDocument doc;
  group_detail::ProjectDidDocument(W, invoker, &doc);
  return !doc.capability_invocation.empty();
}

// ---- shared helpers --------------------------------------------------------

std::vector<std::string> GovernanceBackend::AllCapabilityIds(GraphBackend* W) {
  std::set<std::string> ids;
  TripleQuery q;
  q.predicate = living_web::kGovHasZcap;
  std::vector<living_web::Triple> ts;
  if (W->QueryTriples(q, &ts))
    for (const auto& t : ts)
      if (!t.object.is_literal())
        ids.insert(t.object.iri_or_bnode);
  return std::vector<std::string>(ids.begin(), ids.end());
}

std::string GovernanceBackend::RootCapabilityId(GraphBackend* W,
                                                const std::string& W_did) {
  return group_detail::FirstIriOf(W, W_did, living_web::kGovRootCapability)
      .value_or("");
}

bool GovernanceBackend::AgentInSection(GraphBackend* W,
                                       const std::string& graph_did,
                                       living_web::DIDCapabilitySection section,
                                       const std::string& agent_did) {
  auto akey = living_web::ParseAnyDidEd25519(agent_did);
  if (!akey)
    return false;
  for (const auto& o : group_detail::QueryObjects(
           W, graph_did, living_web::SectionPredicate(section))) {
    if (o.is_literal())
      continue;
    auto key = living_web::DecodePublicKeyMultibase(
        gov_detail::Fragment(o.iri_or_bnode));
    if (key && *key == *akey)
      return true;
  }
  return false;
}

bool GovernanceBackend::SignerActsAs(GraphBackend* W, const DIDKeyPair* signer,
                                     const std::string& principal) {
  if (signer->did == principal)
    return true;
  if (living_web::did_graph::IsDidGraph(principal) &&
      AgentInSection(W, principal,
                     living_web::DIDCapabilitySection::kCapabilityDelegation,
                     signer->did))
    return true;
  return false;
}

bool GovernanceBackend::AuthoriseGovernance(GraphBackend* W,
                                            const std::string& W_did,
                                            const std::string& author_did) {
  std::string iri;
  W->GetIri(&iri);
  std::string reason;
  return RunCapabilityAlgorithm(W, W_did, iri, std::nullopt, author_did,
                                living_web::kActionUpdateGovernance,
                                /*is_non_triple=*/true, &reason);
}

bool GovernanceBackend::HasCapabilityConstraint(GraphBackend* W,
                                                const std::string& W_did) {
  for (const auto& c : CollectConstraints(W, W_did))
    if (c.kind == living_web::kConstraintKindCapability)
      return true;
  return false;
}

std::vector<GraphConstraint> GovernanceBackend::CollectConstraints(
    GraphBackend* W,
    const std::string& W_did) {
  std::vector<GraphConstraint> out;
  if (!W)
    return out;
  for (const auto& o :
       group_detail::QueryObjects(W, W_did, living_web::kGovHasConstraint)) {
    if (o.is_literal())
      continue;
    const std::string& cid = o.iri_or_bnode;
    auto kind = group_detail::FirstLiteralOf(W, cid, living_web::kGovConstraintKind);
    if (!kind)
      continue;  // a constraint MUST declare a kind (§4.1)
    GraphConstraint gc;
    gc.id = cid;
    gc.scope = W_did;
    gc.kind = *kind;
    TripleQuery q;
    q.subject = cid;
    std::vector<living_web::Triple> ts;
    if (W->QueryTriples(q, &ts)) {
      for (const auto& t : ts) {
        if (t.predicate == living_web::kGovConstraintKind ||
            t.predicate == living_web::kGovEntryType)
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

std::string GovernanceBackend::GetEnforcementModeToken(GraphBackend* W) {
  if (!W)
    return "open";
  std::optional<std::string> wdid = W->did();
  if (!wdid)
    return "open";
  return group_detail::FirstLiteralOf(W, *wdid, living_web::kGovEnforcementMode)
      .value_or("open");
}

}  // namespace content
