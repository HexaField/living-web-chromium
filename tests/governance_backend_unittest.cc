// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 04 browser-process governance port
// (content::GovernanceBackend) plus the shared Chromium-independent ZCAP-LD
// canonicalisation core (content/browser/governance/zcap.{h,cc}) — the Graph
// Capability Framework. These exercise the same normative behaviour as the
// standalone Cap_*/Zcap_* conformance harness, but against the browser port bound
// to content::DIDKeyProvider, content::GraphBackendManager and
// content::GroupBackendManager, so the full-tree content_unittests build has
// direct coverage of the §4–§13 authority-is-constituted algorithms, their
// DOMException error names, and the §8.1.5 delegateCapability SignedContent
// projection. The byte-critical core (the §4.5.3.1 delegation-proof pre-image,
// the §8 actions-subset / immutable-caveats attenuation tests, and the caveat
// scanner) is shared verbatim with the standalone harness, so the bytes a proof
// signs never diverge between the two build worlds.

#include "content/browser/governance/governance_backend.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/did/group_backend_manager.h"
#include "content/browser/governance/zcap.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

using living_web::DIDCapabilitySection;
using living_web::kActionCreateLink;
using living_web::kActionDelegateCapability;
using living_web::kActionRemoveLink;
using living_web::kActionUpdateGovernance;
using living_web::Triple;

// A one-element expiry-caveat array at the given RFC-3339 instant (§9.2).
std::string ExpiryCaveat(const std::string& at) {
  return "[{\"type\":\"expiry\",\"value\":{\"expiresAt\":\"" + at + "\"}}]";
}

// A plug-in constraint kind (§9.3) that blocks writes to a named predicate.
class BlockPredicateConstraint : public ConstraintKindHandler {
 public:
  std::string kind() const override { return "blockPredicate"; }
  HandlerResult Validate(const std::optional<Triple>& triple,
                         const GraphConstraint& constraint,
                         const ValidationContext&) override {
    HandlerResult r;
    auto blocked = constraint.Property("governance://blocked_predicate");
    if (triple && blocked && triple->predicate == *blocked) {
      r.allowed = false;
      r.reason = "blocked_predicate";
    }
    return r;
  }
};

// A plug-in caveat (§9.3) that forbids a specific object-literal value.
class ForbidValueCaveat : public CaveatHandler {
 public:
  std::string type() const override { return "forbidValue"; }
  bool appliesToNonTripleOps() const override { return false; }
  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& triple,
                         const std::string&,
                         const ValidationContext&) override {
    HandlerResult r;
    auto forbidden = living_web::JsonStringField(caveat.value_raw, "equals");
    if (triple && forbidden && triple->object.is_literal() &&
        triple->object.literal->lexical == *forbidden) {
      r.allowed = false;
      r.reason = "forbidden_value";
    }
    return r;
  }
};

// ---- shared ZCAP core (§4.5.3.1, §4.3, §8; zcap.{h,cc}) --------------------
//
// These assert the byte-critical core that the browser port and the standalone
// harness link verbatim, so the amendment-pinned invariants (exact proof
// pre-image, framework-core default actions) are guarded in the browser build
// too, not only the standalone one.

TEST(GovernanceZcapCoreTest, DelegationProofPreimageExactBytes) {
  living_web::ZcapProofFields fields;
  fields.id = "urn:uuid:cap";
  fields.invoker = "did:key:z6MkInvoker";
  fields.parent_capability = "urn:living-web:zcap:BootstrapRoot";
  fields.actions = "createLink,removeLink";
  fields.resource = "did:graph:z6MkGraph";
  fields.caveats = "";
  fields.proof_purpose = "capabilityDelegation";
  fields.created = "2026-07-08T00:00:00Z";
  const std::string expected =
      "living-web/zcap/delegation/v1\n"
      "urn:uuid:cap\n"
      "did:key:z6MkInvoker\n"
      "urn:living-web:zcap:BootstrapRoot\n"
      "createLink,removeLink\n"
      "did:graph:z6MkGraph\n"
      "\n"  // empty caveats field
      "capabilityDelegation\n"
      "2026-07-08T00:00:00Z";
  EXPECT_EQ(living_web::BuildDelegationProofPreimage(fields), expected);
}

TEST(GovernanceZcapCoreTest, DefaultRootActionsAreFrameworkCore) {
  auto a = living_web::DefaultRootActions();
  EXPECT_EQ(a.size(), 8u);
  const std::string joined = living_web::JoinActions(a);
  EXPECT_TRUE(living_web::ActionInSet("createLink", joined));
  EXPECT_TRUE(living_web::ActionInSet("updateGovernance", joined));
  EXPECT_TRUE(living_web::ActionInSet("delegateCapability", joined));
  EXPECT_TRUE(living_web::ActionInSet("announceFork", joined));
  // §4.3 amendment: updateSHACL is a Spec-07 extension, NOT a default action.
  EXPECT_FALSE(living_web::ActionInSet("updateSHACL", joined));
}

TEST(GovernanceZcapCoreTest, CaveatsAttenuationIsImmutable) {
  // §8 immutable caveats: every parent element must reappear byte-identically.
  EXPECT_TRUE(living_web::CaveatsAttenuationOk("", "[{\"type\":\"x\"}]"));
  EXPECT_TRUE(living_web::CaveatsAttenuationOk(
      "[{\"type\":\"x\"}]", "[{\"type\":\"x\"},{\"type\":\"y\"}]"));
  EXPECT_FALSE(
      living_web::CaveatsAttenuationOk("[{\"type\":\"x\"}]", "[{\"type\":\"y\"}]"));
  EXPECT_FALSE(living_web::CaveatsAttenuationOk("[{\"type\":\"x\"}]", ""));
  EXPECT_FALSE(
      living_web::CaveatsAttenuationOk("bad", "[{\"type\":\"x\"}]"));  // fail-closed
}

// ---- fixture ---------------------------------------------------------------

// A governance fixture mirroring the standalone GovFixture: a group W (a graph
// bearing a did:graph whose DID document holds the group key in every capability
// section) plus a GovernanceBackend over the same DIDKeyProvider. Each write is
// authored by the group's constitutional key (gcred_, whose did == W's did:graph).
class GovernanceBackendTest : public testing::Test {
 protected:
  GovernanceBackendTest()
      : graphs_(&identity_), groups_(&identity_, &graphs_), gov_(&identity_) {
    identity_.CreateKey("Human");  // the first key is active by default
    GroupCreationOptions o;
    o.sync_module = "urn:sync:module:default";
    o.display_name = "Governed";
    group_ = groups_.CreateGroup(o);
    gcred_ = CredIdForDid(group_->did());
  }

  // The credential whose DID equals |did| — for a group, its own adopted key.
  std::string CredIdForDid(const std::string& did) const {
    for (const DIDKeyPair* c : identity_.ListCredentials())
      if (c->did == did)
        return c->id;
    return std::string();
  }

  // Mint the root, install the capability constraint, and enter enforced mode,
  // all authored by the group key. Returns the root capability id.
  std::string BootstrapEnforced() {
    std::string root;
    EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
    std::string cid;
    EXPECT_TRUE(
        gov_.InstallCapabilityConstraint(W(), gcred_, std::nullopt, &cid));
    EXPECT_TRUE(
        gov_.SetEnforcementMode(W(), gcred_, EnforcementMode::kEnforced));
    return root;
  }

  GraphBackend* W() { return group_->graph(); }
  const std::string& Wdid() { return group_->did(); }

  DIDKeyProvider identity_;
  GraphBackendManager graphs_;
  GroupBackendManager groups_;
  GovernanceBackend gov_;
  std::unique_ptr<GroupBackend> group_;
  std::string gcred_;
};

// ---- bootstrap: mint the root (§4.3) ---------------------------------------

TEST_F(GovernanceBackendTest, MintRootCapabilityRecordsAndLists) {
  std::string root;
  EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
  EXPECT_EQ(root.substr(0, 9), "urn:uuid:");
  // The root is invoked by the graph DID and lists its framework-core actions.
  auto caps = gov_.MyCapabilities(W(), Wdid());
  ASSERT_EQ(caps.size(), 1u);
  EXPECT_EQ(caps[0].id, root);
  EXPECT_EQ(caps[0].resource, Wdid());
  EXPECT_TRUE(
      living_web::ActionInSet("updateGovernance",
                              living_web::JoinActions(caps[0].actions)));
}

TEST_F(GovernanceBackendTest, MintRootRequiresGraphDid) {
  GraphBackend* g = graphs_.Create("Plain");  // a local graph with no DID (§4.5.2)
  std::string root;
  EXPECT_FALSE(gov_.MintRootCapability(g, gcred_, std::nullopt, &root));
  EXPECT_EQ(gov_.last_error(), "InvalidStateError");
}

// ---- enforcement modes (§5.1) ----------------------------------------------

TEST_F(GovernanceBackendTest, OpenModeSkipsCapabilityChecks) {
  std::string root;
  EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
  std::string cid;
  EXPECT_TRUE(gov_.InstallCapabilityConstraint(W(), gcred_, std::nullopt, &cid));
  // Default mode is open: an undelegated stranger is still allowed (§5.1).
  std::unique_ptr<DIDKeyPair> stranger = identity_.CreateKey("Stranger");
  auto r = gov_.CanAddTriple(
      W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"), stranger->did);
  EXPECT_TRUE(r.allowed);
  EXPECT_EQ(r.mode, "open");
}

TEST_F(GovernanceBackendTest, EnforcedAllowsHolderDeniesStranger) {
  BootstrapEnforced();
  // The graph DID (the root invoker) is authorised.
  auto ok = gov_.CanAddTriple(
      W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"), Wdid());
  EXPECT_TRUE(ok.allowed);
  EXPECT_EQ(ok.mode, "enforced");
  // A stranger holding no capability is denied, attributed to the constraint.
  std::unique_ptr<DIDKeyPair> stranger = identity_.CreateKey("Stranger");
  auto no = gov_.CanAddTriple(
      W(), group_detail::T_lit("urn:n:2", "urn:p:body", "hi"), stranger->did);
  EXPECT_FALSE(no.allowed);
  EXPECT_EQ(no.constraint_kind, "capability");
}

TEST_F(GovernanceBackendTest, AnnouncedModeComputesButAccepts) {
  std::string root;
  EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
  std::string cid;
  EXPECT_TRUE(gov_.InstallCapabilityConstraint(W(), gcred_, std::nullopt, &cid));
  EXPECT_TRUE(gov_.SetEnforcementMode(W(), gcred_, EnforcementMode::kAnnounced));
  // A stranger would fail the capability check, but announced never rejects.
  std::unique_ptr<DIDKeyPair> stranger = identity_.CreateKey("Stranger");
  auto r = gov_.CanAddTriple(
      W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"), stranger->did);
  EXPECT_TRUE(r.allowed);
  EXPECT_EQ(r.mode, "announced");
}

// ---- delegation + attenuation (§4.5.3, §8) ---------------------------------

TEST_F(GovernanceBackendTest, DelegateAttenuatesActions) {
  std::string root = BootstrapEnforced();
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");

  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  std::string child;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, req, &child));

  // Member can createLink...
  EXPECT_TRUE(gov_.CanAddTriple(
                     W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"),
                     member->did)
                  .allowed);
  // ...but cannot updateGovernance (never delegated).
  EXPECT_FALSE(
      gov_.CanPerformAction(W(), kActionUpdateGovernance, member->did).allowed);

  // A mid cap that CAN delegate, but only createLink.
  DelegationRequest mid;
  mid.parent_capability = root;
  mid.invoker = member->did;
  mid.actions = {kActionCreateLink, kActionDelegateCapability};
  std::string midcap;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, mid, &midcap));

  // Member (mid invoker) cannot over-delegate an action outside mid (§8).
  std::unique_ptr<DIDKeyPair> m2 = identity_.CreateKey("M2");
  DelegationRequest over;
  over.parent_capability = midcap;
  over.invoker = m2->did;
  over.actions = {kActionRemoveLink};
  std::string x;
  EXPECT_FALSE(gov_.Delegate(W(), member->id, over, &x));
  EXPECT_EQ(gov_.last_error(), "attenuation_actions");
}

TEST_F(GovernanceBackendTest, DelegateRejectsResourceEscalation) {
  std::string root = BootstrapEnforced();
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  req.resource = "did:graph:z6MkSomethingElse";  // != parent.resource (§8)
  std::string x;
  EXPECT_FALSE(gov_.Delegate(W(), gcred_, req, &x));
  EXPECT_EQ(gov_.last_error(), "attenuation_resource");
}

TEST_F(GovernanceBackendTest, DelegateCaveatsAreImmutable) {
  std::string root = BootstrapEnforced();
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  // A mid cap carrying an expiry caveat + delegateCapability.
  DelegationRequest mid;
  mid.parent_capability = root;
  mid.invoker = member->did;
  mid.actions = {kActionCreateLink, kActionDelegateCapability};
  mid.caveats = ExpiryCaveat("2099-01-01T00:00:00Z");
  std::string midcap;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, mid, &midcap));

  std::unique_ptr<DIDKeyPair> m2 = identity_.CreateKey("M2");
  // Dropping the parent caveat is rejected (§8 immutable caveats).
  DelegationRequest drop;
  drop.parent_capability = midcap;
  drop.invoker = m2->did;
  drop.actions = {kActionCreateLink};
  drop.caveats = "";
  std::string x;
  EXPECT_FALSE(gov_.Delegate(W(), member->id, drop, &x));
  EXPECT_EQ(gov_.last_error(), "attenuation_caveats");

  // Preserving it byte-for-byte is accepted.
  DelegationRequest keep = drop;
  keep.caveats = ExpiryCaveat("2099-01-01T00:00:00Z");
  std::string ok;
  EXPECT_TRUE(gov_.Delegate(W(), member->id, keep, &ok));
}

TEST_F(GovernanceBackendTest, TwoLevelDelegationChainAuthorises) {
  std::string root = BootstrapEnforced();
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  DelegationRequest mid;
  mid.parent_capability = root;
  mid.invoker = member->did;
  mid.actions = {kActionCreateLink, kActionDelegateCapability};
  std::string midcap;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, mid, &midcap));

  std::unique_ptr<DIDKeyPair> m2 = identity_.CreateKey("M2");
  DelegationRequest leaf;
  leaf.parent_capability = midcap;
  leaf.invoker = m2->did;
  leaf.actions = {kActionCreateLink};
  std::string leafcap;
  EXPECT_TRUE(gov_.Delegate(W(), member->id, leaf, &leafcap));

  // The deepest invoker writes via the two-hop chain root → mid → leaf.
  EXPECT_TRUE(gov_.CanAddTriple(
                     W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"),
                     m2->did)
                  .allowed);
}

// ---- caveats (§9.2 expiry, §9.3 plug-ins) ----------------------------------

TEST_F(GovernanceBackendTest, ExpiryCaveatBlocksExpiredAllowsLive) {
  std::string root = BootstrapEnforced();

  std::unique_ptr<DIDKeyPair> expired = identity_.CreateKey("Expired");
  DelegationRequest e;
  e.parent_capability = root;
  e.invoker = expired->did;
  e.actions = {kActionCreateLink};
  e.caveats = ExpiryCaveat("2000-01-01T00:00:00Z");
  std::string ecap;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, e, &ecap));
  EXPECT_FALSE(gov_.CanAddTriple(
                      W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"),
                      expired->did)
                   .allowed);

  std::unique_ptr<DIDKeyPair> live = identity_.CreateKey("Live");
  DelegationRequest l;
  l.parent_capability = root;
  l.invoker = live->did;
  l.actions = {kActionCreateLink};
  l.caveats = ExpiryCaveat("2099-01-01T00:00:00Z");
  std::string lcap;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, l, &lcap));
  EXPECT_TRUE(gov_.CanAddTriple(
                     W(), group_detail::T_lit("urn:n:2", "urn:p:body", "hi"),
                     live->did)
                  .allowed);
}

TEST_F(GovernanceBackendTest, PluginCaveatHandler) {
  gov_.RegisterCaveatType(std::make_unique<ForbidValueCaveat>());
  std::string root = BootstrapEnforced();
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  req.caveats = "[{\"type\":\"forbidValue\",\"value\":{\"equals\":\"secret\"}}]";
  std::string child;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, req, &child));
  // The caveat forbids the object literal "secret".
  EXPECT_FALSE(gov_.CanAddTriple(
                      W(), group_detail::T_lit("urn:n:1", "urn:p:body", "secret"),
                      member->did)
                   .allowed);
  EXPECT_TRUE(gov_.CanAddTriple(
                     W(), group_detail::T_lit("urn:n:2", "urn:p:body", "ok"),
                     member->did)
                  .allowed);
}

// ---- revocation + brick protection (§4.5.5, §13.10) ------------------------

TEST_F(GovernanceBackendTest, RevokeBlocksDelegatee) {
  std::string root = BootstrapEnforced();
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  std::string child;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, req, &child));
  EXPECT_TRUE(gov_.CanAddTriple(
                     W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"),
                     member->did)
                  .allowed);

  // The graph DID (an ancestor invoker) revokes the child (§4.5.5).
  EXPECT_TRUE(gov_.Revoke(W(), gcred_, child));
  EXPECT_FALSE(gov_.CanAddTriple(
                      W(), group_detail::T_lit("urn:n:2", "urn:p:body", "hi"),
                      member->did)
                   .allowed);
}

TEST_F(GovernanceBackendTest, RootCapabilityIsUnrevokable) {
  std::string root;
  EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
  // The root has no ancestor invoker, so no agent has standing to revoke it.
  EXPECT_FALSE(gov_.Revoke(W(), gcred_, root));
  EXPECT_EQ(gov_.last_error(), "not_authorised_to_revoke");
}

TEST_F(GovernanceBackendTest, RevokeRefusedWhenItWouldBrickGovernance) {
  std::string root;
  EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
  // A did:key agent will hold the sole *exercisable* governance capability.
  std::unique_ptr<DIDKeyPair> agent = identity_.CreateKey("Agent");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = agent->did;
  req.actions = {kActionUpdateGovernance, kActionDelegateCapability};
  std::string gov_cap;
  EXPECT_TRUE(gov_.Delegate(W(), gcred_, req, &gov_cap));

  // White-box: strip the group key from the graph DID's capabilityInvocation so
  // the root (invoker = the graph DID) is no longer *exercisable*. The agent's
  // governance capability is then the only surviving one, and revoking it must
  // be refused as bricking (§13.10 true branch).
  {
    group_detail::ScopedActive active(&identity_, gcred_);
    for (const auto& o : group_detail::QueryObjects(
             W(), Wdid(),
             living_web::SectionPredicate(
                 DIDCapabilitySection::kCapabilityInvocation))) {
      if (o.is_literal())
        continue;
      bool removed = false;
      W()->RemoveTriple(
          group_detail::T_iri(Wdid(),
                              living_web::SectionPredicate(
                                  DIDCapabilitySection::kCapabilityInvocation),
                              o.iri_or_bnode),
          &removed);
    }
  }
  EXPECT_FALSE(gov_.Revoke(W(), gcred_, gov_cap));
  EXPECT_EQ(gov_.last_error(), "would_brick_governance");
}

// ---- immutable seeds (§10) -------------------------------------------------

TEST_F(GovernanceBackendTest, ImmutableSeedPredicateRejectedInAllModes) {
  // Rewriting the group's syncModule seed is rejected before any capability
  // logic, in every mode (§10) — the fixture is in open mode with no constraint.
  auto r = gov_.CanAddTriple(
      W(),
      group_detail::T_lit(Wdid(), living_web::kGroupSyncModule,
                          "urn:sync:module:evil"),
      Wdid());
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.reason, "immutable_seed_predicate");
}

// ---- constraint kinds (§9.3, §13.8) + governance gate (§5.2) ---------------

TEST_F(GovernanceBackendTest, UnknownConstraintKindFailsClosed) {
  const std::string cid = "urn:uuid:constraint-temporal";
  {
    group_detail::ScopedActive active(&identity_, gcred_);
    EXPECT_TRUE(W()->AddTriples({
        group_detail::T_iri(cid, living_web::kGovEntryType,
                            living_web::kGovConstraintEntryType),
        group_detail::T_lit(cid, living_web::kGovConstraintKind, "temporal"),
        group_detail::T_iri(Wdid(), living_web::kGovHasConstraint, cid),
    }));
  }
  auto r = gov_.CanAddTriple(
      W(), group_detail::T_lit("urn:n:1", "urn:p:body", "hi"), Wdid());
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "temporal");
  EXPECT_EQ(r.reason, "unknown_constraint_kind");
}

TEST_F(GovernanceBackendTest, PluginConstraintKindHandler) {
  gov_.RegisterConstraintKind(std::make_unique<BlockPredicateConstraint>());
  const std::string cid = "urn:uuid:constraint-block";
  {
    group_detail::ScopedActive active(&identity_, gcred_);
    EXPECT_TRUE(W()->AddTriples({
        group_detail::T_iri(cid, living_web::kGovEntryType,
                            living_web::kGovConstraintEntryType),
        group_detail::T_lit(cid, living_web::kGovConstraintKind,
                            "blockPredicate"),
        group_detail::T_lit(cid, "governance://blocked_predicate",
                            "urn:p:forbidden"),
        group_detail::T_iri(Wdid(), living_web::kGovHasConstraint, cid),
    }));
  }
  EXPECT_FALSE(gov_.CanAddTriple(
                      W(),
                      group_detail::T_lit("urn:n:1", "urn:p:forbidden", "x"),
                      Wdid())
                   .allowed);
  EXPECT_TRUE(gov_.CanAddTriple(
                     W(), group_detail::T_lit("urn:n:1", "urn:p:body", "x"),
                     Wdid())
                  .allowed);
}

TEST_F(GovernanceBackendTest, SetEnforcementModeRequiresGovernance) {
  BootstrapEnforced();
  // Once a capability constraint is installed, flipping the mode demands
  // updateGovernance (§5.2); a stranger cannot.
  std::unique_ptr<DIDKeyPair> stranger = identity_.CreateKey("Stranger");
  EXPECT_FALSE(
      gov_.SetEnforcementMode(W(), stranger->id, EnforcementMode::kOpen));
  EXPECT_EQ(gov_.last_error(), "not_authorised");
  EXPECT_EQ(gov_.GetEnforcementMode(W()), EnforcementMode::kEnforced);
}

TEST_F(GovernanceBackendTest, ConstraintsForListsCapabilityConstraint) {
  std::string root;
  EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
  std::string cid;
  EXPECT_TRUE(gov_.InstallCapabilityConstraint(W(), gcred_, std::nullopt, &cid));
  bool found = false;
  for (const auto& c : gov_.ConstraintsFor(W(), Wdid()))
    if (c.kind == "capability" && c.id == cid)
      found = true;
  EXPECT_TRUE(found);
}

TEST_F(GovernanceBackendTest, EnforcementModeDefaultsToOpen) {
  // §5.1: absent an explicit mode triple, the enforcement mode is open.
  EXPECT_EQ(gov_.GetEnforcementMode(W()), EnforcementMode::kOpen);
}

// ---- §11 current-identity resolution (browser integration) -----------------

TEST_F(GovernanceBackendTest, ActiveIdentityResolvesCurrentAuthor) {
  // §11.1/§11.3 resolve "the current identity" through the active credential, so
  // the renderer surface never names an author. Selecting the group key makes the
  // graph DID the current author; a stranger key makes its did:key the author.
  ASSERT_TRUE(identity_.SetActiveCredential(gcred_));
  EXPECT_EQ(gov_.ActiveCredentialId(), gcred_);
  EXPECT_EQ(gov_.ActiveAuthorDid(), Wdid());

  std::unique_ptr<DIDKeyPair> stranger = identity_.CreateKey("Stranger");
  ASSERT_TRUE(identity_.SetActiveCredential(stranger->id));
  EXPECT_EQ(gov_.ActiveCredentialId(), stranger->id);
  EXPECT_EQ(gov_.ActiveAuthorDid(), stranger->did);
}

// ---- §8.1.5 group delegateCapability support -------------------------------

TEST_F(GovernanceBackendTest, EnsureRootCapabilityLazilyMintsOnce) {
  // Spec 03 group creation does not mint a governance root; the group's first
  // delegation constitutes it here (§8.1.5). EnsureRootCapability mints when
  // absent and returns the existing id thereafter.
  std::string root = gov_.EnsureRootCapability(W(), gcred_);
  ASSERT_FALSE(root.empty());
  EXPECT_EQ(root.substr(0, 9), "urn:uuid:");
  EXPECT_EQ(gov_.EnsureRootCapability(W(), gcred_), root);  // idempotent
  // The lazily-minted root is invoked by the graph DID.
  auto caps = gov_.MyCapabilities(W(), Wdid());
  ASSERT_EQ(caps.size(), 1u);
  EXPECT_EQ(caps[0].id, root);
}

TEST_F(GovernanceBackendTest, ResolveDelegationRecordProjectsSignedContent) {
  std::string root = gov_.EnsureRootCapability(W(), gcred_);
  ASSERT_FALSE(root.empty());
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  std::string child;
  ASSERT_TRUE(gov_.Delegate(W(), gcred_, req, &child));

  // The §8.1.5 SignedContent projection carries the flattened ZCAP that was
  // signed plus its §4.5.3.1 proof, ready to frame as SignedContent in the
  // renderer.
  GovernanceBackend::DelegationRecord rec;
  ASSERT_TRUE(gov_.ResolveDelegationRecord(W(), child, &rec));
  EXPECT_FALSE(rec.author.empty());
  EXPECT_FALSE(rec.proof_value.empty());
  EXPECT_FALSE(rec.proof_method.empty());
  EXPECT_NE(rec.data_json.find(member->did), std::string::npos);

  // A non-existent capability id has no delegation record.
  GovernanceBackend::DelegationRecord missing;
  EXPECT_FALSE(gov_.ResolveDelegationRecord(W(), "urn:uuid:nope", &missing));
}

}  // namespace
}  // namespace content
