// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 03 browser-process group port
// (content::GroupBackendManager / content::GroupBackend) plus the shared
// did:graph codec + DID-document model (living_web::did_graph / DidDocument) —
// Decentralised Group Identity. These exercise the same normative behaviour as
// the standalone Group_* conformance harness, but against the browser port bound
// to content::DIDKeyProvider and content::GraphBackendManager, so the full-tree
// content_unittests build has direct coverage of the §4/§5/§6/§7/§8 algorithms
// and their DOMException error names. The did:graph codec + DID-document model is
// Chromium-independent and shared verbatim with the standalone harness, so the
// triples written, signed, and projected never diverge between the two.

#include "content/browser/did/group_backend_manager.h"

#include <memory>
#include <string>
#include <vector>

#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

using living_web::DIDCapabilitySection;
using living_web::DidDocument;

// ---- did:graph codec (§4.1) ------------------------------------------------

// The did:graph method-specific id uses the SAME multibase Ed25519 encoding as
// did:key — only the method prefix differs (§4.1) — and round-trips losslessly.
TEST(DidGraphCodecTest, RoundTrip) {
  std::vector<uint8_t> pk(32, 0x11);
  auto did = living_web::did_graph::DeriveDidGraphEd25519(pk);
  ASSERT_TRUE(did.has_value());
  EXPECT_EQ(did->substr(0, 12), "did:graph:z6");
  EXPECT_TRUE(living_web::did_graph::IsDidGraph(*did));
  EXPECT_FALSE(living_web::did_graph::IsDidGraph("did:key:z6MkFoo"));

  auto pk2 = living_web::did_graph::ParseDidGraphEd25519(*did);
  ASSERT_TRUE(pk2.has_value());
  EXPECT_EQ(*pk2, pk);
}

// ---- fixture ---------------------------------------------------------------

// One human did:key active in the provider, plus a graph + group manager sharing
// it. The GraphBackendManager owns the host graphs; the GroupBackendManager
// indexes them by did:graph so participation edges between locally-mounted groups
// resolve (§4.7).
class GroupBackendTest : public testing::Test {
 protected:
  GroupBackendTest() : graphs_(&identity_), groups_(&identity_, &graphs_) {
    identity_.CreateKey("Human");  // the first key is active by default
  }

  static GroupCreationOptions DefaultGroupOptions() {
    GroupCreationOptions o;
    o.sync_module = "urn:sync:module:default";
    return o;
  }

  DIDKeyProvider identity_;
  GraphBackendManager graphs_;
  GroupBackendManager groups_;
};

// ---- createGroup: binding + seed + resolution (§4.2, §4.7) -----------------

TEST_F(GroupBackendTest, CreateBindsDidGraphAndSeed) {
  GroupCreationOptions opts = DefaultGroupOptions();
  opts.display_name = "Book Club";
  opts.description = "We read books";
  std::unique_ptr<GroupBackend> group = groups_.CreateGroup(opts);
  ASSERT_NE(group, nullptr);
  EXPECT_EQ(group->did().substr(0, 10), "did:graph:");
  ASSERT_TRUE(group->name().has_value());
  EXPECT_EQ(*group->name(), "Book Club");
  ASSERT_TRUE(group->description().has_value());
  EXPECT_EQ(*group->description(), "We read books");
  EXPECT_TRUE(group->created().has_value());
  // The human's prior-active DID is recorded as creator (§4.2).
  ASSERT_TRUE(group->creator().has_value());
  EXPECT_EQ(group->creator()->substr(0, 8), "did:key:");

  DidDocument doc;
  ASSERT_TRUE(group->Resolve(&doc));
  EXPECT_EQ(doc.id, group->did());
  EXPECT_EQ(doc.trust_level, "local");
  EXPECT_FALSE(doc.deactivated);
  // Group-of-one: the creator key holds every section (§11).
  EXPECT_EQ(doc.verification_method.size(), 1u);
  EXPECT_EQ(doc.capability_invocation.size(), 1u);
  EXPECT_EQ(doc.capability_delegation.size(), 1u);
  EXPECT_EQ(doc.assertion_method.size(), 1u);
  EXPECT_EQ(doc.authentication.size(), 1u);

  auto sm = group_detail::FirstLiteralOf(group->graph(), group->did(),
                                         living_web::kGroupSyncModule);
  ASSERT_TRUE(sm.has_value());
  EXPECT_EQ(*sm, "urn:sync:module:default");
}

TEST_F(GroupBackendTest, CreateRequiresSyncModule) {
  GroupCreationOptions opts;  // no sync_module
  std::unique_ptr<GroupBackend> group = groups_.CreateGroup(opts);
  EXPECT_EQ(group, nullptr);
  EXPECT_EQ(groups_.last_error(), "SyntaxError");
}

// ---- groupify: one-way promotion of an existing graph (§4.2) ---------------

TEST_F(GroupBackendTest, GroupifyExistingGraphOneWay) {
  GraphBackend* g = graphs_.Create("Existing");
  ASSERT_TRUE(
      g->AddTriple(group_detail::T_lit("urn:note:1", "urn:p:body", "hi")));

  GroupifyOptions opts;
  opts.sync_module = "urn:sync:module:default";
  std::unique_ptr<GroupBackend> group = groups_.Groupify(g, opts);
  ASSERT_NE(group, nullptr);
  ASSERT_TRUE(g->did().has_value());
  EXPECT_EQ(*g->did(), group->did());

  // Pre-existing content survives groupification.
  auto body = group_detail::FirstLiteralOf(g, "urn:note:1", "urn:p:body");
  ASSERT_TRUE(body.has_value());
  EXPECT_EQ(*body, "hi");

  // Re-groupify is rejected — groupification is one-way (§4.2).
  std::unique_ptr<GroupBackend> again = groups_.Groupify(g, opts);
  EXPECT_EQ(again, nullptr);
  EXPECT_EQ(groups_.last_error(), "InvalidStateError");
}

// ---- delegate management (§5.4, §8.1.4) ------------------------------------

TEST_F(GroupBackendTest, AddAndRemoveDelegate) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());

  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  auto vm = group_detail::MethodFromDelegateDid(group->did(), member->did);
  ASSERT_TRUE(vm.has_value());

  EXPECT_TRUE(group->AddDelegate(
      *vm, {DIDCapabilitySection::kCapabilityInvocation,
            DIDCapabilitySection::kAssertionMethod}));
  EXPECT_TRUE(group->IsSigner(member->did));
  EXPECT_TRUE(
      group->IsSigner(member->did, DIDCapabilitySection::kAssertionMethod));
  EXPECT_FALSE(
      group->IsSigner(member->did, DIDCapabilitySection::kCapabilityDelegation));

  DidDocument doc;
  group->Resolve(&doc);
  EXPECT_EQ(doc.verification_method.size(), 2u);

  EXPECT_TRUE(group->RemoveDelegate(vm->id));
  EXPECT_FALSE(group->IsSigner(member->did));
  group->Resolve(&doc);
  EXPECT_EQ(doc.verification_method.size(), 1u);
}

TEST_F(GroupBackendTest, GrantAndRevokeSection) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  auto vm = group_detail::MethodFromDelegateDid(group->did(), member->did);
  ASSERT_TRUE(vm.has_value());
  EXPECT_TRUE(group->AddDelegate(
      *vm, {DIDCapabilitySection::kCapabilityInvocation}));

  EXPECT_FALSE(
      group->IsSigner(member->did, DIDCapabilitySection::kAuthentication));
  EXPECT_TRUE(
      group->GrantSection(vm->id, DIDCapabilitySection::kAuthentication));
  EXPECT_TRUE(
      group->IsSigner(member->did, DIDCapabilitySection::kAuthentication));
  EXPECT_TRUE(
      group->RevokeSection(vm->id, DIDCapabilitySection::kAuthentication));
  EXPECT_FALSE(
      group->IsSigner(member->did, DIDCapabilitySection::kAuthentication));
}

// ---- brick-state guards (§5.4) ---------------------------------------------

TEST_F(GroupBackendTest, RemoveSoleCapabilityDelegationBricks) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());
  DidDocument doc;
  group->Resolve(&doc);
  ASSERT_EQ(doc.capability_delegation.size(), 1u);
  const std::string sole = doc.capability_delegation[0];

  // Removing the only capabilityDelegation method would brick the group (§5.4).
  EXPECT_FALSE(group->RemoveSigner(sole));
  EXPECT_EQ(group->last_error(), "InvalidStateError");
  // Revoking its capabilityDelegation membership likewise bricks.
  EXPECT_FALSE(
      group->RevokeSection(sole, DIDCapabilitySection::kCapabilityDelegation));
  EXPECT_EQ(group->last_error(), "InvalidStateError");
}

// ---- authorship rules (§6.2, §5.4) -----------------------------------------

TEST_F(GroupBackendTest, WritesRequireDelegateAuthority) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());

  // Add a capabilityInvocation-only delegate, then act as it.
  std::unique_ptr<DIDKeyPair> member = identity_.CreateKey("Member");
  auto vm = group_detail::MethodFromDelegateDid(group->did(), member->did);
  ASSERT_TRUE(vm.has_value());
  EXPECT_TRUE(group->AddDelegate(
      *vm, {DIDCapabilitySection::kCapabilityInvocation}));
  group->SetActingCredential(member->id);

  // Accepting participation demands capabilityDelegation authorship (§6.2).
  EXPECT_FALSE(group->Invite("urn:person:bob"));
  EXPECT_EQ(group->last_error(), "NotAllowedError");
  // Managing delegates demands capabilityDelegation (§5.4).
  EXPECT_FALSE(
      group->AddDelegate(*vm, {DIDCapabilitySection::kAuthentication}));
  EXPECT_EQ(group->last_error(), "NotAllowedError");
  // signGraph demands assertionMethod (§5.4).
  SignedContentResult sr;
  EXPECT_FALSE(group->SignGraph(group->did(), &sr));
  EXPECT_EQ(group->last_error(), "NotAllowedError");
}

// ---- participation lifecycle (§7.1, §8.1.1-8.1.3) --------------------------

TEST_F(GroupBackendTest, ParticipationLifecycle) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());
  EXPECT_FALSE(group->HasParticipant("urn:person:alice"));
  EXPECT_TRUE(group->Invite("urn:person:alice"));
  EXPECT_TRUE(group->HasParticipant("urn:person:alice"));

  std::vector<Participant> parts = group->Participants();
  ASSERT_EQ(parts.size(), 1u);
  EXPECT_EQ(parts[0].did, "urn:person:alice");
  EXPECT_FALSE(parts[0].is_group);
  EXPECT_FALSE(parts[0].joined_at.empty());

  EXPECT_TRUE(group->RevokeParticipation("urn:person:alice"));
  EXPECT_FALSE(group->HasParticipant("urn:person:alice"));
}

// ---- signGraph, group-of-one (§5.4, §11) -----------------------------------

TEST_F(GroupBackendTest, SignGraphGroupOfOne) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());
  SignedContentResult sr;
  ASSERT_TRUE(group->SignGraph(group->did(), &sr));
  EXPECT_EQ(sr.author, group->did());
  EXPECT_FALSE(sr.proof_sig.empty());
  EXPECT_EQ(sr.proof_type, "Ed25519Signature2020");
  EXPECT_EQ(sr.proof_method.substr(0, group->did().size()), group->did());
}

// ---- nesting + transitive participation (§6.3, §8.1.3) ---------------------

TEST_F(GroupBackendTest, NestedTransitiveParticipants) {
  std::unique_ptr<GroupBackend> parent =
      groups_.CreateGroup(DefaultGroupOptions());
  std::unique_ptr<GroupBackend> child =
      groups_.CreateGroup(DefaultGroupOptions());

  EXPECT_TRUE(child->Invite("urn:person:alice"));
  EXPECT_TRUE(parent->Invite(child->did()));  // a sub-group participates
  EXPECT_TRUE(parent->Invite("urn:person:bob"));

  EXPECT_EQ(parent->Participants().size(), 2u);

  std::vector<Participant> trans = parent->TransitiveParticipants();
  ASSERT_EQ(trans.size(), 2u);  // alice (via child) + bob; child is not an individual
  bool has_alice = false, has_bob = false;
  for (const auto& p : trans) {
    EXPECT_FALSE(p.is_group);
    if (p.did == "urn:person:alice")
      has_alice = true;
    if (p.did == "urn:person:bob")
      has_bob = true;
  }
  EXPECT_TRUE(has_alice);
  EXPECT_TRUE(has_bob);

  std::vector<std::unique_ptr<GroupBackend>> kids = parent->ChildGroups();
  ASSERT_EQ(kids.size(), 1u);
  EXPECT_EQ(kids[0]->did(), child->did());
}

TEST_F(GroupBackendTest, TransitiveParticipantsCycleSafe) {
  std::unique_ptr<GroupBackend> a = groups_.CreateGroup(DefaultGroupOptions());
  std::unique_ptr<GroupBackend> b = groups_.CreateGroup(DefaultGroupOptions());
  EXPECT_TRUE(a->Invite(b->did()));
  EXPECT_TRUE(b->Invite(a->did()));  // mutual participation forms a cycle
  EXPECT_TRUE(a->Invite("urn:person:solo"));

  std::vector<Participant> trans = a->TransitiveParticipants();  // must terminate
  ASSERT_EQ(trans.size(), 1u);
  EXPECT_EQ(trans[0].did, "urn:person:solo");
}

// ---- forking (§4.8) --------------------------------------------------------

TEST_F(GroupBackendTest, ForkInheritsAndRelinks) {
  GroupCreationOptions opts = DefaultGroupOptions();
  opts.display_name = "Origin";
  std::unique_ptr<GroupBackend> parent = groups_.CreateGroup(opts);
  const std::string parent_did = parent->did();

  // Plain content the fork should inherit.
  ASSERT_TRUE(parent->graph()->AddTriple(
      group_detail::T_lit("urn:book:1", "urn:p:title", "Dune")));

  ForkOptions fo;
  fo.sync_module = "urn:sync:module:default";
  fo.display_name = "Fork";
  std::unique_ptr<GroupBackend> child = groups_.ForkGroup(parent_did, fo);
  ASSERT_NE(child, nullptr);
  const std::string child_did = child->did();
  EXPECT_NE(child_did, parent_did);

  // Inherited content survives in the child.
  auto title =
      group_detail::FirstLiteralOf(child->graph(), "urn:book:1", "urn:p:title");
  ASSERT_TRUE(title.has_value());
  EXPECT_EQ(*title, "Dune");

  // The child records its lineage (§4.8 step 4).
  auto ff = group_detail::FirstIriOf(child->graph(), child_did,
                                     living_web::kGroupForkedFrom);
  ASSERT_TRUE(ff.has_value());
  EXPECT_EQ(*ff, parent_did);
  auto fr = group_detail::FirstLiteralOf(child->graph(), child_did,
                                         living_web::kGroupForkedAtRevision);
  EXPECT_TRUE(fr.has_value());

  // The parent identity is stripped from the child (§4.8 step 3).
  DidDocument stale;
  group_detail::ProjectDidDocument(child->graph(), parent_did, &stale);
  EXPECT_EQ(stale.verification_method.size(), 0u);

  // The parent announces the fork (§4.8 step 6).
  auto to = group_detail::FirstIriOf(parent->graph(), parent_did,
                                     living_web::kGroupForkedTo);
  ASSERT_TRUE(to.has_value());
  EXPECT_EQ(*to, child_did);
}

// ---- deactivation + reopen (§4.9, §8.2) ------------------------------------

TEST_F(GroupBackendTest, DeactivateReflectsInResolution) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());
  EXPECT_TRUE(group->Deactivate());
  DidDocument doc;
  group->Resolve(&doc);
  EXPECT_TRUE(doc.deactivated);
}

TEST_F(GroupBackendTest, OpenByDidAndByIri) {
  std::unique_ptr<GroupBackend> group =
      groups_.CreateGroup(DefaultGroupOptions());
  const std::string did = group->did();

  std::unique_ptr<GroupBackend> by_did = groups_.OpenGroup(did);
  ASSERT_NE(by_did, nullptr);
  EXPECT_EQ(by_did->did(), did);

  std::string iri;
  ASSERT_TRUE(group->GetIri(&iri));
  std::unique_ptr<GroupBackend> by_iri = groups_.OpenGroup(iri);
  ASSERT_NE(by_iri, nullptr);
  EXPECT_EQ(by_iri->did(), did);

  EXPECT_EQ(groups_.OpenGroup("did:graph:zUnknown"), nullptr);
  EXPECT_EQ(groups_.last_error(), "NotFoundError");
}

}  // namespace
}  // namespace content
