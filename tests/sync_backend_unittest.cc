// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 05 browser-process synchronisation port
// (content::SyncBackend) plus the shared Chromium-independent GraphDiff-identity
// core (content/browser/graph_sync/graph_diff.{h,cc}) — the Graph Synchronisation
// Protocol. These exercise the same normative behaviour as the standalone Sync_*
// conformance harness, but against the browser port bound to
// content::DIDKeyProvider, content::GraphBackendManager, content::
// GroupBackendManager and content::GovernanceBackend, so the full-tree
// content_unittests build has direct coverage of the §5.2.2 diff construction,
// the §9.2.1 validateDiff steps 0–6 (including the reifier↔bundle author binding),
// the §9.2.2 mountContext read gate, the §7 sync-space derivation and public/
// restricted classification, the §12 invitation links, and the §13 reconnection
// primitives (durable diff queue, exponential backoff, batching policy). The
// byte-critical core (the §5.2.2.1 revision/commitId pre-images, the §5.2.1
// dependency ordering, and the §7.3 space-derivation input) is shared verbatim
// with the standalone harness, so the bytes a diff is content-addressed and
// signed over — and the sync-space a graph derives — never diverge between the
// two build worlds.

#include "content/browser/graph_sync/sync_backend.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/did/group_backend_manager.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph/oxigraph_store.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph_sync/graph_diff.h"
#include "crypto/sha2.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

using living_web::SpaceTopology;
using living_web::Triple;

// ---- triple constructors (mirror the standalone MakeLit/MakeIri) -----------

// An xsd:string literal-object triple.
Triple MakeLit(const std::string& s,
               const std::string& p,
               const std::string& lex) {
  Triple t;
  t.subject = s;
  t.predicate = p;
  living_web::LiteralValue lv;
  lv.lexical = lex;
  t.object = living_web::ObjectTerm::Literal(lv);
  return t;
}

// An IRI-object triple.
Triple MakeIri(const std::string& s,
               const std::string& p,
               const std::string& iri) {
  Triple t;
  t.subject = s;
  t.predicate = p;
  t.object = living_web::ObjectTerm::Iri(iri);
  return t;
}

// ---- forge helper (port of the standalone ForgeDiff) -----------------------
//
// Builds a fully-signed GraphDiff for |wdid| whose additions' reifiers are
// authored by |reifier_agent| while the bundle (commitId + signature) is authored
// by |bundle_agent|. With the two equal this reproduces the SyncBackend::
// CommitDiff construction byte-for-byte; with them distinct it is the
// author-smuggling diff that §9.2.1 step 4 (the reifier↔bundle author binding)
// must reject — every content address still recomputes correctly, so only the
// binding stands in the way. The content:: port maps the standalone calls thus:
//   crypto::SHA256HashString              -> crypto::SHA256HashString (crypto/sha2.h)
//   BuildSignaturePreimage                -> living_web::BuildSignaturePreimage
//   BuildTripleWithReifierNquads          -> living_web::BuildTripleWithReifierNquads
//   OxigraphStore::Canonicalize           -> living_web::OxigraphStore::Canonicalize
//   BuildRevisionPreimage/BuildCommitId.. -> living_web:: (graph_diff.h)
//   BuildSignatureMessage/SortDependencies-> living_web:: (graph_diff.h)
//   ToLowerHex                            -> living_web::ToLowerHex
//   did_key::MultibaseEncode              -> living_web::did_key::MultibaseEncode
//   p.SignRaw(agent->id, bytes)           -> DIDKeyProvider::SignRaw
GraphDiff ForgeDiff(DIDKeyProvider& p,
                    const std::string& wdid,
                    const DIDKeyPair* reifier_agent,
                    const DIDKeyPair* bundle_agent,
                    const std::vector<Triple>& additions,
                    const std::string& timestamp,
                    const std::vector<std::string>& deps = {}) {
  GraphDiff d;
  d.graph_did = wdid;
  d.author = bundle_agent->did;
  d.timestamp = timestamp;
  d.dependencies = living_web::SortDependencies(deps);
  for (const Triple& t : additions) {
    std::string payload = crypto::SHA256HashString(
        living_web::BuildSignaturePreimage(t, timestamp, wdid));
    auto sig = p.SignRaw(reifier_agent->id,
                         std::vector<uint8_t>(payload.begin(), payload.end()));
    DiffTriple dt;
    dt.triple = t;
    dt.author = reifier_agent->did;
    dt.timestamp = timestamp;
    dt.method = reifier_agent->method_id;
    dt.signature = living_web::did_key::MultibaseEncode(*sig);
    d.additions.push_back(std::move(dt));
  }
  std::string block;
  for (size_t i = 0; i < d.additions.size(); ++i) {
    const DiffTriple& dt = d.additions[i];
    block += living_web::BuildTripleWithReifierNquads(
        dt.triple, "_:r" + std::to_string(i), dt.author, dt.timestamp, dt.method,
        dt.signature);
  }
  std::string canon_add, err;
  living_web::OxigraphStore::Canonicalize(block, living_web::CanonHash::kSha256,
                                          &canon_add, &err);
  d.revision = living_web::ToLowerHex(crypto::SHA256HashString(
      living_web::BuildRevisionPreimage(wdid, canon_add, std::string(),
                                        d.dependencies)));
  d.commit_id = living_web::ToLowerHex(crypto::SHA256HashString(
      living_web::BuildCommitIdPreimage(d.revision, d.author, d.timestamp,
                                        std::string())));
  std::string msg = living_web::BuildSignatureMessage(d.commit_id);
  auto bsig = p.SignRaw(bundle_agent->id,
                        std::vector<uint8_t>(msg.begin(), msg.end()));
  d.signature = living_web::did_key::MultibaseEncode(*bsig);
  return d;
}

// ---- shared GraphDiff-identity core (graph_diff.{h,cc}, §5.2, §7) ----------
//
// These assert the byte-critical core that the browser port and the standalone
// harness link verbatim, so the amendment-pinned invariants (the exact revision/
// commitId pre-images, the dependency ordering, the space-derivation input) are
// guarded in the browser build too, not only the standalone one.

TEST(SyncGraphDiffCoreTest, RevisionPreimageExactBytes) {
  // §5.2.2.1: length-framed, domain-separated, dependency-sorted+deduped.
  std::vector<std::string> deps = {"revB", "revA", "revA"};
  const std::string expected =
      "living-web/sync/revision/v1\n"
      "did:graph:zW\n"
      "3\n"
      "ADD"
      "2\n"
      "RM"
      "2\n"
      "revA\n"
      "revB\n";
  EXPECT_EQ(living_web::BuildRevisionPreimage(
                "did:graph:zW", "ADD", "RM", living_web::SortDependencies(deps)),
            expected);
}

TEST(SyncGraphDiffCoreTest, CommitIdPreimageExactBytes) {
  const std::string expected =
      "living-web/sync/commit/v1\n"
      "abc123\n"
      "did:key:zAuthor\n"
      "2026-07-08T00:00:00Z\n"
      "urn:zcap:leaf";
  EXPECT_EQ(living_web::BuildCommitIdPreimage("abc123", "did:key:zAuthor",
                                              "2026-07-08T00:00:00Z",
                                              "urn:zcap:leaf"),
            expected);
}

TEST(SyncGraphDiffCoreTest, SignatureMessageIsCommitIdDirect) {
  // Amendment 05/§5.2.2.1: the commitId hex is signed directly, not re-hashed.
  EXPECT_EQ(living_web::BuildSignatureMessage("deadbeef"), "deadbeef");
}

TEST(SyncGraphDiffCoreTest, SortDependenciesOrdersAndDedups) {
  auto out = living_web::SortDependencies({"c", "a", "b", "a", "c"});
  EXPECT_EQ(out.size(), 3u);
  EXPECT_EQ(out[0], "a");
  EXPECT_EQ(out[1], "b");
  EXPECT_EQ(out[2], "c");
}

TEST(SyncGraphDiffCoreTest, SpaceDerivationInputPerTopology) {
  EXPECT_EQ(living_web::BuildSpaceDerivationInput(SpaceTopology::kUnified, false,
                                                  "ns", "did", ""),
            "lwsync:unified:ns");
  EXPECT_EQ(living_web::BuildSpaceDerivationInput(SpaceTopology::kPrivacyTiered,
                                                  false, "ns", "did", ""),
            "lwsync:public:ns");
  EXPECT_EQ(living_web::BuildSpaceDerivationInput(SpaceTopology::kPrivacyTiered,
                                                  true, "ns", "did", ""),
            "lwsync:dedicated:did");
  EXPECT_EQ(living_web::BuildSpaceDerivationInput(
                SpaceTopology::kFullyPartitioned, false, "ns", "did", ""),
            "lwsync:dedicated:did");
  EXPECT_EQ(living_web::BuildSpaceDerivationInput(SpaceTopology::kCustom, false,
                                                  "ns", "did", "myspace"),
            "lwsync:named:myspace");
}

TEST(SyncGraphDiffCoreTest, TopologyTokenRoundTrip) {
  EXPECT_EQ(std::string(living_web::SpaceTopologyToken(SpaceTopology::kUnified)),
            "unified");
  EXPECT_EQ(
      std::string(living_web::SpaceTopologyToken(SpaceTopology::kPrivacyTiered)),
      "privacy-tiered");
  EXPECT_EQ(std::string(living_web::SpaceTopologyToken(
                SpaceTopology::kFullyPartitioned)),
            "fully-partitioned");
  EXPECT_EQ(std::string(living_web::SpaceTopologyToken(SpaceTopology::kCustom)),
            "custom");
  EXPECT_TRUE(living_web::SpaceTopologyFromToken("privacy-tiered") ==
              SpaceTopology::kPrivacyTiered);
  EXPECT_TRUE(living_web::SpaceTopologyFromToken("fully-partitioned") ==
              SpaceTopology::kFullyPartitioned);
  EXPECT_TRUE(living_web::SpaceTopologyFromToken("custom") ==
              SpaceTopology::kCustom);
  EXPECT_TRUE(living_web::SpaceTopologyFromToken("nonsense") ==
              SpaceTopology::kUnified);
}

// ---- fixture ---------------------------------------------------------------

// A sync fixture mirroring the standalone SyncFixture (a GovFixture with two
// SyncEngines): a group W (a graph bearing a did:graph whose DID document holds
// the group key in every capability section) over an open-governance
// GovernanceBackend, plus a sender and a receiver SyncBackend sharing the same
// DIDKeyProvider and GovernanceBackend but keeping independent diff chains — so a
// receiver genuinely re-validates what a sender emits rather than short-circuiting
// on its own commit record.
class SyncBackendTest : public testing::Test {
 protected:
  SyncBackendTest()
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
  // all authored by the group key (the graph's constitutional signer). Returns
  // the root capability id. Mirrors the standalone BootstrapEnforced.
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
  SyncBackend sync_{&identity_, &gov_};      // the committing (sender) peer
  SyncBackend receiver_{&identity_, &gov_};  // an independent receiving peer
};

// ---- sync-space derivation (§7) --------------------------------------------

TEST_F(SyncBackendTest, DeriveSpaceProducesStableSpaceUri) {
  auto s1 = sync_.DeriveSpace(W(), SpaceTopology::kUnified);
  EXPECT_TRUE(s1.has_value());
  EXPECT_TRUE(s1->rfind("space://", 0) == 0);
  EXPECT_EQ(s1->size(), std::string("space://").size() + 64);  // sha256 hex
  auto s2 = sync_.DeriveSpace(W(), SpaceTopology::kUnified);
  EXPECT_EQ(*s1, *s2);  // deterministic
  // Unified keys off the participates-in namespace, fully-partitioned off the
  // graph DID — distinct derivation inputs → distinct spaces (§7.3).
  auto s3 = sync_.DeriveSpace(W(), SpaceTopology::kFullyPartitioned);
  EXPECT_TRUE(s3.has_value());
  EXPECT_NE(*s1, *s3);
}

TEST_F(SyncBackendTest, IsRestrictedTracksCapabilityConstraint) {
  EXPECT_FALSE(sync_.IsRestricted(W()));  // no capability constraint → public
  std::string root, cid;
  EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, std::nullopt, &root));
  EXPECT_TRUE(gov_.InstallCapabilityConstraint(W(), gcred_, std::nullopt, &cid));
  EXPECT_TRUE(sync_.IsRestricted(W()));  // capability constraint → restricted
}

// ---- validateReadAccess (§9.2.2) -------------------------------------------

TEST_F(SyncBackendTest, ReadAccessOpenGraphAccepts) {
  std::unique_ptr<DIDKeyPair> reader = identity_.CreateKey("Reader");
  EXPECT_TRUE(
      receiver_.ValidateReadAccess(W(), reader->did, std::nullopt).accepted);
}

TEST_F(SyncBackendTest, ReadAccessRestrictedGraphRejectsStranger) {
  BootstrapEnforced();
  std::unique_ptr<DIDKeyPair> stranger = identity_.CreateKey("Stranger");
  EXPECT_FALSE(
      sync_.ValidateReadAccess(W(), stranger->did, std::nullopt).accepted);
}

// ---- commit → validate round trip (§5.2.2, §9.2.1) -------------------------

TEST_F(SyncBackendTest, CommitDiffRoundTripAccepts) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  std::vector<Triple> adds = {
      MakeLit("urn:note:1", "https://schema.org/name", "Hello"),
      MakeIri("urn:note:1", "https://schema.org/about", "urn:topic:sync")};
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, adds, {}, opts, &diff));
  EXPECT_FALSE(diff.revision.empty());
  EXPECT_FALSE(diff.commit_id.empty());
  EXPECT_FALSE(diff.signature.empty());
  EXPECT_EQ(diff.author, alice->did);
  EXPECT_EQ(diff.additions.size(), 2u);

  // A fresh receiving peer validates it against its own (empty) chain.
  EXPECT_TRUE(receiver_.ValidateDiff(W(), diff).accepted);
  EXPECT_TRUE(receiver_.HasChain(Wdid()));
  // §14.4: replaying an already-applied revision is an idempotent accept.
  EXPECT_TRUE(receiver_.ValidateDiff(W(), diff).accepted);
}

TEST_F(SyncBackendTest, RemovalsRoundTripAccepts) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id,
                               {MakeLit("urn:a", "urn:p", "keep")},
                               {MakeLit("urn:b", "urn:p", "drop")}, opts, &diff));
  EXPECT_EQ(diff.additions.size(), 1u);
  EXPECT_EQ(diff.removals.size(), 1u);
  EXPECT_TRUE(receiver_.ValidateDiff(W(), diff).accepted);
}

TEST_F(SyncBackendTest, BundleSignatureTamperRejected) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  std::unique_ptr<DIDKeyPair> bob = identity_.CreateKey("Bob");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:s", "urn:p", "v")},
                               {}, opts, &diff));
  // Replace the bundle signature with Bob's signature over the same commitId: it
  // decodes to 64 bytes, but fails to verify against the author (Alice) key.
  std::string msg = living_web::BuildSignatureMessage(diff.commit_id);
  auto bobsig =
      identity_.SignRaw(bob->id, std::vector<uint8_t>(msg.begin(), msg.end()));
  GraphDiff tampered = diff;
  tampered.signature = living_web::did_key::MultibaseEncode(*bobsig);
  SyncValidationResult r = receiver_.ValidateDiff(W(), tampered);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "signature_invalid");
}

TEST_F(SyncBackendTest, RevisionTamperRejected) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id,
                               {MakeLit("urn:s", "urn:p", "original")}, {}, opts,
                               &diff));
  // Mutate the payload triple without recomputing the revision: the receiver's
  // recomputed content address no longer matches the claimed one (step 0).
  GraphDiff tampered = diff;
  tampered.additions[0].triple = MakeLit("urn:s", "urn:p", "tampered");
  SyncValidationResult r = receiver_.ValidateDiff(W(), tampered);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "revision_invalid");
}

TEST_F(SyncBackendTest, ForgeDiffFidelity) {
  // The forge helper reproduces the real CommitDiff construction: a diff whose
  // reifiers and bundle are the same agent validates cleanly.
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  GraphDiff honest =
      ForgeDiff(identity_, Wdid(), alice.get(), alice.get(),
                {MakeLit("urn:claim", "urn:p", "x")}, "2026-07-01T00:00:00Z");
  EXPECT_TRUE(receiver_.ValidateDiff(W(), honest).accepted);
}

TEST_F(SyncBackendTest, ReifierAuthorSmuggleRejected) {
  // Regression: Alice authored the reifiers, but Mallory wraps + signs the
  // bundle. revision (over Alice's reifiers), commitId (over Mallory), and the
  // bundle signature (Mallory's) all recompute correctly — so ONLY the §9.2.1
  // step-4 author binding prevents Mallory from committing triples misattributed
  // to Alice. Removing that binding makes this diff wrongly accepted.
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  std::unique_ptr<DIDKeyPair> mallory = identity_.CreateKey("Mallory");
  GraphDiff smuggled =
      ForgeDiff(identity_, Wdid(), alice.get(), mallory.get(),
                {MakeLit("urn:claim", "urn:p", "x")}, "2026-07-01T00:00:00Z");
  SyncValidationResult r = receiver_.ValidateDiff(W(), smuggled);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "reifier_signature_invalid");
}

// ---- dependency validation (§5.2.1) ----------------------------------------

TEST_F(SyncBackendTest, ChainRootAndSnapshotPromotion) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  CommitOptions o0;
  o0.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff first;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:a", "urn:p", "1")},
                               {}, o0, &first));
  EXPECT_TRUE(receiver_.ValidateDiff(W(), first).accepted);

  // A second chain-root (no dependencies) on a non-empty chain is rejected...
  CommitOptions o1;
  o1.timestamp = "2026-07-01T00:01:00Z";
  GraphDiff orphan;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:b", "urn:p", "2")},
                               {}, o1, &orphan));
  SyncValidationResult r = receiver_.ValidateDiff(W(), orphan);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "chain_root_conflict");

  // ...unless it advertises a snapshot promotion (§5.2.1).
  CommitOptions o2;
  o2.timestamp = "2026-07-01T00:02:00Z";
  o2.snapshot_promotion = true;
  GraphDiff promo;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:c", "urn:p", "3")},
                               {}, o2, &promo));
  EXPECT_TRUE(receiver_.ValidateDiff(W(), promo).accepted);
}

TEST_F(SyncBackendTest, MissingDependencyRejected) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  opts.dependencies = {"a-revision-the-receiver-never-saw"};
  GraphDiff diff;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:a", "urn:p", "1")},
                               {}, opts, &diff));
  SyncValidationResult r = receiver_.ValidateDiff(W(), diff);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "missing_dependency");
}

// ---- timestamp plausibility (§14.5) ----------------------------------------

TEST_F(SyncBackendTest, TimestampFutureRejected) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2099-01-01T00:00:00Z";  // well beyond now + 300 s
  GraphDiff diff;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:a", "urn:p", "1")},
                               {}, opts, &diff));
  SyncValidationResult r = receiver_.ValidateDiff(W(), diff);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "timestamp_future");
  EXPECT_EQ(r.constraint_kind, "temporal");
}

TEST_F(SyncBackendTest, TimestampCausalRejected) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  CommitOptions p;
  p.timestamp = "2026-07-01T02:00:00Z";
  GraphDiff parent;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:a", "urn:p", "1")},
                               {}, p, &parent));
  EXPECT_TRUE(receiver_.ValidateDiff(W(), parent).accepted);

  // A child that depends on the parent but is dated before it violates causal
  // monotonicity.
  CommitOptions c;
  c.timestamp = "2026-07-01T01:00:00Z";
  c.dependencies = {parent.revision};
  GraphDiff child;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:b", "urn:p", "2")},
                               {}, c, &child));
  SyncValidationResult r = receiver_.ValidateDiff(W(), child);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "timestamp_causal");
}

TEST_F(SyncBackendTest, TimestampMonotonicRejected) {
  std::unique_ptr<DIDKeyPair> alice = identity_.CreateKey("Alice");
  CommitOptions o0;
  o0.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff d0;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:a", "urn:p", "1")},
                               {}, o0, &d0));
  EXPECT_TRUE(receiver_.ValidateDiff(W(), d0).accepted);

  CommitOptions o2;
  o2.timestamp = "2026-07-01T02:00:00Z";
  o2.dependencies = {d0.revision};
  GraphDiff d2;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:b", "urn:p", "2")},
                               {}, o2, &d2));
  EXPECT_TRUE(receiver_.ValidateDiff(W(), d2).accepted);

  // A later commit dated before the author's max applied timestamp, depending
  // only on the root (so no dependency is newer than it — causal is satisfied),
  // still violates per-author monotonicity (§14.5).
  CommitOptions o1;
  o1.timestamp = "2026-07-01T01:00:00Z";
  o1.dependencies = {d0.revision};
  GraphDiff d1;
  EXPECT_TRUE(sync_.CommitDiff(W(), alice->id, {MakeLit("urn:c", "urn:p", "3")},
                               {}, o1, &d1));
  SyncValidationResult r = receiver_.ValidateDiff(W(), d1);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "timestamp_monotonic");
}

TEST_F(SyncBackendTest, Rfc3339EpochParsing) {
  int64_t e = 0;
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("1970-01-01T00:00:00Z", &e));
  EXPECT_EQ(e, int64_t(0));
  int64_t earlier = 0, later = 0;
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-01T00:00:00Z", &earlier));
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-01T00:00:01Z", &later));
  EXPECT_EQ(later - earlier, int64_t(1));
  // Offset designators normalise to UTC: 12:00+02:00 == 10:00Z == 08:00-02:00.
  int64_t z = 0, plus = 0, minus = 0;
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-08T10:00:00Z", &z));
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-08T12:00:00+02:00", &plus));
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-08T08:00:00-02:00", &minus));
  EXPECT_EQ(z, plus);
  EXPECT_EQ(z, minus);
  EXPECT_FALSE(sync_detail::Rfc3339ToEpoch("not-a-timestamp", &e));
}

// ---- invitation links (§12) ------------------------------------------------

TEST_F(SyncBackendTest, InvitationFormatParseRoundTrip) {
  const std::string relay = "relay.example.com:8443";
  const std::string space = "space://abc123";  // arbitrary bytes → base64url
  const std::string did = "did:graph:z6MkExample";
  const std::string module = "sha256:deadbeef";
  const std::string name = "Alice & Bob's Space";  // spaces + reserved chars
  std::string uri =
      SyncBackend::FormatInvitation(relay, space, did, module, name);
  EXPECT_TRUE(uri.rfind("web+graph://", 0) == 0);

  SyncBackend::Invitation inv;
  EXPECT_TRUE(SyncBackend::ParseInvitation(uri, &inv));
  EXPECT_EQ(inv.relay_host, relay);
  EXPECT_EQ(inv.space_uri, space);
  EXPECT_EQ(inv.graph_did, did);
  EXPECT_EQ(inv.module_hash, module);
  EXPECT_EQ(inv.name, name);
}

TEST_F(SyncBackendTest, InvitationOptionalFieldsAbsent) {
  std::string uri =
      SyncBackend::FormatInvitation("relay", "space://x", "did:graph:zX");
  SyncBackend::Invitation inv;
  EXPECT_TRUE(SyncBackend::ParseInvitation(uri, &inv));
  EXPECT_EQ(inv.graph_did, "did:graph:zX");
  EXPECT_TRUE(inv.module_hash.empty());
  EXPECT_TRUE(inv.name.empty());
}

TEST_F(SyncBackendTest, InvitationRequiresDid) {
  // A well-formed URI missing the required did= parameter is rejected (§12.2).
  std::string uri = "web+graph://relay.example.com/" +
                    sync_detail::Base64UrlEncode("space://x") + "?name=NoDid";
  SyncBackend::Invitation inv;
  EXPECT_FALSE(SyncBackend::ParseInvitation(uri, &inv));
}

TEST_F(SyncBackendTest, InvitationRejectsWrongScheme) {
  SyncBackend::Invitation inv;
  EXPECT_FALSE(SyncBackend::ParseInvitation("https://relay/x?did=y", &inv));
}

// ---- reconnection primitives (§13) -----------------------------------------

TEST_F(SyncBackendTest, DiffQueueDedupesByCommitId) {
  DiffQueue q;
  GraphDiff a;
  a.commit_id = "c1";
  GraphDiff b;
  b.commit_id = "c2";
  EXPECT_TRUE(q.Enqueue(a));
  EXPECT_FALSE(q.Enqueue(a));  // same commitId → not re-enqueued
  EXPECT_TRUE(q.Enqueue(b));
  EXPECT_EQ(q.Size(), 2u);
  EXPECT_TRUE(q.Contains("c1"));
  EXPECT_TRUE(q.Acknowledge("c1"));
  EXPECT_FALSE(q.Contains("c1"));
  EXPECT_EQ(q.Size(), 1u);
  EXPECT_FALSE(q.Acknowledge("c1"));  // already acknowledged
}

TEST_F(SyncBackendTest, DiffQueueBatchCapsAndOrders) {
  DiffQueue q;
  for (int i = 0; i < 150; ++i) {
    GraphDiff d;
    d.commit_id = "c" + std::to_string(i);
    EXPECT_TRUE(q.Enqueue(d));
  }
  EXPECT_EQ(q.Size(), 150u);
  EXPECT_EQ(q.NextBatch().size(), kBatchMaxDiffs);  // default cap = 100 (§13.4)
  EXPECT_EQ(q.NextBatch(10).size(), 10u);
  auto batch = q.NextBatch(3);  // commit order preserved
  EXPECT_EQ(batch[0].commit_id, "c0");
  EXPECT_EQ(batch[1].commit_id, "c1");
  EXPECT_EQ(batch[2].commit_id, "c2");
}

TEST_F(SyncBackendTest, ReconnectBackoffDoublesAndCaps) {
  EXPECT_EQ(ReconnectBackoffMs(0), uint64_t(5000));
  EXPECT_EQ(ReconnectBackoffMs(1), uint64_t(10000));
  EXPECT_EQ(ReconnectBackoffMs(2), uint64_t(20000));
  EXPECT_EQ(ReconnectBackoffMs(3), uint64_t(40000));
  EXPECT_EQ(ReconnectBackoffMs(4), uint64_t(80000));
  EXPECT_EQ(ReconnectBackoffMs(5), uint64_t(160000));
  EXPECT_EQ(ReconnectBackoffMs(6), uint64_t(300000));    // 320000 capped
  EXPECT_EQ(ReconnectBackoffMs(100), uint64_t(300000));  // stays capped
}

}  // namespace
}  // namespace content
