// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 08 Governance Constraint Vocabulary browser binding
// (content/browser/governance/constraint_vocabulary_backend.{h,cc}) plus the
// shared Chromium-independent decision core
// (content/browser/governance/constraint_vocabulary.{h,cc}). These exercise the
// same normative behaviour as the standalone Gov_* conformance harness, but
// against the browser handlers registered on content::GovernanceBackend and bound
// to content::DIDKeyProvider / content::GraphBackendManager /
// content::GroupBackendManager, so the full-tree content_unittests build has
// direct coverage of the §4–§6 constraint kinds and the §7 caveat types.
//
// The pure-decision core (glob / deny-wins / RFC-3339 / §5.3 plausibility / §6.2
// content order / the §4 VC proof pre-image) is shared verbatim with the
// standalone harness, so those bytes and verdicts never diverge between the two
// build worlds; the one deliberate divergence is the regex primitive — the
// browser backs §9.3 with RE2 (linear-time, no timeout) where the standalone uses
// a std::regex worker bounded to 10 ms, so the timeout test becomes the RE2
// no-false-match test below.

#include "content/browser/governance/constraint_vocabulary_backend.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/did/group_backend_manager.h"
#include "content/browser/governance/constraint_vocabulary.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

namespace cv = living_web::constraint_vocab;
using living_web::kActionCreateLink;
using living_web::Triple;

// ---- fixture + helpers (mirror the standalone GovFixture / InstallKindConstraint
//      / WriteAs / BootstrapEnforced / DelegateWithCaveats, bound to the browser
//      types) ---------------------------------------------------------------

// The credential whose DID equals |did| — for a group, its own adopted key.
std::string CredIdForDid(DIDKeyProvider& provider, const std::string& did) {
  for (const DIDKeyPair* c : provider.ListCredentials())
    if (c->did == did)
      return c->id;
  return std::string();
}

// A governance fixture: a group W (a graph bearing a did:graph whose DID document
// holds the group key in every capability section) plus a GovernanceBackend over
// the same DIDKeyProvider. Each governed write is decided against W's constraints;
// gcred is the group's constitutional key (its did == W's did:graph). Constructed
// as a local per test — several tests need a fresh graph, and one needs two.
struct GovFixture {
  DIDKeyProvider provider;
  GraphBackendManager graphs{&provider};
  GroupBackendManager groups{&provider, &graphs};
  GovernanceBackend gov{&provider};
  std::unique_ptr<GroupBackend> group;
  std::string gcred;  // the group's own credential id (did == group->did())

  GovFixture() {
    provider.CreateKey("Human");
    GroupCreationOptions o;
    o.sync_module = "urn:sync:module:default";
    o.display_name = "Governed";
    group = groups.CreateGroup(o);
    gcred = CredIdForDid(provider, group->did());
  }
  GraphBackend* W() { return group->graph(); }
  const std::string& Wdid() { return group->did(); }
};

// A literal-object / IRI-object triple (the group_detail primitives the browser
// graph layer builds reifiable triples from), named to read like the standalone.
Triple MakeLit(const std::string& s, const std::string& p,
               const std::string& lex) {
  return group_detail::T_lit(s, p, lex);
}
Triple MakeIri(const std::string& s, const std::string& p,
               const std::string& iri) {
  return group_detail::T_iri(s, p, iri);
}

// Installs a graph constraint of |kind| carrying the given (predicate,
// literal-object) defining triples, authored by |cred|, and binds it to the graph
// DID via governance://has_constraint (Spec 04 §4.2 — a constraint binds to the
// graph it governs and applies to every write in that graph; the handler decides
// pass/fail from the current author's own state, Spec 08 §3).
void InstallKindConstraint(
    GovFixture& f, const std::string& cred, const std::string& kind,
    const std::string& cid,
    const std::vector<std::pair<std::string, std::string>>& props) {
  group_detail::ScopedActive active(&f.provider, cred);
  std::vector<Triple> t = {
      group_detail::T_iri(cid, living_web::kGovEntryType,
                          living_web::kGovConstraintEntryType),
      group_detail::T_lit(cid, living_web::kGovConstraintKind, kind),
  };
  for (const auto& kv : props)
    t.push_back(group_detail::T_lit(cid, kv.first, kv.second));
  t.push_back(group_detail::T_iri(f.Wdid(), living_web::kGovHasConstraint, cid));
  EXPECT_TRUE(f.W()->AddTriples(t));
}

// Writes |triple| into W authored by |cred| (recording the author/timestamp
// reifier the temporal / authorOnly provenance queries read back). AddTriple
// bypasses governance, so this seeds history in any enforcement mode.
void WriteAs(GovFixture& f, const std::string& cred, const Triple& triple) {
  group_detail::ScopedActive active(&f.provider, cred);
  EXPECT_TRUE(f.W()->AddTriple(triple));
}

// Mint the root, install the capability constraint, and enter enforced mode, all
// authored by the group key. Returns the root capability id.
std::string BootstrapEnforced(GovFixture& f) {
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  std::string cid;
  EXPECT_TRUE(
      f.gov.InstallCapabilityConstraint(f.W(), f.gcred, std::nullopt, &cid));
  EXPECT_TRUE(
      f.gov.SetEnforcementMode(f.W(), f.gcred, EnforcementMode::kEnforced));
  return root;
}

// Delegates a createLink capability to |invoker_did| under |caveats| JSON,
// returning the child capability id (assumes BootstrapEnforced already ran).
std::string DelegateWithCaveats(GovFixture& f, const std::string& root,
                                const std::string& invoker_did,
                                const std::string& caveats) {
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = invoker_did;
  req.actions = {kActionCreateLink};
  req.caveats = caveats;
  std::string child;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, req, &child));
  return child;
}

// ---- pure decision core (constraint_vocabulary.{h,cc}) ---------------------
//
// Shared byte-for-byte with the standalone harness; asserted here so the
// amendment-pinned invariants (glob, deny-wins, RFC-3339, §5.3 order, the VC
// proof pre-image) are guarded in the browser build too.

TEST(ConstraintVocabularyCoreTest, CoreGlobMatch) {
  EXPECT_TRUE(cv::GlobMatch("a*c", "abbbc"));
  EXPECT_TRUE(cv::GlobMatch("*", "anything"));
  EXPECT_TRUE(cv::GlobMatch("exact", "exact"));
  EXPECT_FALSE(cv::GlobMatch("exact", "exactly"));
  EXPECT_TRUE(cv::GlobMatch("did:key:*", "did:key:z6Mk1"));
  EXPECT_FALSE(cv::GlobMatch("did:key:*", "did:web:example"));
  EXPECT_TRUE(cv::GlobMatch("*.example.com", "a.b.example.com"));
  EXPECT_FALSE(cv::GlobMatch("*.example.com", "example.org"));
}

TEST(ConstraintVocabularyCoreTest, CoreEvalAllowDeny) {
  using AD = cv::AllowDeny;
  // Deny-only: anything not denied is accepted (§7.2).
  EXPECT_TRUE(cv::EvalAllowDeny({}, {"x"}, "y") == AD::kAccept);
  EXPECT_TRUE(cv::EvalAllowDeny({}, {"x"}, "x") == AD::kDenied);
  // Allow-list restricts to its members.
  EXPECT_TRUE(cv::EvalAllowDeny({"a"}, {}, "a") == AD::kAccept);
  EXPECT_TRUE(cv::EvalAllowDeny({"a"}, {}, "b") == AD::kNotAllowed);
  // Deny wins over allow (§7.2 deny-wins).
  EXPECT_TRUE(cv::EvalAllowDeny({"a"}, {"a"}, "a") == AD::kDenied);
}

TEST(ConstraintVocabularyCoreTest, CoreRfc3339ToEpoch) {
  int64_t e = -1;
  EXPECT_TRUE(cv::ParseRfc3339ToEpoch("1970-01-01T00:00:00Z", &e));
  EXPECT_EQ(e, int64_t(0));
  EXPECT_TRUE(cv::ParseRfc3339ToEpoch("2000-01-01T00:00:00Z", &e));
  EXPECT_EQ(e, int64_t(946684800));
  // A numeric offset is honoured.
  EXPECT_TRUE(cv::ParseRfc3339ToEpoch("2000-01-01T00:00:00+00:00", &e));
  EXPECT_EQ(e, int64_t(946684800));
  EXPECT_FALSE(cv::ParseRfc3339ToEpoch("not-a-date", &e));
  EXPECT_FALSE(cv::ParseRfc3339ToEpoch("2000-01-01", &e));
}

TEST(ConstraintVocabularyCoreTest, CorePlausibility) {
  // Within the +300 s future bound → plausible (§5.3 check 1).
  cv::PlausibilityInput ok;
  ok.t = "2026-01-01T00:00:10Z";
  ok.now = "2026-01-01T00:00:00Z";
  EXPECT_TRUE(cv::CheckTimestampPlausibility(ok).ok);
  // Beyond the bound → future-bound reject.
  cv::PlausibilityInput future;
  future.t = "2026-01-01T01:00:00Z";
  future.now = "2026-01-01T00:00:00Z";
  auto fb = cv::CheckTimestampPlausibility(future);
  EXPECT_FALSE(fb.ok);
  EXPECT_EQ(fb.reason, "future-bound");
  // A timestamp earlier than a resolved parent → causal-monotonicity reject.
  cv::PlausibilityInput causal;
  causal.t = "2026-01-01T00:00:00Z";
  causal.now = "2026-01-01T00:00:00Z";
  causal.parent_timestamps = {"2026-01-01T00:01:00Z"};
  auto cm = cv::CheckTimestampPlausibility(causal);
  EXPECT_FALSE(cm.ok);
  EXPECT_EQ(cm.reason, "causal-monotonicity");
}

TEST(ConstraintVocabularyCoreTest, CoreContentPolicyOrder) {
  cv::RegexMatcher matcher = MakeRe2Matcher();
  cv::ContentPolicy p;
  p.max_length = 5;
  EXPECT_FALSE(cv::EvaluateContentText(p, "toolong", matcher).allowed);
  EXPECT_TRUE(cv::EvaluateContentText(p, "ok", matcher).allowed);
  // Blocked pattern (§6.2 step 4) fires after length.
  cv::ContentPolicy b;
  b.blocked_patterns = {"bad[0-9]+"};
  auto r = cv::EvaluateContentText(b, "contains bad42 here", matcher);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.reason, "blocked-pattern");
  EXPECT_TRUE(cv::EvaluateContentText(b, "all clean", matcher).allowed);
  // URL policy + domain whitelist (§6.2 steps 5-6).
  cv::ContentPolicy u;
  u.allow_urls = false;
  EXPECT_FALSE(
      cv::EvaluateContentText(u, "go http://x.example/y", matcher).allowed);
  cv::ContentPolicy d;
  d.allow_urls = true;
  d.allowed_domains = {"example.com"};
  EXPECT_TRUE(
      cv::EvaluateContentText(d, "see https://example.com/a", matcher).allowed);
  EXPECT_FALSE(
      cv::EvaluateContentText(d, "see https://evil.example/a", matcher).allowed);
}

TEST(ConstraintVocabularyCoreTest, CoreVcPreimageDeterministic) {
  cv::LivingWebVc vc;
  vc.types = {"VerifiableCredential", "EmailVerified"};
  vc.issuer = "did:key:zIssuer";
  vc.issuance_date = "2020-01-01T00:00:00Z";
  vc.subject_id = "did:key:zSubject";
  vc.status_id = "urn:status:1";
  vc.proof_purpose = "assertionMethod";
  vc.proof_created = "2020-01-01T00:00:00Z";
  vc.proof_method = "did:key:zIssuer";
  const std::string expected =
      "living-web/vc/credential/v1\n"
      "VerifiableCredential,EmailVerified\n"
      "did:key:zIssuer\n"
      "2020-01-01T00:00:00Z\n"
      "did:key:zSubject\n"
      "urn:status:1\n"
      "assertionMethod\n"
      "2020-01-01T00:00:00Z\n"
      "did:key:zIssuer";
  EXPECT_EQ(cv::BuildVcProofPreimage(vc), expected);
}

TEST(ConstraintVocabularyCoreTest, UsageLedgerWindowAndLifetime) {
  UsageLedger led;
  // §7.5 sliding window: max 2 uses in a 100 s window.
  EXPECT_TRUE(led.CheckAndRecordRate("z", "a", 2, 100, 1000));
  EXPECT_TRUE(led.CheckAndRecordRate("z", "a", 2, 100, 1050));
  EXPECT_FALSE(led.CheckAndRecordRate("z", "a", 2, 100, 1090));  // 2 already
  EXPECT_TRUE(led.CheckAndRecordRate("z", "a", 2, 100, 1200));   // window slid
  // A different author has an independent counter.
  EXPECT_TRUE(led.CheckAndRecordRate("z", "b", 2, 100, 1090));
  // A non-positive bound admits nothing.
  EXPECT_FALSE(led.CheckAndRecordRate("z", "a", 0, 100, 2000));
  // §7.6 lifetime cap.
  EXPECT_TRUE(led.CheckAndRecordCardinality("c", "a", 2));
  EXPECT_TRUE(led.CheckAndRecordCardinality("c", "a", 2));
  EXPECT_FALSE(led.CheckAndRecordCardinality("c", "a", 2));
  EXPECT_TRUE(led.CheckAndRecordCardinality("c", "b", 2));  // distinct author
}

TEST(ConstraintVocabularyCoreTest, Re2MatcherMatchNoMatch) {
  cv::RegexMatcher m = MakeRe2Matcher();
  EXPECT_TRUE(m("ab+c", "xxabbbcyy") == cv::RegexOutcome::kMatch);
  EXPECT_TRUE(m("^zzz$", "abc") == cv::RegexOutcome::kNoMatch);
  // RE2 is linear-time, so the pathological pattern that forces catastrophic
  // std::regex backtracking (which the standalone must bound with a 10 ms
  // timeout) resolves here with no timeout and — critically — no false match: the
  // browser matcher never returns kTimeout (§9.3).
  const std::string evil = std::string(50, 'a') + "b";
  EXPECT_TRUE(m("(a+)+$", evil) == cv::RegexOutcome::kNoMatch);
  // A malformed pattern cannot compile; it matches nothing (blocks nothing), the
  // same fail-open-on-malformed behaviour as the standalone.
  EXPECT_TRUE(m("(unclosed", "anything") == cv::RegexOutcome::kNoMatch);
}

// ---- §4 credential constraint ----------------------------------------------

TEST(ConstraintVocabularyTest, CredentialConstraintHolderVsStranger) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto issuer = f.provider.CreateKey("Issuer");
  auto holder = f.provider.CreateKey("Holder");
  auto stranger = f.provider.CreateKey("Stranger");

  const std::string vc = MakeSignedLivingWebVc(
      &f.provider, issuer->id, issuer->did, {"EmailVerified"}, holder->did,
      "2020-01-01T00:00:00Z");
  std::string addr;
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(StoreCredential(f.W(), holder->did, vc, &addr));
  }
  // One graph-wide credential requirement governs every writer (Spec 04 §4.2);
  // the handler decides per-author from each writer's own held credentials.
  InstallKindConstraint(
      f, f.gcred, cv::kKindCredential, "urn:uuid:cred-c1",
      {{cv::kGovRequiresCredentialType, "EmailVerified"}});
  // The holder presents a matching, valid credential → allowed.
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 holder->did)
                  .allowed);
  // The stranger, under the same requirement, holds nothing → rejected.
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                              stranger->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "credential");
  EXPECT_EQ(r.reason, "credential_required");
}

TEST(ConstraintVocabularyTest, CredentialConstraintIssuerFreshnessRevocation) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto issuer = f.provider.CreateKey("Issuer");
  auto holder = f.provider.CreateKey("Holder");
  const std::string status = "urn:status:cred:kyc";

  const std::string vc = MakeSignedLivingWebVc(
      &f.provider, issuer->id, issuer->did, {"KYC"}, holder->did,
      "2020-01-01T00:00:00Z", status);
  std::string addr;
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(StoreCredential(f.W(), holder->did, vc, &addr));
  }
  InstallKindConstraint(f, f.gcred, cv::kKindCredential, "urn:uuid:cred-r",
                        {{cv::kGovRequiresCredentialType, "KYC"},
                         {cv::kGovCredentialIssuerPattern, issuer->did},
                         {cv::kGovCredentialMinAgeHours, "24"}});
  // Matching issuer, older than 24 h, not revoked → allowed.
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 holder->did)
                  .allowed);
  // Revoking the credential's status subject flips it to rejected (§4.2.2.7).
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(RevokeCredentialStatus(f.W(), status));
  }
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                                  holder->did)
                   .allowed);
}

// ---- §5 temporal constraint ------------------------------------------------

TEST(ConstraintVocabularyTest, TemporalConstraintInterval) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  // A prior matching write event, ~now.
  WriteAs(f, w->id, MakeLit("urn:e:1", "urn:p:post", "first"));
  InstallKindConstraint(f, f.gcred, cv::kKindTemporal, "urn:uuid:temporal-i",
                        {{cv::kGovTemporalMinIntervalSeconds, "3600"},
                         {cv::kGovTemporalAppliesToPredicates, "urn:p:post"}});
  // A second write < 3600 s after the first → interval reject (§5.2.3.3).
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:e:2", "urn:p:post", "second"),
                              w->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "temporal");
  EXPECT_EQ(r.reason, "temporal_interval");
  // A predicate outside applies-to is out of scope → allowed (§5.2.3.1).
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:e:3", "urn:p:other", "x"),
                                 w->did)
                  .allowed);
}

TEST(ConstraintVocabularyTest, TemporalConstraintWindowCount) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  WriteAs(f, w->id, MakeLit("urn:e:1", "urn:p:post", "a"));
  WriteAs(f, w->id, MakeLit("urn:e:2", "urn:p:post", "b"));
  InstallKindConstraint(f, f.gcred, cv::kKindTemporal, "urn:uuid:temporal-w",
                        {{cv::kGovTemporalMaxCountPerWindow, "2"},
                         {cv::kGovTemporalWindowSeconds, "3600"},
                         {cv::kGovTemporalAppliesToPredicates, "urn:p:post"}});
  // Two prior events already fill the window → the third is rejected (§5.2.3.4).
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:e:3", "urn:p:post", "c"),
                              w->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.reason, "temporal_window");
}

// ---- §6 content constraint -------------------------------------------------

TEST(ConstraintVocabularyTest, ContentConstraintLength) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  InstallKindConstraint(f, f.gcred, cv::kKindContent, "urn:uuid:content-len",
                        {{cv::kGovContentMaxLength, "8"},
                         {cv::kGovContentAppliesToPredicates, "urn:p:body"}});
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "short"),
                                 w->did)
                  .allowed);
  auto r = f.gov.CanAddTriple(
      f.W(), MakeLit("urn:n:2", "urn:p:body", "way too long"), w->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "content");
  // Out-of-scope predicate is unaffected by the length rule.
  EXPECT_TRUE(f.gov.CanAddTriple(
                  f.W(), MakeLit("urn:n:3", "urn:p:other", "way too long"),
                  w->did)
                  .allowed);
}

TEST(ConstraintVocabularyTest, ContentConstraintBlockedPattern) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  InstallKindConstraint(f, f.gcred, cv::kKindContent, "urn:uuid:content-pat",
                        {{cv::kGovContentBlockedPatterns, "badword|forbidden"},
                         {cv::kGovContentAppliesToPredicates, "urn:p:body"}});
  EXPECT_FALSE(f.gov.CanAddTriple(
                   f.W(), MakeLit("urn:n:1", "urn:p:body", "has a badword in it"),
                   w->did)
                   .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(
                  f.W(), MakeLit("urn:n:2", "urn:p:body", "totally clean text"),
                  w->did)
                  .allowed);
}

TEST(ConstraintVocabularyTest, ContentConstraintUrlPolicyAndDomain) {
  // A content constraint binds to the graph and governs every write (Spec 04
  // §4.2), so the two conflicting URL policies below live in two graphs.
  {
    GovFixture f;
    RegisterConstraintVocabulary(&f.gov);
    auto w = f.provider.CreateKey("Writer");
    // Disallow URLs entirely.
    InstallKindConstraint(f, f.gcred, cv::kKindContent, "urn:uuid:content-url",
                          {{cv::kGovContentAllowUrls, "false"},
                           {cv::kGovContentAppliesToPredicates, "urn:p:body"}});
    EXPECT_FALSE(
        f.gov.CanAddTriple(
             f.W(), MakeLit("urn:n:1", "urn:p:body", "go http://evil.example/x"),
             w->did)
            .allowed);
    EXPECT_TRUE(f.gov.CanAddTriple(f.W(),
                                   MakeLit("urn:n:2", "urn:p:body", "no link"),
                                   w->did)
                    .allowed);
  }

  // A second graph permits URLs but only to a whitelisted domain.
  {
    GovFixture f;
    RegisterConstraintVocabulary(&f.gov);
    auto w = f.provider.CreateKey("Writer");
    InstallKindConstraint(f, f.gcred, cv::kKindContent, "urn:uuid:content-dom",
                          {{cv::kGovContentAllowUrls, "true"},
                           {cv::kGovContentAllowedDomains, "example.com"},
                           {cv::kGovContentAppliesToPredicates, "urn:p:body"}});
    EXPECT_TRUE(
        f.gov.CanAddTriple(
             f.W(), MakeLit("urn:n:3", "urn:p:body", "see https://example.com/a"),
             w->did)
            .allowed);
    EXPECT_FALSE(
        f.gov.CanAddTriple(
             f.W(), MakeLit("urn:n:4", "urn:p:body", "see https://evil.example/a"),
             w->did)
            .allowed);
  }
}

// ---- §7 caveat types -------------------------------------------------------

TEST(ConstraintVocabularyTest, PredicateCaveatDenyWins) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"predicate\",\"value\":{\"denied\":[\"urn:p:secret\"]}}]");
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(),
                                  MakeLit("urn:n:1", "urn:p:secret", "x"), m->did)
                   .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:ok", "x"),
                                 m->did)
                  .allowed);
}

TEST(ConstraintVocabularyTest, PropertyCaveatAllowList) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"property\",\"value\":{\"allowed\":[\"urn:p:ok\"]}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:ok", "x"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:other", "x"),
                                  m->did)
                   .allowed);
}

TEST(ConstraintVocabularyTest, SubjectGlobCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"subject\",\"value\":{\"pattern\":\"urn:allowed:*\"}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:allowed:1", "urn:p:body", "x"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:other:1", "urn:p:body", "x"),
                                  m->did)
                   .allowed);
}

TEST(ConstraintVocabularyTest, ObjectGlobCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"object\",\"value\":{\"pattern\":\"https://good.example/*\"}}]");
  EXPECT_TRUE(
      f.gov.CanAddTriple(
           f.W(), MakeIri("urn:n:1", "urn:p:ref", "https://good.example/a"),
           m->did)
          .allowed);
  EXPECT_FALSE(
      f.gov.CanAddTriple(
           f.W(), MakeIri("urn:n:2", "urn:p:ref", "https://bad.example/a"),
           m->did)
          .allowed);
}

TEST(ConstraintVocabularyTest, RateLimitCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"rateLimit\",\"value\":{\"maxPerWindow\":2,"
      "\"windowSeconds\":3600}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "a"),
                                 m->did)
                  .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "b"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:3", "urn:p:body", "c"),
                                  m->did)
                   .allowed);
}

TEST(ConstraintVocabularyTest, CardinalityCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(f, root, m->did,
                      "[{\"type\":\"cardinality\",\"value\":{\"max\":2}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "a"),
                                 m->did)
                  .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "b"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:3", "urn:p:body", "c"),
                                  m->did)
                   .allowed);
}

TEST(ConstraintVocabularyTest, AuthorOnlyCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  // The group DID introduces urn:doc:1 (its author of record).
  WriteAs(f, f.gcred, MakeLit("urn:doc:1", "urn:p:body", "original"));
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(f, root, m->did, "[{\"type\":\"authorOnly\"}]");
  // M is not urn:doc:1's author of record → rejected (§7.7).
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(),
                                  MakeLit("urn:doc:1", "urn:p:extra", "y"),
                                  m->did)
                   .allowed);
  // A subject with no prior author of record → accepted (§7.7).
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:doc:2", "urn:p:body", "z"),
                                 m->did)
                  .allowed);
}

TEST(ConstraintVocabularyTest, ShapeCaveatConformsAndFailClosed) {
  // Conforming case: an injected shape service accepts only urn:ok:1.
  GovFixture f;
  ConstraintVocabOptions opts;
  opts.shape_conforms = [](GraphBackend*, const std::string&, const Triple& t) {
    return t.subject == "urn:ok:1";
  };
  RegisterConstraintVocabulary(&f.gov, opts);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"shape\",\"value\":{\"shapeIri\":\"urn:shape:X\"}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:ok:1", "urn:p:body", "hi"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:no:1", "urn:p:body", "hi"),
                                  m->did)
                   .allowed);

  // Fail-closed: with no shape service wired, any shape caveat rejects (§9.6).
  GovFixture f2;
  RegisterConstraintVocabulary(&f2.gov);
  const std::string root2 = BootstrapEnforced(f2);
  auto m2 = f2.provider.CreateKey("M2");
  DelegateWithCaveats(
      f2, root2, m2->did,
      "[{\"type\":\"shape\",\"value\":{\"shapeIri\":\"urn:shape:X\"}}]");
  EXPECT_FALSE(f2.gov.CanAddTriple(f2.W(), MakeLit("urn:ok:1", "urn:p:body", "hi"),
                                   m2->did)
                   .allowed);
}

TEST(ConstraintVocabularyTest, ContentSparqlAskCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  // The ASK passes only when the written triple binds urn:p:body on $this.
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"content\",\"value\":{\"sparql\":"
      "\"ASK { $this <urn:p:body> ?o }\"}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:x:1", "urn:p:body", "hi"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:x:1", "urn:p:other", "hi"),
                                  m->did)
                   .allowed);
}

TEST(ConstraintVocabularyTest, CredentialCaveatRequires) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto issuer = f.provider.CreateKey("Issuer");
  const std::string root = BootstrapEnforced(f);
  auto holder = f.provider.CreateKey("Holder");
  auto bare = f.provider.CreateKey("Bare");

  const std::string vc = MakeSignedLivingWebVc(
      &f.provider, issuer->id, issuer->did, {"EmailVerified"}, holder->did,
      "2020-01-01T00:00:00Z");
  std::string addr;
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(StoreCredential(f.W(), holder->did, vc, &addr));
  }
  const std::string caveats =
      "[{\"type\":\"credential\",\"value\":{\"requires\":"
      "[{\"type\":\"EmailVerified\"}]}}]";
  DelegateWithCaveats(f, root, holder->did, caveats);
  DelegateWithCaveats(f, root, bare->did, caveats);
  // The holder satisfies the required credential; the bare agent does not.
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 holder->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                                  bare->did)
                   .allowed);
}

}  // namespace
}  // namespace content
