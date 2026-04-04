// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for GovernanceEngine — constraint enforcement.

#include "content/browser/graph_governance/governance_engine.h"
#include "content/browser/graph/graph_store.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

SignedTriple MakeTriple(const std::string& source,
                        const std::string& predicate,
                        const std::string& target,
                        const std::string& author = "did:key:agent1",
                        const std::string& timestamp = "2026-01-01T00:00:00Z") {
  SignedTriple t;
  t.data.source = source;
  t.data.predicate = predicate;
  t.data.target = target;
  t.author = author;
  t.timestamp = timestamp;
  t.proof.key = author;
  t.proof.signature = "sig";
  return t;
}

// Helper: set up a graph with governance constraints.
void SetupGovernanceGraph(GraphStore& graph,
                           const std::string& root = "root") {
  // Define entity hierarchy: root → channel1 → thread1
  graph.AddTriple(MakeTriple(root, "has_child", "channel1", "system"));
  graph.AddTriple(MakeTriple("channel1", "has_child", "thread1", "system"));
}

// Helper: add a constraint to the graph.
void AddConstraint(GraphStore& graph,
                   const std::string& entity,
                   const std::string& constraint_id,
                   const std::string& kind) {
  graph.AddTriple(MakeTriple(entity, "governance://has_constraint",
                              constraint_id, "system"));
  graph.AddTriple(MakeTriple(constraint_id, "governance://entry_type",
                              "governance://constraint", "system"));
  graph.AddTriple(MakeTriple(constraint_id, "governance://constraint_kind",
                              kind, "system"));
}

TEST(GovernanceEngineTest, NoConstraintsAllowAll) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;

  auto triple = MakeTriple("entity1", "app://body", "Hello");
  auto result = engine.ValidateTriple(graph, triple, "did:key:root");
  EXPECT_TRUE(result.accepted);
}

TEST(GovernanceEngineTest, ContentMaxLength) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;

  // Add content constraint: max 100 chars.
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length",
                              "100", "system"));

  SetupGovernanceGraph(graph);

  // Short message should pass.
  auto short_triple = MakeTriple("channel1", "app://body", "Hello!");
  auto result = engine.ValidateTriple(graph, short_triple, "did:key:root");
  EXPECT_TRUE(result.accepted);

  // Long message should fail.
  std::string long_text(200, 'x');
  auto long_triple = MakeTriple("channel1", "app://body", long_text);
  result = engine.ValidateTriple(graph, long_triple, "did:key:root");
  EXPECT_FALSE(result.accepted);
  EXPECT_EQ(result.rejecting_kind, "content");
}

TEST(GovernanceEngineTest, ContentBlockedPattern) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;

  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_blocked_patterns",
                              "spam|phishing", "system"));

  SetupGovernanceGraph(graph);

  auto clean = MakeTriple("channel1", "app://body", "Normal message");
  EXPECT_TRUE(engine.ValidateTriple(graph, clean, "did:key:root").accepted);

  auto spam = MakeTriple("channel1", "app://body", "Buy spam now!");
  EXPECT_FALSE(engine.ValidateTriple(graph, spam, "did:key:root").accepted);
}

TEST(GovernanceEngineTest, ContentURLPolicy) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;

  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_url_policy",
                              "block_all", "system"));

  SetupGovernanceGraph(graph);

  auto no_url = MakeTriple("channel1", "app://body", "Just text");
  EXPECT_TRUE(engine.ValidateTriple(graph, no_url, "did:key:root").accepted);

  auto with_url = MakeTriple("channel1", "app://body",
                              "Check https://evil.com/malware");
  EXPECT_FALSE(engine.ValidateTriple(graph, with_url, "did:key:root").accepted);
}

TEST(GovernanceEngineTest, TemporalMaxCount) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;

  AddConstraint(graph, "channel1", "t1", "temporal");
  graph.AddTriple(MakeTriple("t1",
                              "governance://temporal_max_count_per_window",
                              "2", "system"));
  graph.AddTriple(MakeTriple("t1",
                              "governance://temporal_window_seconds",
                              "60", "system"));

  SetupGovernanceGraph(graph);

  // Add two existing triples from agent1.
  graph.AddTriple(MakeTriple("channel1", "app://body", "msg1",
                              "did:key:agent1", "2026-01-01T00:00:01Z"));
  graph.AddTriple(MakeTriple("channel1", "app://body", "msg2",
                              "did:key:agent1", "2026-01-01T00:00:02Z"));

  // Third should be rate-limited.
  auto third = MakeTriple("channel1", "app://body", "msg3",
                           "did:key:agent1", "2026-01-01T00:00:03Z");
  auto result = engine.ValidateTriple(graph, third, "did:key:root");
  EXPECT_FALSE(result.accepted);
  EXPECT_EQ(result.rejecting_kind, "temporal");
}

TEST(GovernanceEngineTest, CredentialRequired) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;

  AddConstraint(graph, "root", "cr1", "credential");
  graph.AddTriple(MakeTriple("cr1",
                              "governance://requires_credential_type",
                              "ProofOfHumanity", "system"));

  // Agent without credential.
  auto triple = MakeTriple("root", "app://body", "Hello", "did:key:agent1");
  auto result = engine.ValidateTriple(graph, triple, "did:key:root");
  EXPECT_FALSE(result.accepted);
  EXPECT_EQ(result.rejecting_kind, "credential");

  // Add credential for agent.
  graph.AddTriple(MakeTriple("did:key:agent1",
                              "governance://has_credential",
                              "cred://abc123", "system"));
  graph.AddTriple(MakeTriple("cred://abc123", "vc://type",
                              "ProofOfHumanity", "system"));
  graph.AddTriple(MakeTriple("cred://abc123", "vc://subject",
                              "did:key:agent1", "system"));

  result = engine.ValidateTriple(graph, triple, "did:key:root");
  EXPECT_TRUE(result.accepted);
}

TEST(GovernanceEngineTest, CapabilityRequired) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;

  AddConstraint(graph, "channel1", "cap1", "capability");
  graph.AddTriple(MakeTriple("cap1",
                              "governance://capability_enforcement",
                              "required", "system"));
  graph.AddTriple(MakeTriple("cap1",
                              "governance://capability_predicates",
                              "app://body", "system"));

  SetupGovernanceGraph(graph);

  // Root authority always passes.
  auto root_triple = MakeTriple("channel1", "app://body", "Hello",
                                 "did:key:root");
  EXPECT_TRUE(
      engine.ValidateTriple(graph, root_triple, "did:key:root").accepted);

  // Agent without ZCAP fails.
  auto agent_triple = MakeTriple("channel1", "app://body", "Hello",
                                  "did:key:agent1");
  EXPECT_FALSE(
      engine.ValidateTriple(graph, agent_triple, "did:key:root").accepted);
}

TEST(GovernanceEngineTest, ScopeInheritance) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);

  // Add content constraint at root — should inherit to thread1.
  AddConstraint(graph, "root", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length",
                              "50", "system"));

  // Triple in thread1 should be subject to root's constraint.
  std::string long_text(100, 'x');
  auto triple = MakeTriple("thread1", "app://body", long_text);
  auto result = engine.ValidateTriple(graph, triple, "did:key:root");
  EXPECT_FALSE(result.accepted);
}

TEST(GovernanceEngineTest, ScopeOverride) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);

  // Root: max 50 chars.
  AddConstraint(graph, "root", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length",
                              "50", "system"));

  // Channel1: max 200 chars (overrides root).
  AddConstraint(graph, "channel1", "c2", "content");
  graph.AddTriple(MakeTriple("c2", "governance://content_max_text_length",
                              "200", "system"));

  // 100-char message in channel1 should pass (channel1's limit is 200).
  std::string medium_text(100, 'x');
  auto triple = MakeTriple("channel1", "app://body", medium_text);
  auto result = engine.ValidateTriple(graph, triple, "did:key:root");
  EXPECT_TRUE(result.accepted);
}

TEST(GovernanceEngineTest, ConstraintsForQuery) {
  GraphStore graph("test", "Test");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);

  AddConstraint(graph, "root", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length",
                              "100", "system"));

  AddConstraint(graph, "channel1", "t1", "temporal");
  graph.AddTriple(MakeTriple("t1",
                              "governance://temporal_min_interval_seconds",
                              "30", "system"));

  auto constraints = engine.GetConstraintsFor(graph, "channel1");
  EXPECT_EQ(constraints.contents.size(), 1u);
  EXPECT_EQ(constraints.temporals.size(), 1u);
}

}  // namespace
}  // namespace content
