// Living Web — Comprehensive Test Suite
// Tests all spec MUST assertions across all five specifications
// Uses a minimal test framework (no gtest dependency)

#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "graph_store.h"
#include "sparql_engine.h"
#include "did_key_provider.h"
#include "governance_engine.h"
#include "sync_service.h"
#include "json_parser.h"

using namespace living_web;

// ============================================================
// Minimal test framework
// ============================================================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static std::vector<std::string> failures;

#define TEST(name) \
  static void test_##name(); \
  static bool test_##name##_registered = (register_test(#name, test_##name), true); \
  static void test_##name()

#define EXPECT_TRUE(expr) do { \
  if (!(expr)) { \
    std::cerr << "  FAIL: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_FALSE(expr) EXPECT_TRUE(!(expr))
#define EXPECT_EQ(a, b) do { \
  auto _a = (a); auto _b = (b); \
  if (_a != _b) { \
    std::cerr << "  FAIL: " << #a << " == " << #b << " (" << _a << " != " << _b << ") at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_NE(a, b) do { \
  if ((a) == (b)) { \
    std::cerr << "  FAIL: " << #a << " != " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_GT(a, b) do { \
  if (!((a) > (b))) { \
    std::cerr << "  FAIL: " << #a << " > " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

struct TestEntry {
  std::string name;
  std::function<void()> fn;
};
static std::vector<TestEntry>& test_registry() {
  static std::vector<TestEntry> r;
  return r;
}
static void register_test(const std::string& name, std::function<void()> fn) {
  test_registry().push_back({name, fn});
}

// ============================================================
// Helper functions
// ============================================================

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

void SetupGovernanceGraph(GraphStore& graph, const std::string& root = "root") {
  graph.AddTriple(MakeTriple(root, "has_child", "channel1", "system"));
  graph.AddTriple(MakeTriple("channel1", "has_child", "thread1", "system"));
}

void AddConstraint(GraphStore& graph, const std::string& entity,
                   const std::string& constraint_id, const std::string& kind) {
  graph.AddTriple(MakeTriple(entity, "governance://has_constraint", constraint_id, "system"));
  graph.AddTriple(MakeTriple(constraint_id, "governance://constraint_kind", kind, "system"));
}

// ============================================================
// 1. GRAPH STORE TESTS
// ============================================================

TEST(GraphStore_CreateAndRetrieve) {
  GraphStore store("test-uuid", "Test Graph");
  EXPECT_EQ(store.uuid(), "test-uuid");
  EXPECT_EQ(store.name(), "Test Graph");
  EXPECT_EQ(store.size(), 0u);
}

TEST(GraphStore_AddTriple) {
  GraphStore store("t", "T");
  auto triple = MakeTriple("ex:alice", "foaf:knows", "ex:bob");
  EXPECT_TRUE(store.AddTriple(triple));
  EXPECT_EQ(store.size(), 1u);
}

TEST(GraphStore_AddDuplicate) {
  GraphStore store("t", "T");
  auto triple = MakeTriple("ex:alice", "foaf:knows", "ex:bob");
  EXPECT_TRUE(store.AddTriple(triple));
  EXPECT_FALSE(store.AddTriple(triple));
  EXPECT_EQ(store.size(), 1u);
}

TEST(GraphStore_RemoveTriple) {
  GraphStore store("t", "T");
  auto triple = MakeTriple("ex:alice", "foaf:knows", "ex:bob");
  store.AddTriple(triple);
  EXPECT_TRUE(store.RemoveTriple(triple));
  EXPECT_EQ(store.size(), 0u);
  EXPECT_FALSE(store.RemoveTriple(triple));
}

TEST(GraphStore_QueryBySource) {
  GraphStore store("t", "T");
  store.AddTriple(MakeTriple("ex:alice", "foaf:knows", "ex:bob"));
  store.AddTriple(MakeTriple("ex:alice", "foaf:name", "Alice"));
  store.AddTriple(MakeTriple("ex:bob", "foaf:name", "Bob"));
  TripleQuery q;
  q.source = "ex:alice";
  EXPECT_EQ(store.QueryTriples(q).size(), 2u);
}

TEST(GraphStore_QueryByPredicate) {
  GraphStore store("t", "T");
  store.AddTriple(MakeTriple("ex:alice", "foaf:knows", "ex:bob"));
  store.AddTriple(MakeTriple("ex:alice", "foaf:name", "Alice"));
  TripleQuery q;
  q.predicate = "foaf:knows";
  auto results = store.QueryTriples(q);
  EXPECT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].data.target, "ex:bob");
}

TEST(GraphStore_QueryByTarget) {
  GraphStore store("t", "T");
  store.AddTriple(MakeTriple("ex:alice", "foaf:knows", "ex:bob"));
  store.AddTriple(MakeTriple("ex:carol", "foaf:knows", "ex:bob"));
  TripleQuery q;
  q.target = "ex:bob";
  EXPECT_EQ(store.QueryTriples(q).size(), 2u);
}

TEST(GraphStore_QueryWithLimit) {
  GraphStore store("t", "T");
  for (int i = 0; i < 10; i++) {
    store.AddTriple(MakeTriple("ex:alice", "ex:item",
                                "ex:item" + std::to_string(i), "did:key:test",
                                "2026-01-0" + std::to_string(i + 1) + "T00:00:00Z"));
  }
  TripleQuery q;
  q.source = "ex:alice";
  q.limit = 5;
  EXPECT_EQ(store.QueryTriples(q).size(), 5u);
}

TEST(GraphStore_QueryTemporalRange) {
  GraphStore store("t", "T");
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:b", "did:key:test", "2026-01-01T00:00:00Z"));
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:c", "did:key:test", "2026-06-01T00:00:00Z"));
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:d", "did:key:test", "2026-12-01T00:00:00Z"));
  TripleQuery q;
  q.source = "ex:a";
  q.from_date = "2026-03-01T00:00:00Z";
  q.until_date = "2026-09-01T00:00:00Z";
  auto results = store.QueryTriples(q);
  EXPECT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].data.target, "ex:c");
}

TEST(GraphStore_Snapshot) {
  GraphStore store("t", "T");
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:b", "did:key:test", "2026-02-01T00:00:00Z"));
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:c", "did:key:test", "2026-01-01T00:00:00Z"));
  auto snapshot = store.Snapshot();
  EXPECT_EQ(snapshot.size(), 2u);
  EXPECT_EQ(snapshot[0].timestamp, "2026-01-01T00:00:00Z");
  EXPECT_EQ(snapshot[1].timestamp, "2026-02-01T00:00:00Z");
}

TEST(GraphStore_AddTriplesBatch) {
  GraphStore store("t", "T");
  std::vector<SignedTriple> batch = {
    MakeTriple("ex:a", "ex:p", "ex:b"),
    MakeTriple("ex:a", "ex:p", "ex:c"),
  };
  EXPECT_TRUE(store.AddTriples(batch));
  EXPECT_EQ(store.size(), 2u);
}

TEST(GraphStore_AddTriplesBatchAtomicFailure) {
  GraphStore store("t", "T");
  auto existing = MakeTriple("ex:a", "ex:p", "ex:b");
  store.AddTriple(existing);
  std::vector<SignedTriple> batch = {
    MakeTriple("ex:a", "ex:p", "ex:c"),
    existing,
  };
  EXPECT_FALSE(store.AddTriples(batch));
  EXPECT_EQ(store.size(), 1u);
}

TEST(GraphStore_URIValidation) {
  // Source and target should be non-empty strings
  GraphStore store("t", "T");
  auto t = MakeTriple("", "ex:p", "ex:b");
  // Empty source is technically allowed by the store (spec says "string")
  EXPECT_TRUE(store.AddTriple(t));
  // But useful data requires URIs
  auto t2 = MakeTriple("ex:alice", "foaf:knows", "ex:bob");
  EXPECT_TRUE(store.AddTriple(t2));
}

TEST(GraphStore_ShapeAddAndQuery) {
  GraphStore store("t", "T");
  std::string shape_json = R"({
    "targetClass": "ex:Task",
    "properties": [
      {"path": "ex:title", "name": "title", "minCount": 1, "maxCount": 1}
    ],
    "constructor": [
      {"action": "addLink", "predicate": "rdf:type", "value": "ex:Task"},
      {"action": "addLink", "predicate": "ex:title", "target": "title"}
    ]
  })";
  EXPECT_TRUE(store.AddShape("Task", shape_json));
  auto uri = store.CreateShapeInstance("Task", R"({"title": "My Task"})");
  EXPECT_FALSE(uri.empty());
  auto instances = store.GetShapeInstances("Task");
  EXPECT_EQ(instances.size(), 1u);
  EXPECT_EQ(instances[0], uri);
}

TEST(GraphStore_ShapeInvalidJSON) {
  GraphStore store("t", "T");
  EXPECT_FALSE(store.AddShape("Bad", "not json"));
  EXPECT_FALSE(store.AddShape("Bad", R"({"no":"targetClass"})"));
}

TEST(GraphStore_ShapePropertyGet) {
  GraphStore store("t", "T");
  std::string shape_json = R"({
    "targetClass": "ex:Person",
    "properties": [
      {"path": "ex:name", "name": "name", "minCount": 1, "maxCount": 1}
    ],
    "constructor": [
      {"action": "addLink", "predicate": "rdf:type", "value": "ex:Person"},
      {"action": "addLink", "predicate": "ex:name", "target": "name"}
    ]
  })";
  EXPECT_TRUE(store.AddShape("Person", shape_json));
  auto uri = store.CreateShapeInstance("Person", R"({"name": "Alice"})");
  EXPECT_FALSE(uri.empty());

  // Query the instance's properties
  TripleQuery q;
  q.source = uri;
  q.predicate = "ex:name";
  auto results = store.QueryTriples(q);
  EXPECT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].data.target, "Alice");
}

// ============================================================
// 2. SPARQL ENGINE TESTS
// ============================================================

TEST(Sparql_BasicSelect) {
  SparqlEngine engine;
  GraphStore store("t", "T");
  store.AddTriple(MakeTriple("ex:alice", "foaf:knows", "ex:bob"));
  store.AddTriple(MakeTriple("ex:alice", "foaf:name", "Alice"));

  auto result = engine.Execute(
      "SELECT ?name WHERE { <ex:alice> <foaf:name> ?name }",
      store.triples());
  EXPECT_NE(result.find("Alice"), std::string::npos);
}

TEST(Sparql_SelectWithLimit) {
  SparqlEngine engine;
  std::vector<SignedTriple> triples;
  for (int i = 0; i < 10; i++) {
    triples.push_back(MakeTriple("ex:alice", "foaf:knows",
                                  "ex:friend" + std::to_string(i)));
  }
  auto result = engine.Execute(
      "SELECT ?f WHERE { <ex:alice> <foaf:knows> ?f } LIMIT 3", triples);
  // Count occurrences of "ex:friend" in result
  int count = 0;
  size_t pos = 0;
  while ((pos = result.find("ex:friend", pos)) != std::string::npos) {
    count++;
    pos++;
  }
  EXPECT_EQ(count, 3);
}

TEST(Sparql_SelectStar) {
  SparqlEngine engine;
  std::vector<SignedTriple> triples = {
    MakeTriple("ex:alice", "foaf:knows", "ex:bob"),
  };
  auto result = engine.Execute(
      "SELECT * WHERE { ?s <foaf:knows> ?o }", triples);
  EXPECT_NE(result.find("ex:alice"), std::string::npos);
  EXPECT_NE(result.find("ex:bob"), std::string::npos);
}

TEST(Sparql_OptionalPattern) {
  SparqlEngine engine;
  std::vector<SignedTriple> triples = {
    MakeTriple("ex:alice", "foaf:knows", "ex:bob"),
    MakeTriple("ex:alice", "foaf:name", "Alice"),
  };
  auto result = engine.Execute(
      "SELECT ?s ?name WHERE { ?s <foaf:knows> <ex:bob> . "
      "OPTIONAL { ?s <foaf:name> ?name } }",
      triples);
  EXPECT_NE(result.find("Alice"), std::string::npos);
}

TEST(Sparql_MultiplePatterns) {
  SparqlEngine engine;
  std::vector<SignedTriple> triples = {
    MakeTriple("ex:alice", "foaf:knows", "ex:bob"),
    MakeTriple("ex:bob", "foaf:name", "Bob"),
  };
  auto result = engine.Execute(
      "SELECT ?name WHERE { <ex:alice> <foaf:knows> ?person . "
      "?person <foaf:name> ?name }",
      triples);
  EXPECT_NE(result.find("Bob"), std::string::npos);
}

TEST(Sparql_NoResults) {
  SparqlEngine engine;
  std::vector<SignedTriple> triples = {
    MakeTriple("ex:alice", "foaf:knows", "ex:bob"),
  };
  auto result = engine.Execute(
      "SELECT ?x WHERE { <ex:nobody> <foaf:knows> ?x }", triples);
  EXPECT_EQ(result, "[]");
}

// ============================================================
// 3. DID KEY TESTS
// ============================================================

TEST(DID_CreateKey) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Test Identity");
  EXPECT_TRUE(key != nullptr);
  EXPECT_FALSE(key->did.empty());
  EXPECT_EQ(key->algorithm, "Ed25519");
  EXPECT_EQ(key->display_name, "Test Identity");
  EXPECT_FALSE(key->is_locked);
  EXPECT_EQ(key->public_key.size(), 32u);
  EXPECT_EQ(key->private_key.size(), 64u);
  EXPECT_EQ(key->did.substr(0, 12), "did:key:z6Mk");
}

TEST(DID_ListCredentials) {
  DIDKeyProvider provider;
  provider.CreateKey("First");
  provider.CreateKey("Second");
  EXPECT_EQ(provider.ListCredentials().size(), 2u);
}

TEST(DID_ActiveCredential) {
  DIDKeyProvider provider;
  auto first = provider.CreateKey("First");
  auto second = provider.CreateKey("Second");
  auto active = provider.GetActiveCredential();
  EXPECT_TRUE(active != nullptr);
  EXPECT_EQ(active->id, first->id);
  EXPECT_TRUE(provider.SetActiveCredential(second->id));
  active = provider.GetActiveCredential();
  EXPECT_EQ(active->id, second->id);
}

TEST(DID_DeleteCredential) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("ToDelete");
  EXPECT_TRUE(provider.DeleteCredential(key->id));
  EXPECT_EQ(provider.ListCredentials().size(), 0u);
  EXPECT_FALSE(provider.DeleteCredential("nonexistent"));
}

TEST(DID_SignAndVerify) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Signer");
  auto result = provider.Sign(key->id, R"({"message":"hello"})");
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(result->author, key->did);
  EXPECT_FALSE(result->proof_sig.empty());
  EXPECT_FALSE(result->timestamp.empty());
  EXPECT_TRUE(provider.Verify(result->author, result->data_json,
                                result->timestamp, result->proof_sig));
  EXPECT_FALSE(provider.Verify(result->author, R"({"message":"tampered"})",
                                 result->timestamp, result->proof_sig));
}

TEST(DID_SignLockedKey) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Lockable");
  EXPECT_TRUE(provider.Lock(key->id));
  EXPECT_FALSE(provider.Sign(key->id, "data").has_value());
  EXPECT_TRUE(provider.Unlock(key->id));
  EXPECT_TRUE(provider.Sign(key->id, "data").has_value());
}

TEST(DID_ResolveDID) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Resolvable");
  auto doc = provider.ResolveDID(key->did);
  EXPECT_FALSE(doc.empty());
  EXPECT_NE(doc.find(key->did), std::string::npos);
  EXPECT_NE(doc.find("Ed25519VerificationKey2020"), std::string::npos);
  EXPECT_NE(doc.find("authentication"), std::string::npos);
  EXPECT_NE(doc.find("assertionMethod"), std::string::npos);
  EXPECT_NE(doc.find("capabilityDelegation"), std::string::npos);
  EXPECT_NE(doc.find("capabilityInvocation"), std::string::npos);
}

TEST(DID_ResolveInvalidDID) {
  DIDKeyProvider provider;
  EXPECT_TRUE(provider.ResolveDID("did:web:example.com").empty());
}

TEST(DID_MultipleKeys_UniqueDIDs) {
  DIDKeyProvider provider;
  auto k1 = provider.CreateKey("Key1");
  auto k2 = provider.CreateKey("Key2");
  EXPECT_NE(k1->did, k2->did);
  EXPECT_NE(k1->id, k2->id);
}

TEST(DID_CrossKeyVerification) {
  DIDKeyProvider provider;
  auto k1 = provider.CreateKey("Key1");
  auto k2 = provider.CreateKey("Key2");

  auto signed1 = provider.Sign(k1->id, "data");
  EXPECT_TRUE(signed1.has_value());

  // Verify with k1's DID should work
  EXPECT_TRUE(provider.Verify(signed1->author, signed1->data_json,
                                signed1->timestamp, signed1->proof_sig));

  // Cannot verify with k2's DID
  EXPECT_FALSE(provider.Verify(k2->did, signed1->data_json,
                                 signed1->timestamp, signed1->proof_sig));
}

TEST(DID_InvalidSignatureRejection) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Test");
  auto result = provider.Sign(key->id, "data");
  EXPECT_TRUE(result.has_value());

  // Corrupt signature
  std::string bad_sig = result->proof_sig;
  bad_sig[0] = (bad_sig[0] == 'a') ? 'b' : 'a';
  EXPECT_FALSE(provider.Verify(result->author, result->data_json,
                                 result->timestamp, bad_sig));

  // Wrong timestamp
  EXPECT_FALSE(provider.Verify(result->author, result->data_json,
                                 "1999-01-01T00:00:00Z", result->proof_sig));
}

// ============================================================
// 4. GOVERNANCE TESTS
// ============================================================

TEST(Governance_NoConstraintsAllowAll) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  auto triple = MakeTriple("entity1", "app://body", "Hello");
  EXPECT_TRUE(engine.ValidateTriple(graph, triple, "did:key:root").accepted);
}

TEST(Governance_ContentMaxLength) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length", "100", "system"));
  SetupGovernanceGraph(graph);

  auto short_t = MakeTriple("channel1", "app://body", "Hello!");
  EXPECT_TRUE(engine.ValidateTriple(graph, short_t, "did:key:root").accepted);

  std::string long_text(200, 'x');
  auto long_t = MakeTriple("channel1", "app://body", long_text);
  auto result = engine.ValidateTriple(graph, long_t, "did:key:root");
  EXPECT_FALSE(result.accepted);
  EXPECT_EQ(result.rejecting_kind, "content");
}

TEST(Governance_ContentMinLength) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_min_text_length", "5", "system"));
  SetupGovernanceGraph(graph);

  auto short_t = MakeTriple("channel1", "app://body", "Hi");
  EXPECT_FALSE(engine.ValidateTriple(graph, short_t, "did:key:root").accepted);

  auto ok_t = MakeTriple("channel1", "app://body", "Hello World");
  EXPECT_TRUE(engine.ValidateTriple(graph, ok_t, "did:key:root").accepted);
}

TEST(Governance_ContentBlockedPattern) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_blocked_patterns", "spam|phishing", "system"));
  SetupGovernanceGraph(graph);

  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Normal"), "did:key:root").accepted);
  EXPECT_FALSE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Buy spam now!"), "did:key:root").accepted);
  EXPECT_FALSE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "phishing link"), "did:key:root").accepted);
}

TEST(Governance_ContentURLPolicyBlockAll) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_url_policy", "block_all", "system"));
  SetupGovernanceGraph(graph);

  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Just text"), "did:key:root").accepted);
  EXPECT_FALSE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Check https://evil.com"), "did:key:root").accepted);
}

TEST(Governance_ContentURLPolicyAllowlist) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_url_policy", "allowlist", "system"));
  graph.AddTriple(MakeTriple("c1", "governance://content_url_list", "example.com,trusted.org", "system"));
  SetupGovernanceGraph(graph);

  auto allowed = MakeTriple("channel1", "app://body", "See https://example.com/page");
  EXPECT_TRUE(engine.ValidateTriple(graph, allowed, "did:key:root").accepted);

  auto blocked = MakeTriple("channel1", "app://body", "See https://evil.com/hack");
  EXPECT_FALSE(engine.ValidateTriple(graph, blocked, "did:key:root").accepted);
}

TEST(Governance_ContentURLPolicyBlocklist) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_url_policy", "blocklist", "system"));
  graph.AddTriple(MakeTriple("c1", "governance://content_url_list", "evil.com,malware.org", "system"));
  SetupGovernanceGraph(graph);

  auto ok = MakeTriple("channel1", "app://body", "See https://good.com/page");
  EXPECT_TRUE(engine.ValidateTriple(graph, ok, "did:key:root").accepted);

  auto bad = MakeTriple("channel1", "app://body", "See https://evil.com/hack");
  EXPECT_FALSE(engine.ValidateTriple(graph, bad, "did:key:root").accepted);
}

TEST(Governance_TemporalMaxCount) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "t1", "temporal");
  graph.AddTriple(MakeTriple("t1", "governance://temporal_max_count_per_window", "2", "system"));
  SetupGovernanceGraph(graph);

  graph.AddTriple(MakeTriple("channel1", "app://body", "msg1", "did:key:agent1", "2026-01-01T00:00:01Z"));
  graph.AddTriple(MakeTriple("channel1", "app://body", "msg2", "did:key:agent1", "2026-01-01T00:00:02Z"));

  auto third = MakeTriple("channel1", "app://body", "msg3", "did:key:agent1", "2026-01-01T00:00:03Z");
  auto result = engine.ValidateTriple(graph, third, "did:key:root");
  EXPECT_FALSE(result.accepted);
  EXPECT_EQ(result.rejecting_kind, "temporal");
}

TEST(Governance_TemporalMinInterval) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "t1", "temporal");
  graph.AddTriple(MakeTriple("t1", "governance://temporal_min_interval_seconds", "60", "system"));
  SetupGovernanceGraph(graph);

  graph.AddTriple(MakeTriple("channel1", "app://body", "msg1", "did:key:agent1", "2026-01-01T00:00:30Z"));

  // Too soon (same second)
  auto too_soon = MakeTriple("channel1", "app://body", "msg2", "did:key:agent1", "2026-01-01T00:00:30Z");
  EXPECT_FALSE(engine.ValidateTriple(graph, too_soon, "did:key:root").accepted);
}

TEST(Governance_TemporalPredicateFiltering) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "t1", "temporal");
  graph.AddTriple(MakeTriple("t1", "governance://temporal_max_count_per_window", "1", "system"));
  graph.AddTriple(MakeTriple("t1", "governance://temporal_applies_to_predicates", "app://body", "system"));
  SetupGovernanceGraph(graph);

  graph.AddTriple(MakeTriple("channel1", "app://body", "msg1", "did:key:agent1", "2026-01-01T00:00:01Z"));

  // Second body triple blocked
  auto blocked = MakeTriple("channel1", "app://body", "msg2", "did:key:agent1", "2026-01-01T00:00:02Z");
  EXPECT_FALSE(engine.ValidateTriple(graph, blocked, "did:key:root").accepted);

  // Different predicate allowed
  auto allowed = MakeTriple("channel1", "app://reaction", "👍", "did:key:agent1", "2026-01-01T00:00:02Z");
  EXPECT_TRUE(engine.ValidateTriple(graph, allowed, "did:key:root").accepted);
}

TEST(Governance_CredentialRequired) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "root", "cr1", "credential");
  graph.AddTriple(MakeTriple("cr1", "governance://requires_credential_type", "ProofOfHumanity", "system"));

  auto triple = MakeTriple("root", "app://body", "Hello", "did:key:agent1");
  EXPECT_FALSE(engine.ValidateTriple(graph, triple, "did:key:root").accepted);

  // Add credential
  graph.AddTriple(MakeTriple("did:key:agent1", "governance://has_credential", "cred://abc123", "system"));
  graph.AddTriple(MakeTriple("cred://abc123", "vc://type", "ProofOfHumanity", "system"));
  graph.AddTriple(MakeTriple("cred://abc123", "vc://subject", "did:key:agent1", "system"));

  EXPECT_TRUE(engine.ValidateTriple(graph, triple, "did:key:root").accepted);
}

TEST(Governance_CredentialIssuerPattern) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "root", "cr1", "credential");
  graph.AddTriple(MakeTriple("cr1", "governance://requires_credential_type", "Membership", "system"));
  graph.AddTriple(MakeTriple("cr1", "governance://credential_issuer_pattern", "did:key:issuer*", "system"));

  // Add credential with matching issuer
  graph.AddTriple(MakeTriple("did:key:agent1", "governance://has_credential", "cred://m1", "system"));
  graph.AddTriple(MakeTriple("cred://m1", "vc://type", "Membership", "system"));
  graph.AddTriple(MakeTriple("cred://m1", "vc://subject", "did:key:agent1", "system"));
  graph.AddTriple(MakeTriple("cred://m1", "vc://issuer", "did:key:issuer123", "system"));

  auto triple = MakeTriple("root", "app://body", "Hello", "did:key:agent1");
  EXPECT_TRUE(engine.ValidateTriple(graph, triple, "did:key:root").accepted);
}

TEST(Governance_CapabilityRequired) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "cap1", "capability");
  graph.AddTriple(MakeTriple("cap1", "governance://capability_enforcement", "required", "system"));
  graph.AddTriple(MakeTriple("cap1", "governance://capability_predicates", "app://body", "system"));
  SetupGovernanceGraph(graph);

  // Root authority always passes
  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Hi", "did:key:root"), "did:key:root").accepted);
  // Agent without ZCAP fails
  EXPECT_FALSE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Hi", "did:key:agent1"), "did:key:root").accepted);
}

TEST(Governance_ZcapValid) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "cap1", "capability");
  graph.AddTriple(MakeTriple("cap1", "governance://capability_enforcement", "required", "system"));
  graph.AddTriple(MakeTriple("cap1", "governance://capability_predicates", "app://body", "system"));
  SetupGovernanceGraph(graph);

  // Grant ZCAP to agent1
  graph.AddTriple(MakeTriple("did:key:agent1", "governance://has_zcap", "zcap://1", "system"));
  graph.AddTriple(MakeTriple("zcap://1", "governance://capability_predicates", "app://body", "system"));

  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Hi", "did:key:agent1"), "did:key:root").accepted);
}

TEST(Governance_ZcapRevoked) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "cap1", "capability");
  graph.AddTriple(MakeTriple("cap1", "governance://capability_enforcement", "required", "system"));
  graph.AddTriple(MakeTriple("cap1", "governance://capability_predicates", "app://body", "system"));
  SetupGovernanceGraph(graph);

  // Grant then revoke
  graph.AddTriple(MakeTriple("did:key:agent1", "governance://has_zcap", "zcap://1", "system"));
  graph.AddTriple(MakeTriple("zcap://1", "governance://capability_predicates", "app://body", "system"));
  graph.AddTriple(MakeTriple("did:key:root", "governance://revokes_capability", "zcap://1", "system"));

  EXPECT_FALSE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Hi", "did:key:agent1"), "did:key:root").accepted);
}

TEST(Governance_ZcapWrongPredicate) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "cap1", "capability");
  graph.AddTriple(MakeTriple("cap1", "governance://capability_enforcement", "required", "system"));
  graph.AddTriple(MakeTriple("cap1", "governance://capability_predicates", "app://body", "system"));
  SetupGovernanceGraph(graph);

  // ZCAP for different predicate
  graph.AddTriple(MakeTriple("did:key:agent1", "governance://has_zcap", "zcap://1", "system"));
  graph.AddTriple(MakeTriple("zcap://1", "governance://capability_predicates", "app://reaction", "system"));

  EXPECT_FALSE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Hi", "did:key:agent1"), "did:key:root").accepted);
}

TEST(Governance_ZcapDelegationChain) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "cap1", "capability");
  graph.AddTriple(MakeTriple("cap1", "governance://capability_enforcement", "required", "system"));
  graph.AddTriple(MakeTriple("cap1", "governance://capability_predicates", "app://body", "system"));
  SetupGovernanceGraph(graph);

  // A→B→C delegation chain
  graph.AddTriple(MakeTriple("did:key:agentB", "governance://has_zcap", "zcap://b", "system"));
  graph.AddTriple(MakeTriple("zcap://b", "governance://capability_predicates", "app://body", "system"));
  graph.AddTriple(MakeTriple("zcap://b", "governance://parent_capability", "zcap://a", "system"));

  graph.AddTriple(MakeTriple("did:key:agentC", "governance://has_zcap", "zcap://c", "system"));
  graph.AddTriple(MakeTriple("zcap://c", "governance://capability_predicates", "app://body", "system"));
  graph.AddTriple(MakeTriple("zcap://c", "governance://parent_capability", "zcap://b", "system"));

  // C should be able to act (chain of 2 hops)
  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Hi", "did:key:agentC"), "did:key:root").accepted);
}

TEST(Governance_ZcapScopeRestriction) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "channel1", "cap1", "capability");
  graph.AddTriple(MakeTriple("cap1", "governance://capability_enforcement", "required", "system"));
  SetupGovernanceGraph(graph);

  // ZCAP scoped to channel1
  graph.AddTriple(MakeTriple("did:key:agent1", "governance://has_zcap", "zcap://1", "system"));
  graph.AddTriple(MakeTriple("zcap://1", "governance://capability_scope", "channel1", "system"));

  // Within scope: channel1
  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", "Hi", "did:key:agent1"), "did:key:root").accepted);
  // thread1 is child of channel1, so also in scope
  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("thread1", "app://body", "Hi", "did:key:agent1"), "did:key:root").accepted);
}

TEST(Governance_ScopeInheritance) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);
  AddConstraint(graph, "root", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length", "50", "system"));

  std::string long_text(100, 'x');
  auto triple = MakeTriple("thread1", "app://body", long_text);
  EXPECT_FALSE(engine.ValidateTriple(graph, triple, "did:key:root").accepted);
}

TEST(Governance_ScopeOverride) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);

  AddConstraint(graph, "root", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length", "50", "system"));
  AddConstraint(graph, "channel1", "c2", "content");
  graph.AddTriple(MakeTriple("c2", "governance://content_max_text_length", "200", "system"));

  std::string medium_text(100, 'x');
  EXPECT_TRUE(engine.ValidateTriple(graph, MakeTriple("channel1", "app://body", medium_text), "did:key:root").accepted);
}

TEST(Governance_ConstraintsForQuery) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);

  AddConstraint(graph, "root", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length", "100", "system"));
  AddConstraint(graph, "channel1", "t1", "temporal");
  graph.AddTriple(MakeTriple("t1", "governance://temporal_min_interval_seconds", "30", "system"));

  auto constraints = engine.GetConstraintsFor(graph, "channel1");
  EXPECT_EQ(constraints.contents.size(), 1u);
  EXPECT_EQ(constraints.temporals.size(), 1u);
}

TEST(Governance_DefaultCapabilityIssuance) {
  // Without capability constraint, any agent can add triples
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);

  auto result = engine.CanAddTriple(graph, "did:key:anyone", "app://body", "channel1", "did:key:root");
  EXPECT_TRUE(result.accepted);
}

TEST(Governance_CustomConstraintKind) {
  // Unknown constraint kinds are ignored
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  AddConstraint(graph, "root", "custom1", "custom_moderation");
  // Since "custom_moderation" isn't a recognized kind, it's skipped
  auto triple = MakeTriple("root", "app://body", "Hello");
  EXPECT_TRUE(engine.ValidateTriple(graph, triple, "did:key:root").accepted);
}

TEST(Governance_FullPipeline_FirstRejectionWins) {
  GraphStore graph("t", "T");
  GovernanceEngine engine;
  SetupGovernanceGraph(graph);

  // Add content constraint (max 10 chars)
  AddConstraint(graph, "channel1", "c1", "content");
  graph.AddTriple(MakeTriple("c1", "governance://content_max_text_length", "10", "system"));

  // Add credential constraint
  AddConstraint(graph, "root", "cr1", "credential");
  graph.AddTriple(MakeTriple("cr1", "governance://requires_credential_type", "ProofOfHumanity", "system"));

  // Triple that violates both: no credential AND too long
  std::string long_text(20, 'x');
  auto triple = MakeTriple("channel1", "app://body", long_text, "did:key:agent1");
  auto result = engine.ValidateTriple(graph, triple, "did:key:root");
  EXPECT_FALSE(result.accepted);
  // Content is checked before credentials in pipeline, so content wins
  EXPECT_EQ(result.rejecting_kind, "content");
}

// ============================================================
// 5. SYNC TESTS
// ============================================================

TEST(Sync_ShareGraph) {
  SyncService svc;
  auto uri = svc.ShareGraph("graph1", "My Graph");
  EXPECT_FALSE(uri.empty());
  EXPECT_EQ(svc.session_count(), 1u);
  auto session = svc.GetSession(uri);
  EXPECT_TRUE(session != nullptr);
  EXPECT_EQ(session->name, "My Graph");
}

TEST(Sync_JoinGraph) {
  SyncService svc;
  auto uri = svc.ShareGraph("graph1");
  SyncService svc2;
  EXPECT_TRUE(svc2.JoinGraph(uri));
  EXPECT_EQ(svc2.session_count(), 1u);
}

TEST(Sync_TwoPeersConnect) {
  SyncService svcA, svcB;
  auto uri = svcA.ShareGraph("graph1");
  svcB.JoinGraph(uri);

  svcA.AddPeer(uri, "did:key:peerB");
  svcB.AddPeer(uri, "did:key:peerA");

  EXPECT_EQ(svcA.GetPeers(uri).size(), 1u);
  EXPECT_EQ(svcB.GetPeers(uri).size(), 1u);
}

TEST(Sync_TripleAddedSyncs) {
  SyncService svcA, svcB;
  GraphStore storeA("g1", "G1"), storeB("g1", "G1");
  auto uri = svcA.ShareGraph("g1");
  svcB.JoinGraph(uri);

  // A adds a triple and creates a diff
  auto triple = MakeTriple("ex:a", "ex:p", "ex:b", "did:key:peerA");
  storeA.AddTriple(triple);
  auto diff = svcA.CommitDiff(uri, {triple}, {}, "did:key:peerA");

  // B receives the diff
  svcB.ApplyDiff(uri, &storeB, diff);
  EXPECT_EQ(storeB.size(), 1u);
  auto snapshot = storeB.Snapshot();
  EXPECT_EQ(snapshot[0].data.source, "ex:a");
}

TEST(Sync_RemovalSyncs) {
  SyncService svcA, svcB;
  GraphStore storeA("g1", "G1"), storeB("g1", "G1");
  auto uri = svcA.ShareGraph("g1");
  svcB.JoinGraph(uri);

  // Both start with same triple
  auto triple = MakeTriple("ex:a", "ex:p", "ex:b");
  storeA.AddTriple(triple);
  storeB.AddTriple(triple);

  // A removes it
  storeA.RemoveTriple(triple);
  auto diff = svcA.CommitDiff(uri, {}, {triple}, "did:key:peerA");

  // B receives removal
  svcB.ApplyDiff(uri, &storeB, diff);
  EXPECT_EQ(storeB.size(), 0u);
}

TEST(Sync_ConcurrentEditsConverge) {
  SyncService svcA, svcB;
  GraphStore storeA("g1", "G1"), storeB("g1", "G1");
  auto uri = svcA.ShareGraph("g1");
  svcB.JoinGraph(uri);

  // A adds triple1, B adds triple2 concurrently
  auto t1 = MakeTriple("ex:a", "ex:p", "ex:1", "did:key:A");
  auto t2 = MakeTriple("ex:b", "ex:q", "ex:2", "did:key:B");

  storeA.AddTriple(t1);
  storeB.AddTriple(t2);

  auto diffA = svcA.CommitDiff(uri, {t1}, {}, "did:key:A");
  auto diffB = svcB.CommitDiff(uri, {t2}, {}, "did:key:B");

  // Cross-apply
  svcB.ApplyDiff(uri, &storeB, diffA);
  svcA.ApplyDiff(uri, &storeA, diffB);

  // Both should have both triples
  EXPECT_EQ(storeA.size(), 2u);
  EXPECT_EQ(storeB.size(), 2u);
}

TEST(Sync_SignalDelivery) {
  SyncService svcA, svcB;
  auto uri = svcA.ShareGraph("g1");
  svcB.JoinGraph(uri);

  InProcessTransport transport;
  transport.Connect(&svcA, &svcB, uri);

  std::string received_signal;
  svcB.SetOnSignalReceived([&](const std::string& sender, const std::string& payload) {
    received_signal = payload;
  });

  transport.SendSignal(&svcA, uri, "did:key:A", R"({"type":"ping"})");
  EXPECT_EQ(received_signal, R"({"type":"ping"})");
}

TEST(Sync_PeerJoinLeaveEvents) {
  SyncService svc;
  auto uri = svc.ShareGraph("g1");

  std::string joined_did, left_did;
  svc.SetOnPeerJoined([&](const std::string& did) { joined_did = did; });
  svc.SetOnPeerLeft([&](const std::string& did) { left_did = did; });

  svc.AddPeer(uri, "did:key:peerB");
  EXPECT_EQ(joined_did, "did:key:peerB");

  svc.RemovePeer(uri, "did:key:peerB");
  EXPECT_EQ(left_did, "did:key:peerB");
}

TEST(Sync_DiffReceivedEvent) {
  SyncService svcA, svcB;
  GraphStore storeB("g1", "G1");
  auto uri = svcA.ShareGraph("g1");
  svcB.JoinGraph(uri);

  bool diff_received = false;
  svcB.SetOnDiffReceived([&](const GraphDiff& diff) {
    diff_received = true;
    EXPECT_EQ(diff.additions.size(), 1u);
  });

  auto triple = MakeTriple("ex:a", "ex:p", "ex:b", "did:key:A");
  auto diff = svcA.CommitDiff(uri, {triple}, {}, "did:key:A");
  svcB.ReceiveDiff(uri, &storeB, diff);
  EXPECT_TRUE(diff_received);
}

TEST(Sync_ListSharedGraphs) {
  SyncService svc;
  svc.ShareGraph("g1", "Graph 1");
  svc.ShareGraph("g2", "Graph 2");
  auto list = svc.ListSharedGraphs();
  EXPECT_EQ(list.size(), 2u);
}

// ============================================================
// 6. GRAPH MANAGER TESTS
// ============================================================

TEST(GraphManager_CreateAndList) {
  GraphManager mgr;
  auto uuid1 = mgr.CreateGraph("Graph 1");
  auto uuid2 = mgr.CreateGraph("Graph 2");
  EXPECT_EQ(mgr.graph_count(), 2u);
  EXPECT_TRUE(mgr.GetStore(uuid1) != nullptr);
  EXPECT_TRUE(mgr.GetStore(uuid2) != nullptr);
}

TEST(GraphManager_Remove) {
  GraphManager mgr;
  auto uuid = mgr.CreateGraph("To Remove");
  EXPECT_TRUE(mgr.RemoveGraph(uuid));
  EXPECT_FALSE(mgr.RemoveGraph(uuid));
  EXPECT_TRUE(mgr.GetStore(uuid) == nullptr);
}

// ============================================================
// 7. PERMISSION SERVICE TESTS
// ============================================================

TEST(Permission_RequestAndCheck) {
  PermissionService svc;
  EXPECT_TRUE(svc.RequestPermission("https://example.com", "graph.read"));
  EXPECT_TRUE(svc.HasPermission("https://example.com", "graph.read"));
  EXPECT_FALSE(svc.HasPermission("https://example.com", "graph.write"));
}

TEST(Permission_Revoke) {
  PermissionService svc;
  svc.RequestPermission("https://example.com", "graph.read");
  svc.RevokePermission("https://example.com", "graph.read");
  EXPECT_FALSE(svc.HasPermission("https://example.com", "graph.read"));
}

// ============================================================
// 8. JSON PARSER TESTS
// ============================================================

TEST(Json_ParseSimple) {
  JsonObject obj;
  EXPECT_TRUE(JsonParser::Parse(R"({"name": "Alice", "age": "30"})", obj));
  std::string name;
  EXPECT_TRUE(obj.getString("name", name));
  EXPECT_EQ(name, "Alice");
}

TEST(Json_ParseArray) {
  auto items = JsonParser::ParseArray(R"([{"a":"1"},{"b":"2"}])");
  EXPECT_EQ(items.size(), 2u);
}

TEST(Json_ParseInvalid) {
  JsonObject obj;
  EXPECT_FALSE(JsonParser::Parse("not json", obj));
  EXPECT_FALSE(JsonParser::Parse("", obj));
}

// ============================================================
// 9. CRDT ENGINE TESTS
// ============================================================

TEST(CRDT_CreateDiff) {
  CRDTEngine crdt;
  auto triple = MakeTriple("ex:a", "ex:p", "ex:b");
  auto diff = crdt.CreateDiff({triple}, {}, "did:key:author");
  EXPECT_FALSE(diff.revision.empty());
  EXPECT_EQ(diff.additions.size(), 1u);
  EXPECT_EQ(diff.removals.size(), 0u);
}

TEST(CRDT_MergeDiff) {
  CRDTEngine crdtA, crdtB;
  auto triple = MakeTriple("ex:a", "ex:p", "ex:b");
  auto diff = crdtA.CreateDiff({triple}, {}, "did:key:A");
  crdtB.MergeDiff(diff);
  EXPECT_EQ(crdtA.current_revision(), crdtB.current_revision());
}

// ============================================================
// Main
// ============================================================

int main(int argc, char** argv) {
  std::cout << "Living Web — Test Suite\n";
  std::cout << "=======================\n\n";

  for (auto& entry : test_registry()) {
    tests_run++;
    std::cout << "  [RUN ] " << entry.name << std::flush;
    try {
      entry.fn();
      tests_passed++;
      std::cout << " [PASS]\n";
    } catch (const std::exception& e) {
      tests_failed++;
      failures.push_back(entry.name);
      std::cout << " [FAIL]\n";
    }
  }

  std::cout << "\n=======================\n";
  std::cout << "Tests run: " << tests_run
            << " | Passed: " << tests_passed
            << " | Failed: " << tests_failed << "\n";

  if (!failures.empty()) {
    std::cout << "\nFailed tests:\n";
    for (const auto& f : failures)
      std::cout << "  - " << f << "\n";
  }

  return tests_failed > 0 ? 1 : 0;
}
