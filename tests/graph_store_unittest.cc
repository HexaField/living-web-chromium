// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for GraphStore — in-memory triple store.

#include "content/browser/graph/graph_store.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

SignedTriple MakeTriple(const std::string& source,
                        const std::string& predicate,
                        const std::string& target,
                        const std::string& author = "did:key:test",
                        const std::string& timestamp = "2026-01-01T00:00:00Z") {
  SignedTriple t;
  t.data.source = source;
  t.data.predicate = predicate;
  t.data.target = target;
  t.author = author;
  t.timestamp = timestamp;
  t.proof.key = author;
  t.proof.signature = "deadbeef";
  return t;
}

TEST(GraphStoreTest, CreateAndRetrieve) {
  GraphStore store("test-uuid", "Test Graph");
  EXPECT_EQ(store.uuid(), "test-uuid");
  EXPECT_EQ(store.name(), "Test Graph");
  EXPECT_EQ(store.size(), 0u);
}

TEST(GraphStoreTest, AddTriple) {
  GraphStore store("test-uuid", "Test");
  auto triple = MakeTriple("ex:alice", "foaf:knows", "ex:bob");
  EXPECT_TRUE(store.AddTriple(triple));
  EXPECT_EQ(store.size(), 1u);
}

TEST(GraphStoreTest, AddDuplicate) {
  GraphStore store("test-uuid", "Test");
  auto triple = MakeTriple("ex:alice", "foaf:knows", "ex:bob");
  EXPECT_TRUE(store.AddTriple(triple));
  EXPECT_FALSE(store.AddTriple(triple));  // Duplicate
  EXPECT_EQ(store.size(), 1u);
}

TEST(GraphStoreTest, RemoveTriple) {
  GraphStore store("test-uuid", "Test");
  auto triple = MakeTriple("ex:alice", "foaf:knows", "ex:bob");
  store.AddTriple(triple);
  EXPECT_TRUE(store.RemoveTriple(triple));
  EXPECT_EQ(store.size(), 0u);
  EXPECT_FALSE(store.RemoveTriple(triple));  // Already removed
}

TEST(GraphStoreTest, QueryBySource) {
  GraphStore store("test-uuid", "Test");
  store.AddTriple(MakeTriple("ex:alice", "foaf:knows", "ex:bob"));
  store.AddTriple(MakeTriple("ex:alice", "foaf:name", "Alice"));
  store.AddTriple(MakeTriple("ex:bob", "foaf:name", "Bob"));

  TripleQuery query;
  query.source = "ex:alice";
  auto results = store.QueryTriples(query);
  EXPECT_EQ(results.size(), 2u);
}

TEST(GraphStoreTest, QueryByPredicate) {
  GraphStore store("test-uuid", "Test");
  store.AddTriple(MakeTriple("ex:alice", "foaf:knows", "ex:bob"));
  store.AddTriple(MakeTriple("ex:alice", "foaf:name", "Alice"));

  TripleQuery query;
  query.predicate = "foaf:knows";
  auto results = store.QueryTriples(query);
  EXPECT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].data.target, "ex:bob");
}

TEST(GraphStoreTest, QueryWithLimit) {
  GraphStore store("test-uuid", "Test");
  for (int i = 0; i < 10; i++) {
    store.AddTriple(MakeTriple("ex:alice", "ex:item",
                                "ex:item" + std::to_string(i),
                                "did:key:test",
                                "2026-01-0" + std::to_string(i + 1) +
                                "T00:00:00Z"));
  }

  TripleQuery query;
  query.source = "ex:alice";
  query.limit = 5;
  auto results = store.QueryTriples(query);
  EXPECT_EQ(results.size(), 5u);
}

TEST(GraphStoreTest, QueryTemporalRange) {
  GraphStore store("test-uuid", "Test");
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:b", "did:key:test",
                              "2026-01-01T00:00:00Z"));
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:c", "did:key:test",
                              "2026-06-01T00:00:00Z"));
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:d", "did:key:test",
                              "2026-12-01T00:00:00Z"));

  TripleQuery query;
  query.source = "ex:a";
  query.from_date = "2026-03-01T00:00:00Z";
  query.until_date = "2026-09-01T00:00:00Z";
  auto results = store.QueryTriples(query);
  EXPECT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].data.target, "ex:c");
}

TEST(GraphStoreTest, Snapshot) {
  GraphStore store("test-uuid", "Test");
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:b", "did:key:test",
                              "2026-02-01T00:00:00Z"));
  store.AddTriple(MakeTriple("ex:a", "ex:p", "ex:c", "did:key:test",
                              "2026-01-01T00:00:00Z"));

  auto snapshot = store.Snapshot();
  EXPECT_EQ(snapshot.size(), 2u);
  // Should be sorted ascending by timestamp.
  EXPECT_EQ(snapshot[0].timestamp, "2026-01-01T00:00:00Z");
  EXPECT_EQ(snapshot[1].timestamp, "2026-02-01T00:00:00Z");
}

TEST(GraphStoreTest, AddTriplesBatch) {
  GraphStore store("test-uuid", "Test");
  std::vector<SignedTriple> batch = {
    MakeTriple("ex:a", "ex:p", "ex:b"),
    MakeTriple("ex:a", "ex:p", "ex:c"),
  };
  EXPECT_TRUE(store.AddTriples(batch));
  EXPECT_EQ(store.size(), 2u);
}

TEST(GraphStoreTest, AddTriplesBatchAtomicFailure) {
  GraphStore store("test-uuid", "Test");
  auto existing = MakeTriple("ex:a", "ex:p", "ex:b");
  store.AddTriple(existing);

  std::vector<SignedTriple> batch = {
    MakeTriple("ex:a", "ex:p", "ex:c"),
    existing,  // Duplicate — should fail entire batch
  };
  EXPECT_FALSE(store.AddTriples(batch));
  EXPECT_EQ(store.size(), 1u);  // Only the original triple
}

TEST(GraphStoreTest, BasicSparql) {
  GraphStore store("test-uuid", "Test");
  store.AddTriple(MakeTriple("ex:alice", "foaf:knows", "ex:bob"));
  store.AddTriple(MakeTriple("ex:alice", "foaf:name", "Alice"));

  auto result = store.QuerySparql(
      "SELECT ?name WHERE { <ex:alice> <foaf:name> ?name }");
  EXPECT_NE(result.find("Alice"), std::string::npos);
}

TEST(GraphStoreTest, ShapeAddAndQuery) {
  GraphStore store("test-uuid", "Test");

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

  std::string instance_uri = store.CreateShapeInstance(
      "Task", R"({"title": "My Task"})");
  EXPECT_FALSE(instance_uri.empty());

  auto instances = store.GetShapeInstances("Task");
  EXPECT_EQ(instances.size(), 1u);
  EXPECT_EQ(instances[0], instance_uri);
}

}  // namespace
}  // namespace content
