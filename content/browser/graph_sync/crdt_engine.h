// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_CRDT_ENGINE_H_
#define CONTENT_BROWSER_GRAPH_SYNC_CRDT_ENGINE_H_

#include <string>
#include <unordered_set>
#include <vector>

#include "content/browser/graph/triple.h"

namespace content {

// GraphDiff — a unit of change for sync.
struct GraphDiff {
  std::string revision;
  std::vector<SignedTriple> additions;
  std::vector<SignedTriple> removals;
  std::vector<std::string> dependencies;
  std::string author;
  double timestamp = 0;
};

// CRDTEngine — OR-Set (Observed-Remove Set) CRDT for triples.
//
// Provides deterministic merge semantics: all peers converge to
// the same state given the same set of diffs, regardless of
// application order.
//
// In the full implementation, this would be a Rust crate
// (third_party/living_web_crdt/) accessed via FFI.
class CRDTEngine {
 public:
  CRDTEngine();
  ~CRDTEngine();

  // Merge a remote diff into local state.
  // Returns the set of triples that changed (added or removed).
  GraphDiff MergeDiff(const GraphDiff& remote_diff);

  // Create a diff from local changes.
  GraphDiff CreateDiff(const std::vector<SignedTriple>& additions,
                       const std::vector<SignedTriple>& removals,
                       const std::string& author);

  // Compute the revision hash for a diff.
  std::string ComputeRevision(const GraphDiff& diff) const;

  // Get the current revision.
  const std::string& current_revision() const { return current_revision_; }

  // Get all triples in the CRDT state.
  const std::unordered_set<std::string>& triple_hashes() const {
    return triple_hashes_;
  }

 private:
  std::string HashTriple(const SignedTriple& triple) const;

  std::string current_revision_;
  std::unordered_set<std::string> triple_hashes_;  // For dedup
  std::vector<std::string> revision_dag_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_CRDT_ENGINE_H_
