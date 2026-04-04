// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_TRIPLE_H_
#define CONTENT_BROWSER_GRAPH_TRIPLE_H_

#include <string>
#include <optional>

namespace content {

// SemanticTriple — a single assertion in a graph.
struct SemanticTriple {
  std::string source;
  std::string target;
  std::optional<std::string> predicate;

  bool Matches(const std::optional<std::string>& q_source,
               const std::optional<std::string>& q_target,
               const std::optional<std::string>& q_predicate) const {
    if (q_source && *q_source != source) return false;
    if (q_target && *q_target != target) return false;
    if (q_predicate && predicate != q_predicate) return false;
    return true;
  }

  bool operator==(const SemanticTriple& other) const {
    return source == other.source && target == other.target &&
           predicate == other.predicate;
  }
};

// ContentProof — cryptographic proof.
struct ContentProof {
  std::string key;        // DID URI of signing key
  std::string signature;  // hex-encoded Ed25519 signature
};

// SignedTriple — a SemanticTriple with provenance.
struct SignedTriple {
  SemanticTriple data;
  std::string author;     // DID URI
  std::string timestamp;  // RFC 3339
  ContentProof proof;

  bool operator==(const SignedTriple& other) const {
    return data == other.data && author == other.author &&
           timestamp == other.timestamp;
  }
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_TRIPLE_H_
