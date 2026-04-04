// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_TRIPLE_H_
#define CONTENT_BROWSER_GRAPH_TRIPLE_H_

#include <optional>
#include <string>

namespace content {

// SemanticTriple — a single assertion in a graph.
struct SemanticTriple {
  SemanticTriple();
  ~SemanticTriple();
  SemanticTriple(const SemanticTriple&);
  SemanticTriple& operator=(const SemanticTriple&);
  SemanticTriple(SemanticTriple&&);
  SemanticTriple& operator=(SemanticTriple&&);

  std::string source;
  std::string target;
  std::optional<std::string> predicate;

  bool Matches(const std::optional<std::string>& q_source,
               const std::optional<std::string>& q_target,
               const std::optional<std::string>& q_predicate) const;

  bool operator==(const SemanticTriple& other) const;
};

// ContentProof — cryptographic proof.
struct ContentProof {
  ContentProof();
  ~ContentProof();
  ContentProof(const ContentProof&);
  ContentProof& operator=(const ContentProof&);
  ContentProof(ContentProof&&);
  ContentProof& operator=(ContentProof&&);

  std::string key;        // DID URI of signing key
  std::string signature;  // hex-encoded Ed25519 signature
};

// SignedTriple — a SemanticTriple with provenance.
struct SignedTriple {
  SignedTriple();
  ~SignedTriple();
  SignedTriple(const SignedTriple&);
  SignedTriple& operator=(const SignedTriple&);
  SignedTriple(SignedTriple&&);
  SignedTriple& operator=(SignedTriple&&);

  SemanticTriple data;
  std::string author;     // DID URI
  std::string timestamp;  // RFC 3339
  ContentProof proof;

  bool operator==(const SignedTriple& other) const;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_TRIPLE_H_
