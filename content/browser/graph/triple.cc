// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/triple.h"

namespace content {

// SemanticTriple
SemanticTriple::SemanticTriple() = default;
SemanticTriple::~SemanticTriple() = default;
SemanticTriple::SemanticTriple(const SemanticTriple&) = default;
SemanticTriple& SemanticTriple::operator=(const SemanticTriple&) = default;
SemanticTriple::SemanticTriple(SemanticTriple&&) = default;
SemanticTriple& SemanticTriple::operator=(SemanticTriple&&) = default;

bool SemanticTriple::Matches(const std::optional<std::string>& q_source,
                             const std::optional<std::string>& q_target,
                             const std::optional<std::string>& q_predicate) const {
  if (q_source && *q_source != source) return false;
  if (q_target && *q_target != target) return false;
  if (q_predicate && predicate != q_predicate) return false;
  return true;
}

bool SemanticTriple::operator==(const SemanticTriple& other) const {
  return source == other.source && target == other.target &&
         predicate == other.predicate;
}

// ContentProof
ContentProof::ContentProof() = default;
ContentProof::~ContentProof() = default;
ContentProof::ContentProof(const ContentProof&) = default;
ContentProof& ContentProof::operator=(const ContentProof&) = default;
ContentProof::ContentProof(ContentProof&&) = default;
ContentProof& ContentProof::operator=(ContentProof&&) = default;

// SignedTriple
SignedTriple::SignedTriple() = default;
SignedTriple::~SignedTriple() = default;
SignedTriple::SignedTriple(const SignedTriple&) = default;
SignedTriple& SignedTriple::operator=(const SignedTriple&) = default;
SignedTriple::SignedTriple(SignedTriple&&) = default;
SignedTriple& SignedTriple::operator=(SignedTriple&&) = default;

bool SignedTriple::operator==(const SignedTriple& other) const {
  return data == other.data && author == other.author &&
         timestamp == other.timestamp;
}

}  // namespace content
