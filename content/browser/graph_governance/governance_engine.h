// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GOVERNANCE_GOVERNANCE_ENGINE_H_
#define CONTENT_BROWSER_GRAPH_GOVERNANCE_GOVERNANCE_ENGINE_H_

#include <string>
#include <vector>
#include <optional>

#include "content/browser/graph/triple.h"
#include "content/browser/graph/graph_store.h"
#include "content/browser/did/did_key_provider.h"

namespace content {

// ValidationResult — outcome of governance validation.
struct ValidationResult {
  bool accepted = true;
  std::string rejecting_constraint_id;
  std::string rejecting_kind;  // "capability", "temporal", "content", "credential"
  std::string reason;
};

// Parsed constraint types.
struct CapabilityConstraintDef {
  std::string constraint_id;
  std::string enforcement;  // "required" or "optional"
  std::vector<std::string> predicates;
};

struct TemporalConstraintDef {
  std::string constraint_id;
  std::optional<uint32_t> min_interval_seconds;
  std::optional<uint32_t> max_count_per_window;
  uint32_t window_seconds = 60;
  std::vector<std::string> applies_to_predicates;
};

struct ContentConstraintDef {
  std::string constraint_id;
  std::vector<std::string> blocked_patterns;
  std::optional<uint32_t> max_text_length;
  std::optional<uint32_t> min_text_length;
  std::string url_policy;  // "allow_all", "block_all", "allowlist", "blocklist"
  std::vector<std::string> url_list;
  std::vector<std::string> allowed_media_types;
  std::vector<std::string> applies_to_predicates;
};

struct CredentialConstraintDef {
  std::string constraint_id;
  std::string required_credential_type;
  std::string issuer_pattern;
  uint32_t min_age_hours = 0;
};

// GovernanceEngine — evaluates governance constraints on shared graphs.
//
// Implements:
// - Scope resolution (walking entity hierarchy)
// - ZCAP verification (capability delegation chains)
// - Temporal verification (rate limiting)
// - Content verification (text length, blocked patterns, URL policy)
// - Credential verification (Verifiable Credentials)
//
// All algorithms follow the spec's Sections 5-8 exactly.
class GovernanceEngine {
 public:
  GovernanceEngine();
  ~GovernanceEngine();

  // Validate a triple against all constraints in scope.
  ValidationResult ValidateTriple(const GraphStore& graph,
                                   const SignedTriple& triple,
                                   const std::string& root_authority_did);

  // Query: can agent add triple with this predicate at this scope?
  ValidationResult CanAddTriple(const GraphStore& graph,
                                 const std::string& agent_did,
                                 const std::string& predicate,
                                 const std::string& scope_entity,
                                 const std::string& root_authority_did);

  // Query: what constraints apply at this scope?
  struct ConstraintsAtScope {
    std::vector<CapabilityConstraintDef> capabilities;
    std::vector<TemporalConstraintDef> temporals;
    std::vector<ContentConstraintDef> contents;
    std::vector<CredentialConstraintDef> credentials;
  };
  ConstraintsAtScope GetConstraintsFor(const GraphStore& graph,
                                        const std::string& scope_entity);

 private:
  // Section 5: Scope Resolution Algorithm.
  // Walk has_child relationships from entity up to graph root,
  // collecting constraints at each level.
  std::vector<std::string> ResolveScopeChain(
      const GraphStore& graph,
      const std::string& entity) const;

  // Collect all constraints bound to entities in the scope chain.
  // More-specific constraints of the same kind override less-specific.
  ConstraintsAtScope CollectConstraints(
      const GraphStore& graph,
      const std::vector<std::string>& scope_chain) const;

  // Section 6: ZCAP Verification.
  // Verify a capability delegation chain.
  bool VerifyZcap(const GraphStore& graph,
                   const std::string& agent_did,
                   const std::string& predicate,
                   const std::string& scope_entity,
                   const std::string& root_authority_did) const;

  // Section 7: Temporal Verification.
  // Check rate limits.
  ValidationResult CheckTemporalConstraint(
      const GraphStore& graph,
      const SignedTriple& triple,
      const TemporalConstraintDef& constraint) const;

  // Section 8: Content Verification.
  // Check content rules against triple target.
  ValidationResult CheckContentConstraint(
      const SignedTriple& triple,
      const ContentConstraintDef& constraint) const;

  // Credential verification.
  ValidationResult CheckCredentialConstraint(
      const GraphStore& graph,
      const std::string& agent_did,
      const CredentialConstraintDef& constraint) const;

  // Parse a constraint from graph triples.
  std::optional<CapabilityConstraintDef> ParseCapabilityConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;
  std::optional<TemporalConstraintDef> ParseTemporalConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;
  std::optional<ContentConstraintDef> ParseContentConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;
  std::optional<CredentialConstraintDef> ParseCredentialConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;

  // Helper: get triple target for a given source + predicate.
  std::optional<std::string> GetTripleTarget(
      const GraphStore& graph,
      const std::string& source,
      const std::string& predicate) const;

  // Helper: split comma-separated string.
  std::vector<std::string> SplitCSV(const std::string& csv) const;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GOVERNANCE_GOVERNANCE_ENGINE_H_
