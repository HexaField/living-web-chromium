// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GOVERNANCE_GOVERNANCE_ENGINE_H_
#define CONTENT_BROWSER_GRAPH_GOVERNANCE_GOVERNANCE_ENGINE_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "content/browser/graph/triple.h"
#include "content/browser/graph/graph_store.h"
#include "content/browser/did/did_key_provider.h"

namespace content {

// ValidationResult — outcome of governance validation.
struct ValidationResult {
  ValidationResult();
  ~ValidationResult();
  ValidationResult(const ValidationResult&);
  ValidationResult& operator=(const ValidationResult&);
  ValidationResult(ValidationResult&&);
  ValidationResult& operator=(ValidationResult&&);

  // Convenience constructor for inline creation.
  ValidationResult(bool accepted_val,
                   const std::string& constraint_id,
                   const std::string& kind,
                   const std::string& reason_val);

  bool accepted = true;
  std::string rejecting_constraint_id;
  std::string rejecting_kind;
  std::string reason;
};

// Parsed constraint types.
struct CapabilityConstraintDef {
  CapabilityConstraintDef();
  ~CapabilityConstraintDef();
  CapabilityConstraintDef(const CapabilityConstraintDef&);
  CapabilityConstraintDef& operator=(const CapabilityConstraintDef&);
  CapabilityConstraintDef(CapabilityConstraintDef&&);
  CapabilityConstraintDef& operator=(CapabilityConstraintDef&&);

  std::string constraint_id;
  std::string enforcement;
  std::vector<std::string> predicates;
};

struct TemporalConstraintDef {
  TemporalConstraintDef();
  ~TemporalConstraintDef();
  TemporalConstraintDef(const TemporalConstraintDef&);
  TemporalConstraintDef& operator=(const TemporalConstraintDef&);
  TemporalConstraintDef(TemporalConstraintDef&&);
  TemporalConstraintDef& operator=(TemporalConstraintDef&&);

  std::string constraint_id;
  std::optional<uint32_t> min_interval_seconds;
  std::optional<uint32_t> max_count_per_window;
  uint32_t window_seconds = 60;
  std::vector<std::string> applies_to_predicates;
};

struct ContentConstraintDef {
  ContentConstraintDef();
  ~ContentConstraintDef();
  ContentConstraintDef(const ContentConstraintDef&);
  ContentConstraintDef& operator=(const ContentConstraintDef&);
  ContentConstraintDef(ContentConstraintDef&&);
  ContentConstraintDef& operator=(ContentConstraintDef&&);

  std::string constraint_id;
  std::vector<std::string> blocked_patterns;
  std::optional<uint32_t> max_text_length;
  std::optional<uint32_t> min_text_length;
  std::string url_policy;
  std::vector<std::string> url_list;
  std::vector<std::string> allowed_media_types;
  std::vector<std::string> applies_to_predicates;
};

struct CredentialConstraintDef {
  CredentialConstraintDef();
  ~CredentialConstraintDef();
  CredentialConstraintDef(const CredentialConstraintDef&);
  CredentialConstraintDef& operator=(const CredentialConstraintDef&);
  CredentialConstraintDef(CredentialConstraintDef&&);
  CredentialConstraintDef& operator=(CredentialConstraintDef&&);

  std::string constraint_id;
  std::string required_credential_type;
  std::string issuer_pattern;
  uint32_t min_age_hours = 0;
};

// GovernanceEngine — evaluates governance constraints on shared graphs.
class GovernanceEngine {
 public:
  GovernanceEngine();
  ~GovernanceEngine();

  ValidationResult ValidateTriple(const GraphStore& graph,
                                   const SignedTriple& triple,
                                   const std::string& root_authority_did);
  ValidationResult CanAddTriple(const GraphStore& graph,
                                 const std::string& agent_did,
                                 const std::string& predicate,
                                 const std::string& scope_entity,
                                 const std::string& root_authority_did);

  struct ConstraintsAtScope {
    ConstraintsAtScope();
    ~ConstraintsAtScope();
    ConstraintsAtScope(const ConstraintsAtScope&);
    ConstraintsAtScope& operator=(const ConstraintsAtScope&);
    ConstraintsAtScope(ConstraintsAtScope&&);
    ConstraintsAtScope& operator=(ConstraintsAtScope&&);

    std::vector<CapabilityConstraintDef> capabilities;
    std::vector<TemporalConstraintDef> temporals;
    std::vector<ContentConstraintDef> contents;
    std::vector<CredentialConstraintDef> credentials;
  };
  ConstraintsAtScope GetConstraintsFor(const GraphStore& graph,
                                        const std::string& scope_entity);

 private:
  std::vector<std::string> ResolveScopeChain(
      const GraphStore& graph,
      const std::string& entity) const;
  ConstraintsAtScope CollectConstraints(
      const GraphStore& graph,
      const std::vector<std::string>& scope_chain) const;
  bool VerifyZcap(const GraphStore& graph,
                   const std::string& agent_did,
                   const std::string& predicate,
                   const std::string& scope_entity,
                   const std::string& root_authority_did) const;
  ValidationResult CheckTemporalConstraint(
      const GraphStore& graph,
      const SignedTriple& triple,
      const TemporalConstraintDef& constraint) const;
  ValidationResult CheckContentConstraint(
      const SignedTriple& triple,
      const ContentConstraintDef& constraint) const;
  ValidationResult CheckCredentialConstraint(
      const GraphStore& graph,
      const std::string& agent_did,
      const CredentialConstraintDef& constraint) const;
  std::optional<CapabilityConstraintDef> ParseCapabilityConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;
  std::optional<TemporalConstraintDef> ParseTemporalConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;
  std::optional<ContentConstraintDef> ParseContentConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;
  std::optional<CredentialConstraintDef> ParseCredentialConstraint(
      const GraphStore& graph, const std::string& constraint_id) const;
  std::optional<std::string> GetTripleTarget(
      const GraphStore& graph,
      const std::string& source,
      const std::string& predicate) const;
  std::vector<std::string> SplitCSV(const std::string& csv) const;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GOVERNANCE_GOVERNANCE_ENGINE_H_
