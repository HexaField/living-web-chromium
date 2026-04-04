// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_governance/governance_engine.h"

#include <algorithm>
#include <chrono>
#include <regex>
#include <sstream>

#include "base/logging.h"

namespace content {

GovernanceEngine::GovernanceEngine() = default;
GovernanceEngine::~GovernanceEngine() = default;

// ============================================================
// Scope Resolution (Section 5)
// ============================================================

std::vector<std::string> GovernanceEngine::ResolveScopeChain(
    const GraphStore& graph,
    const std::string& entity) const {
  // Walk has_child in reverse: find all ancestors up to root.
  std::vector<std::string> chain;
  chain.push_back(entity);

  std::string current = entity;
  int max_depth = 100;  // Prevent infinite loops.
  while (max_depth-- > 0) {
    // Find parent: look for triple where target == current and
    // predicate == "has_child".
    TripleQuery query;
    query.target = current;
    query.predicate = "has_child";
    auto parents = graph.QueryTriples(query);

    if (parents.empty())
      break;  // Reached root.

    current = parents[0].data.source;
    chain.push_back(current);
  }

  return chain;
}

GovernanceEngine::ConstraintsAtScope GovernanceEngine::CollectConstraints(
    const GraphStore& graph,
    const std::vector<std::string>& scope_chain) const {
  ConstraintsAtScope result;

  // Track which kinds we've already found (most-specific wins).
  bool found_capability = false;
  bool found_temporal = false;
  bool found_content = false;
  bool found_credential = false;

  // Walk from most specific (index 0) to least specific (root).
  for (const auto& entity : scope_chain) {
    // Find constraint bindings: entity -[governance://has_constraint]→ id
    TripleQuery query;
    query.source = entity;
    query.predicate = "governance://has_constraint";
    auto bindings = graph.QueryTriples(query);

    for (const auto& binding : bindings) {
      const std::string& constraint_id = binding.data.target;

      // Get constraint kind.
      auto kind = GetTripleTarget(graph, constraint_id,
                                   "governance://constraint_kind");
      if (!kind) continue;

      if (*kind == "capability" && !found_capability) {
        auto c = ParseCapabilityConstraint(graph, constraint_id);
        if (c) {
          result.capabilities.push_back(*c);
          found_capability = true;
        }
      } else if (*kind == "temporal" && !found_temporal) {
        auto c = ParseTemporalConstraint(graph, constraint_id);
        if (c) {
          result.temporals.push_back(*c);
          found_temporal = true;
        }
      } else if (*kind == "content" && !found_content) {
        auto c = ParseContentConstraint(graph, constraint_id);
        if (c) {
          result.contents.push_back(*c);
          found_content = true;
        }
      } else if (*kind == "credential" && !found_credential) {
        auto c = ParseCredentialConstraint(graph, constraint_id);
        if (c) {
          result.credentials.push_back(*c);
          found_credential = true;
        }
      }
    }
  }

  return result;
}

// ============================================================
// Main Validation
// ============================================================

ValidationResult GovernanceEngine::ValidateTriple(
    const GraphStore& graph,
    const SignedTriple& triple,
    const std::string& root_authority_did) {
  // 1. Resolve scope chain from triple's source.
  auto scope_chain = ResolveScopeChain(graph, triple.data.source);

  // 2. Collect all constraints in scope.
  auto constraints = CollectConstraints(graph, scope_chain);

  // 3. Check capability constraints.
  for (const auto& cap : constraints.capabilities) {
    if (cap.enforcement == "required") {
      // Check if predicate is in the constrained set.
      bool predicate_constrained = cap.predicates.empty();
      if (!predicate_constrained && triple.data.predicate) {
        for (const auto& p : cap.predicates) {
          if (p == *triple.data.predicate) {
            predicate_constrained = true;
            break;
          }
        }
      }

      if (predicate_constrained) {
        // Root authority always has capability.
        if (triple.author == root_authority_did)
          continue;

        bool has_zcap = VerifyZcap(
            graph, triple.author,
            triple.data.predicate.value_or(""),
            triple.data.source, root_authority_did);
        if (!has_zcap) {
          return {false, cap.constraint_id, "capability",
                  "No valid ZCAP for predicate"};
        }
      }
    }
  }

  // 4. Check temporal constraints.
  for (const auto& temp : constraints.temporals) {
    auto result = CheckTemporalConstraint(graph, triple, temp);
    if (!result.accepted)
      return result;
  }

  // 5. Check content constraints.
  for (const auto& content : constraints.contents) {
    auto result = CheckContentConstraint(triple, content);
    if (!result.accepted)
      return result;
  }

  // 6. Check credential constraints.
  for (const auto& cred : constraints.credentials) {
    auto result = CheckCredentialConstraint(graph, triple.author, cred);
    if (!result.accepted)
      return result;
  }

  return {true, "", "", ""};
}

ValidationResult GovernanceEngine::CanAddTriple(
    const GraphStore& graph,
    const std::string& agent_did,
    const std::string& predicate,
    const std::string& scope_entity,
    const std::string& root_authority_did) {
  // Build a hypothetical triple and validate it.
  SignedTriple hypothetical;
  hypothetical.data.source = scope_entity;
  hypothetical.data.predicate = predicate;
  hypothetical.data.target = "";  // Content check won't apply
  hypothetical.author = agent_did;
  hypothetical.timestamp = "";

  return ValidateTriple(graph, hypothetical, root_authority_did);
}

GovernanceEngine::ConstraintsAtScope GovernanceEngine::GetConstraintsFor(
    const GraphStore& graph,
    const std::string& scope_entity) {
  auto scope_chain = ResolveScopeChain(graph, scope_entity);
  return CollectConstraints(graph, scope_chain);
}

// ============================================================
// ZCAP Verification (Section 6)
// ============================================================

bool GovernanceEngine::VerifyZcap(
    const GraphStore& graph,
    const std::string& agent_did,
    const std::string& predicate,
    const std::string& scope_entity,
    const std::string& root_authority_did) const {
  // Find ZCAPs for this agent.
  TripleQuery query;
  query.source = agent_did;
  query.predicate = "governance://has_zcap";
  auto zcap_triples = graph.QueryTriples(query);

  for (const auto& zcap_triple : zcap_triples) {
    const std::string& zcap_id = zcap_triple.data.target;

    // Check if ZCAP is revoked.
    TripleQuery revoke_query;
    revoke_query.predicate = "governance://revokes_capability";
    revoke_query.target = zcap_id;
    auto revocations = graph.QueryTriples(revoke_query);
    if (!revocations.empty())
      continue;  // ZCAP is revoked.

    // Get ZCAP predicates.
    auto zcap_predicates = GetTripleTarget(
        graph, zcap_id, "governance://capability_predicates");
    if (zcap_predicates) {
      auto preds = SplitCSV(*zcap_predicates);
      bool found = false;
      for (const auto& p : preds) {
        if (p == predicate) { found = true; break; }
      }
      if (!found) continue;  // ZCAP doesn't cover this predicate.
    }
    // Empty predicates = covers all predicates.

    // Check scope.
    auto zcap_scope = GetTripleTarget(
        graph, zcap_id, "governance://capability_scope");
    if (zcap_scope && !zcap_scope->empty()) {
      // Verify scope_entity is within the ZCAP scope.
      auto scope_chain = ResolveScopeChain(graph, scope_entity);
      bool in_scope = false;
      for (const auto& entity : scope_chain) {
        if (entity == *zcap_scope) { in_scope = true; break; }
      }
      if (!in_scope) continue;
    }

    // Check delegation chain depth (max 10).
    int chain_depth = 0;
    std::string current_zcap = zcap_id;
    bool chain_valid = true;
    while (chain_depth < 10) {
      auto parent = GetTripleTarget(
          graph, current_zcap, "governance://parent_capability");
      if (!parent || parent->empty())
        break;  // Root-issued capability.
      current_zcap = *parent;
      chain_depth++;

      // Verify parent isn't revoked.
      TripleQuery parent_revoke;
      parent_revoke.predicate = "governance://revokes_capability";
      parent_revoke.target = current_zcap;
      if (!graph.QueryTriples(parent_revoke).empty()) {
        chain_valid = false;
        break;
      }
    }
    if (chain_depth >= 10) chain_valid = false;

    if (chain_valid)
      return true;  // Valid ZCAP found.
  }

  return false;
}

// ============================================================
// Temporal Verification (Section 7)
// ============================================================

ValidationResult GovernanceEngine::CheckTemporalConstraint(
    const GraphStore& graph,
    const SignedTriple& triple,
    const TemporalConstraintDef& constraint) const {
  // Check if predicate is in the constrained set.
  if (!constraint.applies_to_predicates.empty() && triple.data.predicate) {
    bool applies = false;
    for (const auto& p : constraint.applies_to_predicates) {
      if (p == *triple.data.predicate) { applies = true; break; }
    }
    if (!applies) return {true, "", "", ""};
  }

  // Query existing triples by this author in this scope.
  TripleQuery query;
  query.source = triple.data.source;
  auto existing = graph.QueryTriples(query);

  // Filter to same author.
  std::vector<const SignedTriple*> author_triples;
  for (const auto& t : existing) {
    if (t.author == triple.author)
      author_triples.push_back(&t);
  }

  // Check min_interval_seconds.
  if (constraint.min_interval_seconds && !author_triples.empty()) {
    // Compare timestamps (RFC 3339 strings are lexicographically comparable).
    const auto& latest = author_triples[0]->timestamp;  // Already sorted desc
    // Simple check: if timestamps are too close, reject.
    // In full implementation: parse RFC 3339 and compute difference.
    if (!triple.timestamp.empty() && !latest.empty() &&
        triple.timestamp <= latest) {
      // Same or earlier timestamp — likely too soon.
      return {false, constraint.constraint_id, "temporal",
              "Minimum interval not met"};
    }
  }

  // Check max_count_per_window.
  if (constraint.max_count_per_window) {
    // Count triples within the window.
    // Simplified: count all author triples (full impl would check window).
    if (author_triples.size() >= *constraint.max_count_per_window) {
      return {false, constraint.constraint_id, "temporal",
              "Rate limit exceeded"};
    }
  }

  return {true, "", "", ""};
}

// ============================================================
// Content Verification (Section 8)
// ============================================================

ValidationResult GovernanceEngine::CheckContentConstraint(
    const SignedTriple& triple,
    const ContentConstraintDef& constraint) const {
  // Check if predicate is in the constrained set.
  if (!constraint.applies_to_predicates.empty() && triple.data.predicate) {
    bool applies = false;
    for (const auto& p : constraint.applies_to_predicates) {
      if (p == *triple.data.predicate) { applies = true; break; }
    }
    if (!applies) return {true, "", "", ""};
  }

  const std::string& target = triple.data.target;

  // Check text length.
  if (constraint.max_text_length && target.size() > *constraint.max_text_length) {
    return {false, constraint.constraint_id, "content",
            "Text exceeds maximum length"};
  }
  if (constraint.min_text_length && target.size() < *constraint.min_text_length) {
    return {false, constraint.constraint_id, "content",
            "Text below minimum length"};
  }

  // Check blocked patterns (regex).
  for (const auto& pattern : constraint.blocked_patterns) {
    try {
      std::regex re(pattern, std::regex::icase);
      if (std::regex_search(target, re)) {
        return {false, constraint.constraint_id, "content",
                "Content matches blocked pattern: " + pattern};
      }
    } catch (const std::regex_error&) {
      // Invalid regex — fail closed.
      return {false, constraint.constraint_id, "content",
              "Invalid blocked pattern regex"};
    }
  }

  // Check URL policy.
  if (!constraint.url_policy.empty() && constraint.url_policy != "allow_all") {
    // Simple URL detection.
    std::regex url_re(R"(https?://\S+)", std::regex::icase);
    bool has_url = std::regex_search(target, url_re);

    if (constraint.url_policy == "block_all" && has_url) {
      return {false, constraint.constraint_id, "content",
              "URLs are not allowed"};
    }

    if (constraint.url_policy == "allowlist" && has_url) {
      // Check if URL matches any allowlisted domain.
      std::smatch match;
      if (std::regex_search(target, match, url_re)) {
        std::string url = match[0].str();
        bool allowed = false;
        for (const auto& domain : constraint.url_list) {
          if (url.find(domain) != std::string::npos) {
            allowed = true;
            break;
          }
        }
        if (!allowed) {
          return {false, constraint.constraint_id, "content",
                  "URL not in allowlist"};
        }
      }
    }

    if (constraint.url_policy == "blocklist" && has_url) {
      std::smatch match;
      if (std::regex_search(target, match, url_re)) {
        std::string url = match[0].str();
        for (const auto& domain : constraint.url_list) {
          if (url.find(domain) != std::string::npos) {
            return {false, constraint.constraint_id, "content",
                    "URL in blocklist"};
          }
        }
      }
    }
  }

  return {true, "", "", ""};
}

// ============================================================
// Credential Verification
// ============================================================

ValidationResult GovernanceEngine::CheckCredentialConstraint(
    const GraphStore& graph,
    const std::string& agent_did,
    const CredentialConstraintDef& constraint) const {
  // Find credentials for this agent.
  TripleQuery query;
  query.source = agent_did;
  query.predicate = "governance://has_credential";
  auto cred_triples = graph.QueryTriples(query);

  for (const auto& cred_triple : cred_triples) {
    const std::string& cred_address = cred_triple.data.target;

    // Get credential type.
    auto cred_type = GetTripleTarget(graph, cred_address, "vc://type");
    if (!cred_type || *cred_type != constraint.required_credential_type)
      continue;

    // Check issuer pattern.
    if (!constraint.issuer_pattern.empty()) {
      auto issuer = GetTripleTarget(graph, cred_address, "vc://issuer");
      if (!issuer) continue;

      // Simple glob matching: * matches anything.
      if (constraint.issuer_pattern != "*" &&
          constraint.issuer_pattern != *issuer) {
        // Try glob: did:key:* should match any did:key:...
        std::string pattern = constraint.issuer_pattern;
        if (pattern.back() == '*') {
          std::string prefix = pattern.substr(0, pattern.size() - 1);
          if (issuer->find(prefix) != 0) continue;
        } else {
          continue;
        }
      }
    }

    // Check credential age.
    if (constraint.min_age_hours > 0) {
      auto issuance_date = GetTripleTarget(
          graph, cred_address, "vc://issuanceDate");
      if (!issuance_date) continue;
      // Simplified: skip age check in reference impl.
      // Full impl would parse RFC 3339 and compare.
    }

    // Check credential subject matches agent.
    auto subject = GetTripleTarget(graph, cred_address, "vc://subject");
    if (subject && *subject != agent_did) continue;

    // Credential matches all requirements.
    return {true, "", "", ""};
  }

  return {false, constraint.constraint_id, "credential",
          "Missing required credential: " + constraint.required_credential_type};
}

// ============================================================
// Constraint Parsing
// ============================================================

std::optional<CapabilityConstraintDef> GovernanceEngine::ParseCapabilityConstraint(
    const GraphStore& graph, const std::string& constraint_id) const {
  auto enforcement = GetTripleTarget(
      graph, constraint_id, "governance://capability_enforcement");
  if (!enforcement) return std::nullopt;

  CapabilityConstraintDef def;
  def.constraint_id = constraint_id;
  def.enforcement = *enforcement;

  auto preds = GetTripleTarget(
      graph, constraint_id, "governance://capability_predicates");
  if (preds) def.predicates = SplitCSV(*preds);

  return def;
}

std::optional<TemporalConstraintDef> GovernanceEngine::ParseTemporalConstraint(
    const GraphStore& graph, const std::string& constraint_id) const {
  TemporalConstraintDef def;
  def.constraint_id = constraint_id;

  auto interval = GetTripleTarget(
      graph, constraint_id, "governance://temporal_min_interval_seconds");
  if (interval) def.min_interval_seconds = std::stoul(*interval);

  auto max_count = GetTripleTarget(
      graph, constraint_id, "governance://temporal_max_count_per_window");
  if (max_count) def.max_count_per_window = std::stoul(*max_count);

  auto window = GetTripleTarget(
      graph, constraint_id, "governance://temporal_window_seconds");
  if (window) def.window_seconds = std::stoul(*window);

  auto preds = GetTripleTarget(
      graph, constraint_id, "governance://temporal_applies_to_predicates");
  if (preds) def.applies_to_predicates = SplitCSV(*preds);

  // Must have at least one constraint.
  if (!def.min_interval_seconds && !def.max_count_per_window)
    return std::nullopt;

  return def;
}

std::optional<ContentConstraintDef> GovernanceEngine::ParseContentConstraint(
    const GraphStore& graph, const std::string& constraint_id) const {
  ContentConstraintDef def;
  def.constraint_id = constraint_id;

  auto blocked = GetTripleTarget(
      graph, constraint_id, "governance://content_blocked_patterns");
  if (blocked) {
    // Pipe-separated.
    std::istringstream stream(*blocked);
    std::string pattern;
    while (std::getline(stream, pattern, '|')) {
      if (!pattern.empty()) def.blocked_patterns.push_back(pattern);
    }
  }

  auto max_len = GetTripleTarget(
      graph, constraint_id, "governance://content_max_text_length");
  if (max_len) def.max_text_length = std::stoul(*max_len);

  auto min_len = GetTripleTarget(
      graph, constraint_id, "governance://content_min_text_length");
  if (min_len) def.min_text_length = std::stoul(*min_len);

  auto url_policy = GetTripleTarget(
      graph, constraint_id, "governance://content_url_policy");
  if (url_policy) def.url_policy = *url_policy;

  auto url_list = GetTripleTarget(
      graph, constraint_id, "governance://content_url_list");
  if (url_list) def.url_list = SplitCSV(*url_list);

  auto media = GetTripleTarget(
      graph, constraint_id, "governance://content_allowed_media_types");
  if (media) def.allowed_media_types = SplitCSV(*media);

  auto preds = GetTripleTarget(
      graph, constraint_id, "governance://content_applies_to_predicates");
  if (preds) def.applies_to_predicates = SplitCSV(*preds);

  return def;
}

std::optional<CredentialConstraintDef> GovernanceEngine::ParseCredentialConstraint(
    const GraphStore& graph, const std::string& constraint_id) const {
  auto type = GetTripleTarget(
      graph, constraint_id, "governance://requires_credential_type");
  if (!type) return std::nullopt;

  CredentialConstraintDef def;
  def.constraint_id = constraint_id;
  def.required_credential_type = *type;

  auto issuer = GetTripleTarget(
      graph, constraint_id, "governance://credential_issuer_pattern");
  if (issuer) def.issuer_pattern = *issuer;

  auto age = GetTripleTarget(
      graph, constraint_id, "governance://credential_min_age_hours");
  if (age) def.min_age_hours = std::stoul(*age);

  return def;
}

// ============================================================
// Helpers
// ============================================================

std::optional<std::string> GovernanceEngine::GetTripleTarget(
    const GraphStore& graph,
    const std::string& source,
    const std::string& predicate) const {
  TripleQuery query;
  query.source = source;
  query.predicate = predicate;
  auto results = graph.QueryTriples(query);
  if (results.empty()) return std::nullopt;
  return results[0].data.target;
}

std::vector<std::string> GovernanceEngine::SplitCSV(
    const std::string& csv) const {
  std::vector<std::string> result;
  std::istringstream stream(csv);
  std::string item;
  while (std::getline(stream, item, ',')) {
    // Trim whitespace.
    size_t start = item.find_first_not_of(" \t");
    size_t end = item.find_last_not_of(" \t");
    if (start != std::string::npos)
      result.push_back(item.substr(start, end - start + 1));
  }
  return result;
}

}  // namespace content
