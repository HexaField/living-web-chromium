// Governance Engine - standalone implementation
#ifndef LIVING_WEB_GOVERNANCE_ENGINE_H_
#define LIVING_WEB_GOVERNANCE_ENGINE_H_

#include "types.h"
#include "graph_store.h"
#include <regex>
#include <sstream>

namespace living_web {

class GovernanceEngine {
 public:
  GovernanceEngine() = default;
  ~GovernanceEngine() = default;

  // Section 5: Scope Resolution
  std::vector<std::string> ResolveScopeChain(const GraphStore& graph,
                                              const std::string& entity) const {
    std::vector<std::string> chain;
    chain.push_back(entity);
    std::string current = entity;
    int max_depth = 100;
    while (max_depth-- > 0) {
      TripleQuery query;
      query.target = current;
      query.predicate = "has_child";
      auto parents = graph.QueryTriples(query);
      if (parents.empty()) break;
      current = parents[0].data.source;
      chain.push_back(current);
    }
    return chain;
  }

  ConstraintsAtScope CollectConstraints(const GraphStore& graph,
                                         const std::vector<std::string>& scope_chain) const {
    ConstraintsAtScope result;
    bool found_capability = false, found_temporal = false;
    bool found_content = false, found_credential = false;

    for (const auto& entity : scope_chain) {
      TripleQuery query;
      query.source = entity;
      query.predicate = "governance://has_constraint";
      auto bindings = graph.QueryTriples(query);

      for (const auto& binding : bindings) {
        const std::string& constraint_id = binding.data.target;
        auto kind = GetTripleTarget(graph, constraint_id, "governance://constraint_kind");
        if (!kind) continue;

        if (*kind == "capability" && !found_capability) {
          auto c = ParseCapabilityConstraint(graph, constraint_id);
          if (c) { result.capabilities.push_back(*c); found_capability = true; }
        } else if (*kind == "temporal" && !found_temporal) {
          auto c = ParseTemporalConstraint(graph, constraint_id);
          if (c) { result.temporals.push_back(*c); found_temporal = true; }
        } else if (*kind == "content" && !found_content) {
          auto c = ParseContentConstraint(graph, constraint_id);
          if (c) { result.contents.push_back(*c); found_content = true; }
        } else if (*kind == "credential" && !found_credential) {
          auto c = ParseCredentialConstraint(graph, constraint_id);
          if (c) { result.credentials.push_back(*c); found_credential = true; }
        }
      }
    }
    return result;
  }

  ValidationResult ValidateTriple(const GraphStore& graph,
                                   const SignedTriple& triple,
                                   const std::string& root_authority_did) {
    auto scope_chain = ResolveScopeChain(graph, triple.data.source);
    auto constraints = CollectConstraints(graph, scope_chain);

    // Check capabilities
    for (const auto& cap : constraints.capabilities) {
      if (cap.enforcement == "required") {
        bool predicate_constrained = cap.predicates.empty();
        if (!predicate_constrained && triple.data.predicate) {
          for (const auto& p : cap.predicates) {
            if (p == *triple.data.predicate) { predicate_constrained = true; break; }
          }
        }
        if (predicate_constrained) {
          if (triple.author == root_authority_did) continue;
          bool has_zcap = VerifyZcap(graph, triple.author,
                                      triple.data.predicate.value_or(""),
                                      triple.data.source, root_authority_did);
          if (!has_zcap)
            return {false, cap.constraint_id, "capability", "No valid ZCAP for predicate"};
        }
      }
    }

    // Check temporal
    for (const auto& temp : constraints.temporals) {
      auto result = CheckTemporalConstraint(graph, triple, temp);
      if (!result.accepted) return result;
    }

    // Check content
    for (const auto& content : constraints.contents) {
      auto result = CheckContentConstraint(triple, content);
      if (!result.accepted) return result;
    }

    // Check credentials
    for (const auto& cred : constraints.credentials) {
      auto result = CheckCredentialConstraint(graph, triple.author, cred);
      if (!result.accepted) return result;
    }

    return {true, "", "", ""};
  }

  ValidationResult CanAddTriple(const GraphStore& graph,
                                 const std::string& agent_did,
                                 const std::string& predicate,
                                 const std::string& scope_entity,
                                 const std::string& root_authority_did) {
    SignedTriple hypothetical;
    hypothetical.data.source = scope_entity;
    hypothetical.data.predicate = predicate;
    hypothetical.data.target = "";
    hypothetical.author = agent_did;
    hypothetical.timestamp = "";
    return ValidateTriple(graph, hypothetical, root_authority_did);
  }

  ConstraintsAtScope GetConstraintsFor(const GraphStore& graph,
                                        const std::string& scope_entity) {
    auto scope_chain = ResolveScopeChain(graph, scope_entity);
    return CollectConstraints(graph, scope_chain);
  }

 private:
  bool VerifyZcap(const GraphStore& graph, const std::string& agent_did,
                   const std::string& predicate, const std::string& scope_entity,
                   const std::string& root_authority_did) const {
    TripleQuery query;
    query.source = agent_did;
    query.predicate = "governance://has_zcap";
    auto zcap_triples = graph.QueryTriples(query);

    for (const auto& zcap_triple : zcap_triples) {
      const std::string& zcap_id = zcap_triple.data.target;

      // Check revocation
      TripleQuery revoke_query;
      revoke_query.predicate = "governance://revokes_capability";
      revoke_query.target = zcap_id;
      if (!graph.QueryTriples(revoke_query).empty()) continue;

      // Check predicates
      auto zcap_predicates = GetTripleTarget(graph, zcap_id, "governance://capability_predicates");
      if (zcap_predicates) {
        auto preds = SplitCSV(*zcap_predicates);
        bool found = false;
        for (const auto& p : preds) {
          if (p == predicate) { found = true; break; }
        }
        if (!found) continue;
      }

      // Check scope
      auto zcap_scope = GetTripleTarget(graph, zcap_id, "governance://capability_scope");
      if (zcap_scope && !zcap_scope->empty()) {
        auto scope_chain = ResolveScopeChain(graph, scope_entity);
        bool in_scope = false;
        for (const auto& e : scope_chain) {
          if (e == *zcap_scope) { in_scope = true; break; }
        }
        if (!in_scope) continue;
      }

      // Check expiry
      auto expires = GetTripleTarget(graph, zcap_id, "governance://capability_expires");
      if (expires && !expires->empty()) {
        // Get current time as RFC 3339 for comparison
        auto now = std::time(nullptr);
        auto* tm = std::gmtime(&now);
        std::ostringstream ss;
        ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
        std::string now_str = ss.str();
        if (now_str > *expires) continue;  // Expired
      }

      // Check delegation chain (max 10)
      int chain_depth = 0;
      std::string current_zcap = zcap_id;
      bool chain_valid = true;
      while (chain_depth < 10) {
        auto parent = GetTripleTarget(graph, current_zcap, "governance://parent_capability");
        if (!parent || parent->empty()) break;
        current_zcap = *parent;
        chain_depth++;
        TripleQuery parent_revoke;
        parent_revoke.predicate = "governance://revokes_capability";
        parent_revoke.target = current_zcap;
        if (!graph.QueryTriples(parent_revoke).empty()) {
          chain_valid = false; break;
        }
      }
      if (chain_depth >= 10) chain_valid = false;
      if (chain_valid) return true;
    }
    return false;
  }

  ValidationResult CheckTemporalConstraint(const GraphStore& graph,
                                            const SignedTriple& triple,
                                            const TemporalConstraintDef& constraint) const {
    if (!constraint.applies_to_predicates.empty() && triple.data.predicate) {
      bool applies = false;
      for (const auto& p : constraint.applies_to_predicates) {
        if (p == *triple.data.predicate) { applies = true; break; }
      }
      if (!applies) return {true, "", "", ""};
    }

    TripleQuery query;
    query.source = triple.data.source;
    auto existing = graph.QueryTriples(query);

    std::vector<const SignedTriple*> author_triples;
    for (const auto& t : existing) {
      if (t.author == triple.author) author_triples.push_back(&t);
    }

    if (constraint.min_interval_seconds && !author_triples.empty()) {
      const auto& latest = author_triples[0]->timestamp;
      if (!triple.timestamp.empty() && !latest.empty() && triple.timestamp <= latest)
        return {false, constraint.constraint_id, "temporal", "Minimum interval not met"};
    }

    if (constraint.max_count_per_window) {
      if (author_triples.size() >= *constraint.max_count_per_window)
        return {false, constraint.constraint_id, "temporal", "Rate limit exceeded"};
    }

    return {true, "", "", ""};
  }

  ValidationResult CheckContentConstraint(const SignedTriple& triple,
                                           const ContentConstraintDef& constraint) const {
    if (!constraint.applies_to_predicates.empty() && triple.data.predicate) {
      bool applies = false;
      for (const auto& p : constraint.applies_to_predicates) {
        if (p == *triple.data.predicate) { applies = true; break; }
      }
      if (!applies) return {true, "", "", ""};
    }

    const std::string& target = triple.data.target;

    if (constraint.max_text_length && target.size() > *constraint.max_text_length)
      return {false, constraint.constraint_id, "content", "Text exceeds maximum length"};
    if (constraint.min_text_length && target.size() < *constraint.min_text_length)
      return {false, constraint.constraint_id, "content", "Text below minimum length"};

    for (const auto& pattern : constraint.blocked_patterns) {
      try {
        std::regex re(pattern, std::regex::icase);
        if (std::regex_search(target, re))
          return {false, constraint.constraint_id, "content",
                  "Content matches blocked pattern: " + pattern};
      } catch (const std::regex_error&) {
        return {false, constraint.constraint_id, "content", "Invalid blocked pattern regex"};
      }
    }

    if (!constraint.url_policy.empty() && constraint.url_policy != "allow_all") {
      std::regex url_re(R"(https?://\S+)", std::regex::icase);
      bool has_url = std::regex_search(target, url_re);

      if (constraint.url_policy == "block_all" && has_url)
        return {false, constraint.constraint_id, "content", "URLs are not allowed"};

      if (constraint.url_policy == "allowlist" && has_url) {
        std::smatch match;
        if (std::regex_search(target, match, url_re)) {
          std::string url = match[0].str();
          bool allowed = false;
          for (const auto& domain : constraint.url_list) {
            if (url.find(domain) != std::string::npos) { allowed = true; break; }
          }
          if (!allowed)
            return {false, constraint.constraint_id, "content", "URL not in allowlist"};
        }
      }

      if (constraint.url_policy == "blocklist" && has_url) {
        std::smatch match;
        if (std::regex_search(target, match, url_re)) {
          std::string url = match[0].str();
          for (const auto& domain : constraint.url_list) {
            if (url.find(domain) != std::string::npos)
              return {false, constraint.constraint_id, "content", "URL in blocklist"};
          }
        }
      }
    }

    return {true, "", "", ""};
  }

  ValidationResult CheckCredentialConstraint(const GraphStore& graph,
                                              const std::string& agent_did,
                                              const CredentialConstraintDef& constraint) const {
    TripleQuery query;
    query.source = agent_did;
    query.predicate = "governance://has_credential";
    auto cred_triples = graph.QueryTriples(query);

    for (const auto& cred_triple : cred_triples) {
      const std::string& cred_address = cred_triple.data.target;

      auto cred_type = GetTripleTarget(graph, cred_address, "vc://type");
      if (!cred_type || *cred_type != constraint.required_credential_type) continue;

      if (!constraint.issuer_pattern.empty()) {
        auto issuer = GetTripleTarget(graph, cred_address, "vc://issuer");
        if (!issuer) continue;
        if (constraint.issuer_pattern != "*" && constraint.issuer_pattern != *issuer) {
          std::string pattern = constraint.issuer_pattern;
          if (pattern.back() == '*') {
            std::string prefix = pattern.substr(0, pattern.size() - 1);
            if (issuer->find(prefix) != 0) continue;
          } else {
            continue;
          }
        }
      }

      auto subject = GetTripleTarget(graph, cred_address, "vc://subject");
      if (subject && *subject != agent_did) continue;

      return {true, "", "", ""};
    }

    return {false, constraint.constraint_id, "credential",
            "Missing required credential: " + constraint.required_credential_type};
  }

  // Constraint parsers
  std::optional<CapabilityConstraintDef> ParseCapabilityConstraint(
      const GraphStore& graph, const std::string& id) const {
    auto enforcement = GetTripleTarget(graph, id, "governance://capability_enforcement");
    if (!enforcement) return std::nullopt;
    CapabilityConstraintDef def;
    def.constraint_id = id;
    def.enforcement = *enforcement;
    auto preds = GetTripleTarget(graph, id, "governance://capability_predicates");
    if (preds) def.predicates = SplitCSV(*preds);
    return def;
  }

  std::optional<TemporalConstraintDef> ParseTemporalConstraint(
      const GraphStore& graph, const std::string& id) const {
    TemporalConstraintDef def;
    def.constraint_id = id;
    auto interval = GetTripleTarget(graph, id, "governance://temporal_min_interval_seconds");
    if (interval) def.min_interval_seconds = std::stoul(*interval);
    auto max_count = GetTripleTarget(graph, id, "governance://temporal_max_count_per_window");
    if (max_count) def.max_count_per_window = std::stoul(*max_count);
    auto window = GetTripleTarget(graph, id, "governance://temporal_window_seconds");
    if (window) def.window_seconds = std::stoul(*window);
    auto preds = GetTripleTarget(graph, id, "governance://temporal_applies_to_predicates");
    if (preds) def.applies_to_predicates = SplitCSV(*preds);
    if (!def.min_interval_seconds && !def.max_count_per_window) return std::nullopt;
    return def;
  }

  std::optional<ContentConstraintDef> ParseContentConstraint(
      const GraphStore& graph, const std::string& id) const {
    ContentConstraintDef def;
    def.constraint_id = id;
    auto blocked = GetTripleTarget(graph, id, "governance://content_blocked_patterns");
    if (blocked) {
      std::istringstream stream(*blocked);
      std::string pattern;
      while (std::getline(stream, pattern, '|')) {
        if (!pattern.empty()) def.blocked_patterns.push_back(pattern);
      }
    }
    auto max_len = GetTripleTarget(graph, id, "governance://content_max_text_length");
    if (max_len) def.max_text_length = std::stoul(*max_len);
    auto min_len = GetTripleTarget(graph, id, "governance://content_min_text_length");
    if (min_len) def.min_text_length = std::stoul(*min_len);
    auto url_policy = GetTripleTarget(graph, id, "governance://content_url_policy");
    if (url_policy) def.url_policy = *url_policy;
    auto url_list = GetTripleTarget(graph, id, "governance://content_url_list");
    if (url_list) def.url_list = SplitCSV(*url_list);
    auto media = GetTripleTarget(graph, id, "governance://content_allowed_media_types");
    if (media) def.allowed_media_types = SplitCSV(*media);
    auto preds = GetTripleTarget(graph, id, "governance://content_applies_to_predicates");
    if (preds) def.applies_to_predicates = SplitCSV(*preds);
    return def;
  }

  std::optional<CredentialConstraintDef> ParseCredentialConstraint(
      const GraphStore& graph, const std::string& id) const {
    auto type = GetTripleTarget(graph, id, "governance://requires_credential_type");
    if (!type) return std::nullopt;
    CredentialConstraintDef def;
    def.constraint_id = id;
    def.required_credential_type = *type;
    auto issuer = GetTripleTarget(graph, id, "governance://credential_issuer_pattern");
    if (issuer) def.issuer_pattern = *issuer;
    auto age = GetTripleTarget(graph, id, "governance://credential_min_age_hours");
    if (age) def.min_age_hours = std::stoul(*age);
    return def;
  }

  // Helpers
  std::optional<std::string> GetTripleTarget(const GraphStore& graph,
                                              const std::string& source,
                                              const std::string& predicate) const {
    TripleQuery query;
    query.source = source;
    query.predicate = predicate;
    auto results = graph.QueryTriples(query);
    if (results.empty()) return std::nullopt;
    return results[0].data.target;
  }

  std::vector<std::string> SplitCSV(const std::string& csv) const {
    std::vector<std::string> result;
    std::istringstream stream(csv);
    std::string item;
    while (std::getline(stream, item, ',')) {
      size_t start = item.find_first_not_of(" \t");
      size_t end = item.find_last_not_of(" \t");
      if (start != std::string::npos)
        result.push_back(item.substr(start, end - start + 1));
    }
    return result;
  }
};

}  // namespace living_web

#endif  // LIVING_WEB_GOVERNANCE_ENGINE_H_
