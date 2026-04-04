// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/sparql_engine.h"

#include <algorithm>
#include <regex>
#include <sstream>

namespace content {

SparqlEngine::ParsedQuery SparqlEngine::Parse(
    const std::string& sparql) const {
  ParsedQuery query;

  // Detect SELECT vs CONSTRUCT.
  std::string upper = sparql;
  std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
  query.is_select = upper.find("SELECT") != std::string::npos;

  // Extract SELECT variables.
  if (query.is_select) {
    std::regex select_re(R"(SELECT\s+(.*?)\s+WHERE)",
                         std::regex::icase);
    std::smatch match;
    if (std::regex_search(sparql, match, select_re)) {
      std::istringstream vars(match[1].str());
      std::string var;
      while (vars >> var) {
        if (var == "*") {
          // Will collect all variables from patterns.
          break;
        }
        query.select_vars.push_back(var);
      }
    }
  }

  // Extract WHERE body.
  auto brace_start = sparql.find('{');
  auto brace_end = sparql.rfind('}');
  if (brace_start == std::string::npos || brace_end == std::string::npos)
    return query;

  std::string body = sparql.substr(brace_start + 1,
                                    brace_end - brace_start - 1);

  // Check for OPTIONAL blocks (simple single-pattern support).
  // Split by '.' first, then check for OPTIONAL keyword.
  std::istringstream stream(body);
  std::string segment;
  while (std::getline(stream, segment, '.')) {
    // Trim whitespace.
    size_t start = segment.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) continue;
    segment = segment.substr(start);

    bool optional = false;
    std::regex optional_re(R"(OPTIONAL\s*\{(.*)\})", std::regex::icase);
    std::smatch opt_match;
    if (std::regex_search(segment, opt_match, optional_re)) {
      segment = opt_match[1].str();
      optional = true;
    }

    std::istringstream tokens(segment);
    std::string s, p, o;
    if (tokens >> s >> p >> o) {
      TriplePattern pattern;
      pattern.subject = s;
      pattern.predicate = p;
      pattern.object = o;
      pattern.is_optional = optional;
      query.patterns.push_back(pattern);
    }
  }

  // Extract LIMIT.
  std::regex limit_re(R"(LIMIT\s+(\d+))", std::regex::icase);
  std::smatch limit_match;
  if (std::regex_search(sparql, limit_match, limit_re)) {
    query.limit = std::stoul(limit_match[1].str());
  }

  // If SELECT *, collect all variables from patterns.
  if (query.select_vars.empty()) {
    for (const auto& p : query.patterns) {
      if (p.subject[0] == '?') query.select_vars.push_back(p.subject);
      if (p.predicate[0] == '?') query.select_vars.push_back(p.predicate);
      if (p.object[0] == '?') query.select_vars.push_back(p.object);
    }
    // Deduplicate.
    std::sort(query.select_vars.begin(), query.select_vars.end());
    query.select_vars.erase(
        std::unique(query.select_vars.begin(), query.select_vars.end()),
        query.select_vars.end());
  }

  return query;
}

bool SparqlEngine::MatchTriple(const TriplePattern& pattern,
                                const SignedTriple& triple,
                                Binding& binding) const {
  auto strip = [](const std::string& s) -> std::string {
    if (s.size() >= 2 && s.front() == '<' && s.back() == '>')
      return s.substr(1, s.size() - 2);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
      return s.substr(1, s.size() - 2);
    return s;
  };

  auto match_term = [&](const std::string& pat_term,
                         const std::string& value) -> bool {
    if (pat_term[0] == '?') {
      // Variable — check if already bound.
      auto it = binding.find(pat_term);
      if (it != binding.end())
        return it->second == value;
      binding[pat_term] = value;
      return true;
    }
    return strip(pat_term) == value;
  };

  Binding backup = binding;

  if (!match_term(pattern.subject, triple.data.source)) {
    binding = backup;
    return false;
  }
  if (!triple.data.predicate) {
    if (pattern.predicate[0] != '?') {
      binding = backup;
      return false;
    }
    binding[pattern.predicate] = "";
  } else {
    if (!match_term(pattern.predicate, *triple.data.predicate)) {
      binding = backup;
      return false;
    }
  }
  if (!match_term(pattern.object, triple.data.target)) {
    binding = backup;
    return false;
  }

  return true;
}

std::vector<SparqlEngine::Binding> SparqlEngine::Evaluate(
    const ParsedQuery& query,
    const std::vector<SignedTriple>& triples) const {
  // Simple nested-loop join for multiple patterns.
  std::vector<Binding> results = {{}};  // Start with empty binding.

  for (const auto& pattern : query.patterns) {
    if (pattern.is_optional) {
      // For OPTIONAL, try to extend each binding but keep it if no match.
      std::vector<Binding> new_results;
      for (const auto& binding : results) {
        bool found = false;
        for (const auto& triple : triples) {
          Binding extended = binding;
          if (MatchTriple(pattern, triple, extended)) {
            new_results.push_back(extended);
            found = true;
          }
        }
        if (!found) {
          new_results.push_back(binding);  // Keep original.
        }
      }
      results = std::move(new_results);
    } else {
      // Required pattern — must match.
      std::vector<Binding> new_results;
      for (const auto& binding : results) {
        for (const auto& triple : triples) {
          Binding extended = binding;
          if (MatchTriple(pattern, triple, extended)) {
            new_results.push_back(extended);
          }
        }
      }
      results = std::move(new_results);
    }
  }

  // Apply LIMIT.
  if (query.limit > 0 && results.size() > query.limit) {
    results.resize(query.limit);
  }

  return results;
}

std::string SparqlEngine::SerializeBindings(
    const std::vector<Binding>& bindings,
    const std::vector<std::string>& vars) const {
  std::string result = "[";
  for (size_t i = 0; i < bindings.size(); ++i) {
    if (i > 0) result += ",";
    result += "{";
    bool first = true;
    for (const auto& var : vars) {
      if (!first) result += ",";
      auto it = bindings[i].find(var);
      std::string value = (it != bindings[i].end()) ? it->second : "";
      // Escape quotes in value.
      std::string escaped;
      for (char c : value) {
        if (c == '"') escaped += "\\\"";
        else escaped += c;
      }
      result += "\"" + var + "\":\"" + escaped + "\"";
      first = false;
    }
    result += "}";
  }
  result += "]";
  return result;
}

std::string SparqlEngine::Execute(
    const std::string& sparql,
    const std::vector<SignedTriple>& triples) const {
  auto query = Parse(sparql);
  auto bindings = Evaluate(query, triples);
  return SerializeBindings(bindings, query.select_vars);
}

}  // namespace content
