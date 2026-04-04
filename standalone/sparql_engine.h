// SPARQL Engine - standalone implementation
#ifndef LIVING_WEB_SPARQL_ENGINE_H_
#define LIVING_WEB_SPARQL_ENGINE_H_

#include "types.h"
#include <algorithm>
#include <regex>
#include <sstream>
#include <unordered_map>

namespace living_web {

class SparqlEngine {
 public:
  using Binding = std::unordered_map<std::string, std::string>;

  std::string Execute(const std::string& sparql,
                      const std::vector<SignedTriple>& triples) const {
    auto query = Parse(sparql);
    auto bindings = Evaluate(query, triples);
    return SerializeBindings(bindings, query.select_vars);
  }

 private:
  struct TriplePattern {
    std::string subject;
    std::string predicate;
    std::string object;
    bool is_optional = false;
  };

  struct ParsedQuery {
    std::vector<std::string> select_vars;
    std::vector<TriplePattern> patterns;
    uint32_t limit = 0;
    bool is_select = true;
  };

  ParsedQuery Parse(const std::string& sparql) const {
    ParsedQuery query;
    std::string upper = sparql;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    query.is_select = upper.find("SELECT") != std::string::npos;

    if (query.is_select) {
      std::regex select_re(R"(SELECT\s+(.*?)\s+WHERE)", std::regex::icase);
      std::smatch match;
      if (std::regex_search(sparql, match, select_re)) {
        std::istringstream vars(match[1].str());
        std::string var;
        while (vars >> var) {
          if (var == "*") break;
          query.select_vars.push_back(var);
        }
      }
    }

    auto brace_start = sparql.find('{');
    auto brace_end = sparql.rfind('}');
    if (brace_start == std::string::npos || brace_end == std::string::npos)
      return query;

    std::string body = sparql.substr(brace_start + 1,
                                      brace_end - brace_start - 1);

    std::istringstream stream(body);
    std::string segment;
    while (std::getline(stream, segment, '.')) {
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

    std::regex limit_re(R"(LIMIT\s+(\d+))", std::regex::icase);
    std::smatch limit_match;
    if (std::regex_search(sparql, limit_match, limit_re)) {
      query.limit = std::stoul(limit_match[1].str());
    }

    if (query.select_vars.empty()) {
      for (const auto& p : query.patterns) {
        if (p.subject[0] == '?') query.select_vars.push_back(p.subject);
        if (p.predicate[0] == '?') query.select_vars.push_back(p.predicate);
        if (p.object[0] == '?') query.select_vars.push_back(p.object);
      }
      std::sort(query.select_vars.begin(), query.select_vars.end());
      query.select_vars.erase(
          std::unique(query.select_vars.begin(), query.select_vars.end()),
          query.select_vars.end());
    }

    return query;
  }

  bool MatchTriple(const TriplePattern& pattern, const SignedTriple& triple,
                   Binding& binding) const {
    auto strip = [](const std::string& s) -> std::string {
      if (s.size() >= 2 && s.front() == '<' && s.back() == '>')
        return s.substr(1, s.size() - 2);
      if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        return s.substr(1, s.size() - 2);
      return s;
    };

    auto match_term = [&](const std::string& pat, const std::string& val) -> bool {
      if (pat[0] == '?') {
        auto it = binding.find(pat);
        if (it != binding.end()) return it->second == val;
        binding[pat] = val;
        return true;
      }
      return strip(pat) == val;
    };

    Binding backup = binding;
    if (!match_term(pattern.subject, triple.data.source)) {
      binding = backup; return false;
    }
    if (!triple.data.predicate) {
      if (pattern.predicate[0] != '?') { binding = backup; return false; }
      binding[pattern.predicate] = "";
    } else {
      if (!match_term(pattern.predicate, *triple.data.predicate)) {
        binding = backup; return false;
      }
    }
    if (!match_term(pattern.object, triple.data.target)) {
      binding = backup; return false;
    }
    return true;
  }

  std::vector<Binding> Evaluate(const ParsedQuery& query,
                                 const std::vector<SignedTriple>& triples) const {
    std::vector<Binding> results = {{}};

    for (const auto& pattern : query.patterns) {
      if (pattern.is_optional) {
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
          if (!found) new_results.push_back(binding);
        }
        results = std::move(new_results);
      } else {
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

    if (query.limit > 0 && results.size() > query.limit) {
      results.resize(query.limit);
    }
    return results;
  }

  std::string SerializeBindings(const std::vector<Binding>& bindings,
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
};

}  // namespace living_web

#endif  // LIVING_WEB_SPARQL_ENGINE_H_
