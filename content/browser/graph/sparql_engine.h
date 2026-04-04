// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_SPARQL_ENGINE_H_
#define CONTENT_BROWSER_GRAPH_SPARQL_ENGINE_H_

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "content/browser/graph/triple.h"

namespace content {

// SparqlEngine — basic SPARQL BGP evaluator.
class SparqlEngine {
 public:
  using Binding = std::unordered_map<std::string, std::string>;

  SparqlEngine();
  ~SparqlEngine();

  // Execute a SPARQL query against a set of signed triples.
  std::string Execute(const std::string& sparql,
                      const std::vector<SignedTriple>& triples) const;

 private:
  struct TriplePattern {
    TriplePattern();
    ~TriplePattern();
    TriplePattern(const TriplePattern&);
    TriplePattern& operator=(const TriplePattern&);

    std::string subject;
    std::string predicate;
    std::string object;
    bool is_optional = false;
  };

  struct ParsedQuery {
    ParsedQuery();
    ~ParsedQuery();
    ParsedQuery(const ParsedQuery&);
    ParsedQuery& operator=(const ParsedQuery&);
    ParsedQuery(ParsedQuery&&);
    ParsedQuery& operator=(ParsedQuery&&);

    std::vector<std::string> select_vars;
    std::vector<TriplePattern> patterns;
    uint32_t limit = 0;
    bool is_select = true;
  };

  ParsedQuery Parse(const std::string& sparql) const;

  std::vector<Binding> Evaluate(
      const ParsedQuery& query,
      const std::vector<SignedTriple>& triples) const;

  bool MatchTriple(const TriplePattern& pattern,
                   const SignedTriple& triple,
                   Binding& binding) const;

  std::string SerializeBindings(
      const std::vector<Binding>& bindings,
      const std::vector<std::string>& vars) const;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SPARQL_ENGINE_H_
