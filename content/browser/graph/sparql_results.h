// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A complete recursive-descent JSON parser and a SPARQL 1.1 JSON Results
// decoder for the Living Web graph substrate (Spec 02 — Personal Linked Data
// Graphs).
//
// Spec 02's queryTriples/provenance/snapshot algorithms evaluate SPARQL SELECT
// over the reifier structure and must reconstruct RDF terms (IRI / literal with
// datatype+language / blank node) from the engine's answer. The lightweight
// standalone/json_parser.h flattens nested objects to raw strings and cannot
// represent the nested `results.bindings[].var.{type,value,datatype,xml:lang}`
// shape, so this module supplies a faithful JSON value model plus the SPARQL
// Results binding decode. It is Chromium-independent so the browser service and
// the standalone harness decode identically.

#ifndef CONTENT_BROWSER_GRAPH_SPARQL_RESULTS_H_
#define CONTENT_BROWSER_GRAPH_SPARQL_RESULTS_H_

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace living_web {

// A parsed JSON value. Nested arrays/objects are represented in full (unlike the
// flat json_parser.h), which the SPARQL Results shape requires.
struct JsonValue {
  enum class Type { kNull, kBool, kNumber, kString, kArray, kObject };

  Type type = Type::kNull;
  bool bool_value = false;
  double number_value = 0.0;
  std::string string_value;
  std::vector<JsonValue> array_value;
  std::map<std::string, JsonValue> object_value;

  bool is_object() const { return type == Type::kObject; }
  bool is_array() const { return type == Type::kArray; }
  bool is_string() const { return type == Type::kString; }
  bool is_bool() const { return type == Type::kBool; }

  // Returns the member named |key| of an object value, or nullptr if this is not
  // an object or has no such member.
  const JsonValue* Find(const std::string& key) const;
};

// Parses a complete JSON document (RFC 8259). Any trailing non-whitespace after
// the top-level value is an error. \uXXXX escapes (including surrogate pairs) are
// decoded to UTF-8. Returns false with *error set on malformation.
bool ParseJson(const std::string& text, JsonValue* out, std::string* error);

// The kind of an RDF term appearing in a SPARQL result binding.
enum class SparqlTermType { kUri, kLiteral, kBlankNode, kTriple };

// One RDF term from a SPARQL result binding (SPARQL 1.1 Results JSON §3.2, plus
// the RDF-star "triple" term type). For kLiteral, |datatype| and |language| are
// populated when present. For kTriple, |components| holds subject, predicate and
// object in that order.
struct SparqlTerm {
  SparqlTermType type = SparqlTermType::kUri;
  std::string value;  // IRI, blank-node label (no "_:"), or literal lexical form
  std::optional<std::string> datatype;  // literal only
  std::optional<std::string> language;  // literal only
  std::vector<SparqlTerm> components;   // kTriple only: exactly {s, p, o}
};

// One SELECT solution: a map from bound variable name to its term. Unbound
// variables are simply absent.
struct SparqlSolution {
  std::map<std::string, SparqlTerm> bindings;

  const SparqlTerm* Get(const std::string& var) const {
    auto it = bindings.find(var);
    return it == bindings.end() ? nullptr : &it->second;
  }
};

// A decoded SELECT result set: the ordered projected variables and the ordered
// solutions.
struct SparqlSelect {
  std::vector<std::string> vars;
  std::vector<SparqlSolution> solutions;
};

// Decodes a SPARQL 1.1 Results JSON document produced for a SELECT query.
// Returns false with *error set on malformation.
bool DecodeSparqlSelect(const std::string& json,
                        SparqlSelect* out,
                        std::string* error);

// Decodes a SPARQL 1.1 Results JSON document produced for an ASK query.
// Returns false with *error set on malformation.
bool DecodeSparqlBoolean(const std::string& json, bool* out, std::string* error);

}  // namespace living_web

#endif  // CONTENT_BROWSER_GRAPH_SPARQL_RESULTS_H_
