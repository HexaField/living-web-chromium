// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/graph_store.h"

#include <algorithm>
#include <regex>
#include <sstream>

#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/uuid.h"

namespace content {

GraphStore::GraphStore(const std::string& uuid, const std::string& name)
    : uuid_(uuid), name_(name) {}

GraphStore::~GraphStore() = default;

bool GraphStore::AddTriple(const SignedTriple& triple) {
  // Check for duplicates (same data + author + timestamp).
  for (const auto& existing : triples_) {
    if (existing == triple)
      return false;
  }
  triples_.push_back(triple);
  return true;
}

bool GraphStore::AddTriples(const std::vector<SignedTriple>& triples) {
  // Validate all first (check for duplicates).
  for (const auto& triple : triples) {
    for (const auto& existing : triples_) {
      if (existing == triple)
        return false;
    }
  }
  // All valid — add them.
  for (const auto& triple : triples) {
    triples_.push_back(triple);
  }
  return true;
}

bool GraphStore::RemoveTriple(const SignedTriple& triple) {
  auto it = std::find(triples_.begin(), triples_.end(), triple);
  if (it != triples_.end()) {
    triples_.erase(it);
    return true;
  }
  return false;
}

std::vector<SignedTriple> GraphStore::QueryTriples(
    const TripleQuery& query) const {
  std::vector<SignedTriple> results;

  for (const auto& triple : triples_) {
    if (!triple.data.Matches(query.source, query.target, query.predicate))
      continue;

    // Temporal filtering.
    if (query.from_date && triple.timestamp < *query.from_date)
      continue;
    if (query.until_date && triple.timestamp >= *query.until_date)
      continue;

    results.push_back(triple);
  }

  // Sort by timestamp descending.
  std::sort(results.begin(), results.end(),
            [](const SignedTriple& a, const SignedTriple& b) {
              return a.timestamp > b.timestamp;
            });

  // Apply limit.
  if (query.limit && results.size() > *query.limit) {
    results.resize(*query.limit);
  }

  return results;
}

std::vector<SignedTriple> GraphStore::Snapshot() const {
  auto result = triples_;
  std::sort(result.begin(), result.end(),
            [](const SignedTriple& a, const SignedTriple& b) {
              return a.timestamp < b.timestamp;
            });
  return result;
}

std::vector<GraphStore::SparqlPattern> GraphStore::ParseBasicGraphPatterns(
    const std::string& sparql) const {
  std::vector<SparqlPattern> patterns;

  // Very basic parser: extract triple patterns from WHERE { ... }
  // Handles: ?var or <uri> tokens separated by whitespace, terminated by .
  auto where_pos = sparql.find("WHERE");
  if (where_pos == std::string::npos)
    where_pos = sparql.find("where");
  if (where_pos == std::string::npos)
    return patterns;

  auto brace_start = sparql.find('{', where_pos);
  auto brace_end = sparql.rfind('}');
  if (brace_start == std::string::npos || brace_end == std::string::npos)
    return patterns;

  std::string body = sparql.substr(brace_start + 1,
                                    brace_end - brace_start - 1);

  // Split by '.'
  std::istringstream stream(body);
  std::string pattern_str;
  while (std::getline(stream, pattern_str, '.')) {
    // Trim and tokenize.
    std::istringstream tokens(pattern_str);
    std::string s, p, o;
    if (tokens >> s >> p >> o) {
      patterns.push_back({s, p, o});
    }
  }

  return patterns;
}

std::string GraphStore::QuerySparql(const std::string& sparql) const {
  // Basic SPARQL BGP evaluation.
  // Full SPARQL 1.1 requires Oxigraph integration.
  auto patterns = ParseBasicGraphPatterns(sparql);
  if (patterns.empty())
    return "[]";

  // For single-pattern queries, do a simple match.
  // Variables start with '?', URIs are enclosed in <>.
  std::vector<std::unordered_map<std::string, std::string>> bindings;

  if (patterns.size() == 1) {
    const auto& pat = patterns[0];
    bool s_var = pat.subject[0] == '?';
    bool p_var = pat.predicate[0] == '?';
    bool o_var = pat.object[0] == '?';

    // Strip < > from URIs.
    auto strip = [](const std::string& s) -> std::string {
      if (s.front() == '<' && s.back() == '>')
        return s.substr(1, s.size() - 2);
      return s;
    };

    for (const auto& triple : triples_) {
      bool match = true;
      if (!s_var && strip(pat.subject) != triple.data.source) match = false;
      if (!p_var) {
        if (triple.data.predicate && strip(pat.predicate) != *triple.data.predicate)
          match = false;
        if (!triple.data.predicate)
          match = false;
      }
      if (!o_var && strip(pat.object) != triple.data.target) match = false;

      if (match) {
        std::unordered_map<std::string, std::string> binding;
        if (s_var) binding[pat.subject] = triple.data.source;
        if (p_var) binding[pat.predicate] = triple.data.predicate.value_or("");
        if (o_var) binding[pat.object] = triple.data.target;
        bindings.push_back(std::move(binding));
      }
    }
  }

  // Serialize to JSON.
  std::string result = "[";
  for (size_t i = 0; i < bindings.size(); ++i) {
    if (i > 0) result += ",";
    result += "{";
    bool first = true;
    for (const auto& [k, v] : bindings[i]) {
      if (!first) result += ",";
      result += "\"" + k + "\":\"" + v + "\"";
      first = false;
    }
    result += "}";
  }
  result += "]";
  return result;
}

bool GraphStore::AddShape(const std::string& name,
                           const std::string& shacl_json) {
  // Parse JSON to validate structure.
  auto value = base::JSONReader::Read(shacl_json);
  if (!value || !value->is_dict()) {
    LOG(WARNING) << "Invalid shape JSON for " << name;
    return false;
  }

  // Validate required fields: targetClass, properties, constructor.
  const auto& dict = value->GetDict();
  if (!dict.FindString("targetClass") ||
      !dict.FindList("properties") ||
      !dict.FindList("constructor")) {
    LOG(WARNING) << "Shape missing required fields: " << name;
    return false;
  }

  shapes_[name] = shacl_json;

  // Also store shape as triples in the graph for discoverability.
  std::string shape_uri = "shacl://" + name;
  SignedTriple shape_triple;
  shape_triple.data.source = shape_uri;
  shape_triple.data.predicate = "shacl://has_shape";
  shape_triple.data.target = shacl_json;
  shape_triple.author = "system";
  shape_triple.timestamp = "1970-01-01T00:00:00Z";  // system triple
  triples_.push_back(shape_triple);

  return true;
}

std::vector<std::string> GraphStore::GetShapeInstances(
    const std::string& shape_name) const {
  auto it = shapes_.find(shape_name);
  if (it == shapes_.end())
    return {};

  // Parse the shape to get targetClass.
  auto value = base::JSONReader::Read(it->second);
  if (!value || !value->is_dict())
    return {};

  const std::string* target_class =
      value->GetDict().FindString("targetClass");
  if (!target_class)
    return {};

  // Find all entities with rdf:type == targetClass.
  std::vector<std::string> instances;
  for (const auto& triple : triples_) {
    if (triple.data.predicate == "rdf:type" &&
        triple.data.target == *target_class) {
      instances.push_back(triple.data.source);
    }
  }
  return instances;
}

std::string GraphStore::CreateShapeInstance(const std::string& shape_name,
                                            const std::string& data_json) {
  auto shape_it = shapes_.find(shape_name);
  if (shape_it == shapes_.end())
    return "";

  auto shape = base::JSONReader::Read(shape_it->second);
  if (!shape || !shape->is_dict())
    return "";

  auto data = base::JSONReader::Read(data_json);
  if (!data || !data->is_dict())
    return "";

  const std::string* target_class =
      shape->GetDict().FindString("targetClass");
  if (!target_class)
    return "";

  // Generate instance URI.
  std::string instance_uri = *target_class + ":" +
      base::Uuid::GenerateRandomV4().AsLowercaseString();

  // Execute constructor actions.
  const auto* constructor_list = shape->GetDict().FindList("constructor");
  if (!constructor_list)
    return "";

  for (const auto& action_val : *constructor_list) {
    if (!action_val.is_dict()) continue;
    const auto& action = action_val.GetDict();

    const std::string* action_type = action.FindString("action");
    if (!action_type || *action_type != "addLink") continue;

    const std::string* predicate = action.FindString("predicate");
    if (!predicate) continue;

    std::string target_value;
    const std::string* value_str = action.FindString("value");
    const std::string* param_str = action.FindString("target");

    if (value_str) {
      target_value = *value_str;
    } else if (param_str) {
      // Look up parameter in data.
      const std::string* data_val = data->GetDict().FindString(*param_str);
      if (data_val) {
        target_value = *data_val;
      }
    }

    if (target_value.empty()) continue;

    SignedTriple triple;
    triple.data.source = instance_uri;
    triple.data.predicate = *predicate;
    triple.data.target = target_value;
    triple.author = "system";  // Would use active DID in real impl
    triple.timestamp = "2026-01-01T00:00:00Z";  // Would use real time
    triples_.push_back(triple);
  }

  return instance_uri;
}

}  // namespace content
