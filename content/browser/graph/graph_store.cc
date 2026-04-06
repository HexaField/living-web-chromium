// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/graph_store.h"

#include <algorithm>
#include <regex>
#include <sstream>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/threading/thread_restrictions.h"
#include "base/uuid.h"
#include "base/values.h"

namespace content {

TripleQuery::TripleQuery() = default;
TripleQuery::~TripleQuery() = default;
TripleQuery::TripleQuery(const TripleQuery&) = default;
TripleQuery& TripleQuery::operator=(const TripleQuery&) = default;
TripleQuery::TripleQuery(TripleQuery&&) = default;
TripleQuery& TripleQuery::operator=(TripleQuery&&) = default;

GraphStore::GraphStore(const std::string& uuid,
                       const std::string& name,
                       const base::FilePath& persistence_dir)
    : uuid_(uuid), name_(name), persistence_dir_(persistence_dir) {
  LoadFromDisk();
}

GraphStore::~GraphStore() = default;

bool GraphStore::AddTriple(const SignedTriple& triple) {
  // Check for duplicates (same data + author + timestamp).
  for (const auto& existing : triples_) {
    if (existing == triple)
      return false;
  }
  triples_.push_back(triple);
  PersistToDisk();
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
  PersistToDisk();
  return true;
}

bool GraphStore::RemoveTriple(const SignedTriple& triple) {
  // Match by source/predicate/target only, not by author/timestamp/proof.
  auto it = std::find_if(triples_.begin(), triples_.end(),
      [&triple](const SignedTriple& existing) {
        return existing.data.source == triple.data.source &&
               existing.data.target == triple.data.target &&
               existing.data.predicate == triple.data.predicate;
      });
  if (it != triples_.end()) {
    triples_.erase(it);
    PersistToDisk();
    return true;
  }
  return false;
}

std::vector<std::string> GraphStore::GetShapes() const {
  std::vector<std::string> names;
  names.reserve(shapes_.size());
  for (const auto& [name, _] : shapes_) {
    names.push_back(name);
  }
  return names;
}

bool GraphStore::RemoveShape(const std::string& name) {
  auto it = shapes_.find(name);
  if (it == shapes_.end())
    return false;
  shapes_.erase(it);
  PersistToDisk();
  return true;
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
  auto value = base::JSONReader::Read(shacl_json, base::JSON_PARSE_RFC);
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
  PersistToDisk();

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
  auto value = base::JSONReader::Read(it->second, base::JSON_PARSE_RFC);
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
                                            const std::string& instance_uri,
                                            const std::string& data_json) {
  auto shape_it = shapes_.find(shape_name);
  if (shape_it == shapes_.end())
    return "";

  auto shape = base::JSONReader::Read(shape_it->second, base::JSON_PARSE_RFC);
  if (!shape || !shape->is_dict())
    return "";

  auto data = base::JSONReader::Read(data_json, base::JSON_PARSE_RFC);
  if (!data || !data->is_dict())
    return "";

  const std::string* target_class =
      shape->GetDict().FindString("targetClass");
  if (!target_class)
    return "";

  // Use provided instance URI, or generate one.
  std::string uri = instance_uri.empty()
      ? (*target_class + ":" + base::Uuid::GenerateRandomV4().AsLowercaseString())
      : instance_uri;

  // Execute constructor actions.
  const auto* constructor_list = shape->GetDict().FindList("constructor");
  if (!constructor_list)
    return "";

  for (const auto& action_val : *constructor_list) {
    if (!action_val.is_dict()) continue;
    const auto& action = action_val.GetDict();

    const std::string* action_type = action.FindString("action");
    if (!action_type) continue;

    // Support both "addLink" and "setSingleTarget" actions.
    if (*action_type != "addLink" && *action_type != "setSingleTarget")
      continue;

    const std::string* predicate = action.FindString("predicate");
    if (!predicate) continue;

    std::string target_value;
    const std::string* value_str = action.FindString("value");
    const std::string* param_str = action.FindString("target");

    if (value_str) {
      target_value = *value_str;
    } else if (param_str) {
      // Look up parameter in data; if not found, use as literal value.
      const std::string* data_val = data->GetDict().FindString(*param_str);
      if (data_val) {
        target_value = *data_val;
      } else {
        target_value = *param_str;
      }
    }

    SignedTriple triple;
    triple.data.source = uri;
    triple.data.predicate = *predicate;
    triple.data.target = target_value;
    triple.author = "system";  // Would use active DID in real impl
    triple.timestamp = "2026-01-01T00:00:00Z";  // Would use real time
    triples_.push_back(triple);
  }

  PersistToDisk();
  return uri;
}

base::FilePath GraphStore::GetPersistencePath() const {
  return persistence_dir_.AppendASCII(uuid_ + ".json");
}

void GraphStore::LoadFromDisk() {
  if (persistence_dir_.empty())
    return;

  base::ScopedAllowBlocking allow_blocking;
  base::FilePath path = GetPersistencePath();
  std::string json;
  if (!base::ReadFileToString(path, &json))
    return;

  auto parsed = base::JSONReader::Read(json, base::JSON_PARSE_RFC);
  if (!parsed || !parsed->is_dict()) {
    LOG(WARNING) << "GraphStore: failed to parse persistence file: " << path;
    return;
  }

  const auto& root = parsed->GetDict();

  // Restore triples.
  const auto* triples_list = root.FindList("triples");
  if (triples_list) {
    for (const auto& tv : *triples_list) {
      if (!tv.is_dict()) continue;
      const auto& td = tv.GetDict();
      SignedTriple st;
      const std::string* source = td.FindString("source");
      const std::string* target = td.FindString("target");
      if (source) st.data.source = *source;
      if (target) st.data.target = *target;
      const std::string* predicate = td.FindString("predicate");
      if (predicate) st.data.predicate = *predicate;
      const std::string* author = td.FindString("author");
      if (author) st.author = *author;
      const std::string* timestamp = td.FindString("timestamp");
      if (timestamp) st.timestamp = *timestamp;
      const std::string* proof_key = td.FindString("proof_key");
      if (proof_key) st.proof.key = *proof_key;
      const std::string* proof_sig = td.FindString("proof_signature");
      if (proof_sig) st.proof.signature = *proof_sig;
      triples_.push_back(std::move(st));
    }
  }

  // Restore shapes.
  const auto* shapes_dict = root.FindDict("shapes");
  if (shapes_dict) {
    for (auto [name, val] : *shapes_dict) {
      if (val.is_string())
        shapes_[name] = val.GetString();
    }
  }

  LOG(INFO) << "GraphStore: loaded " << triples_.size() << " triples, "
            << shapes_.size() << " shapes from " << path;
}

void GraphStore::PersistToDisk() {
  if (persistence_dir_.empty())
    return;

  base::ScopedAllowBlocking allow_blocking;

  // Ensure directory exists.
  if (!base::CreateDirectory(persistence_dir_)) {
    LOG(ERROR) << "GraphStore: failed to create directory: "
               << persistence_dir_;
    return;
  }

  base::DictValue root;
  root.Set("uuid", uuid_);
  root.Set("name", name_);

  // Serialize triples.
  base::ListValue triples_list;
  for (const auto& st : triples_) {
    base::DictValue td;
    td.Set("source", st.data.source);
    td.Set("target", st.data.target);
    if (st.data.predicate)
      td.Set("predicate", *st.data.predicate);
    td.Set("author", st.author);
    td.Set("timestamp", st.timestamp);
    td.Set("proof_key", st.proof.key);
    td.Set("proof_signature", st.proof.signature);
    triples_list.Append(std::move(td));
  }
  root.Set("triples", std::move(triples_list));

  // Serialize shapes.
  base::DictValue shapes_dict;
  for (const auto& [name, json] : shapes_) {
    shapes_dict.Set(name, json);
  }
  root.Set("shapes", std::move(shapes_dict));

  std::string output;
  if (!base::JSONWriter::WriteWithOptions(
          root, base::JSONWriter::OPTIONS_PRETTY_PRINT, &output)) {
    LOG(ERROR) << "GraphStore: failed to serialize to JSON";
    return;
  }

  base::FilePath path = GetPersistencePath();
  if (!base::WriteFile(path, output)) {
    LOG(ERROR) << "GraphStore: failed to write: " << path;
  }
}

}  // namespace content
