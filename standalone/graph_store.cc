// Graph Store - standalone implementation
#include "graph_store.h"
#include "json_parser.h"
#include "base_shim.h"
#include <sstream>

namespace living_web {

bool GraphStore::AddShape(const std::string& name,
                           const std::string& shacl_json) {
  JsonObject shape;
  if (!JsonParser::Parse(shacl_json, shape)) return false;
  if (!shape.has("targetClass") || !shape.has("properties") ||
      !shape.has("constructor"))
    return false;

  shapes_[name] = shacl_json;

  // Store shape as triples for discoverability
  SignedTriple shape_triple;
  shape_triple.data.source = "shacl://" + name;
  shape_triple.data.predicate = "shacl://has_shape";
  shape_triple.data.target = shacl_json;
  shape_triple.author = "system";
  shape_triple.timestamp = "1970-01-01T00:00:00Z";
  triples_.push_back(shape_triple);

  return true;
}

std::vector<std::string> GraphStore::GetShapeInstances(
    const std::string& shape_name) const {
  auto it = shapes_.find(shape_name);
  if (it == shapes_.end()) return {};

  JsonObject shape;
  if (!JsonParser::Parse(it->second, shape)) return {};

  std::string target_class;
  if (!shape.getString("targetClass", target_class)) return {};

  std::vector<std::string> instances;
  for (const auto& triple : triples_) {
    if (triple.data.predicate == "rdf:type" &&
        triple.data.target == target_class) {
      instances.push_back(triple.data.source);
    }
  }
  return instances;
}

std::string GraphStore::CreateShapeInstance(const std::string& shape_name,
                                            const std::string& data_json) {
  auto shape_it = shapes_.find(shape_name);
  if (shape_it == shapes_.end()) return "";

  JsonObject shape;
  if (!JsonParser::Parse(shape_it->second, shape)) return "";

  JsonObject data;
  if (!JsonParser::Parse(data_json, data)) return "";

  std::string target_class;
  if (!shape.getString("targetClass", target_class)) return "";

  std::string instance_uri = target_class + ":" +
      base::Uuid::GenerateRandomV4().AsLowercaseString();

  std::string constructor_json;
  if (!shape.getArrayRaw("constructor", constructor_json)) return "";

  auto actions = JsonParser::ParseArray(constructor_json);
  for (const auto& action_str : actions) {
    JsonObject action;
    if (!JsonParser::Parse(action_str, action)) continue;

    std::string action_type;
    if (!action.getString("action", action_type) || action_type != "addLink")
      continue;

    std::string predicate;
    if (!action.getString("predicate", predicate)) continue;

    std::string target_value;
    std::string value_str, param_str;
    if (action.getString("value", value_str)) {
      target_value = value_str;
    } else if (action.getString("target", param_str)) {
      data.getString(param_str, target_value);
    }

    if (target_value.empty()) continue;

    SignedTriple triple;
    triple.data.source = instance_uri;
    triple.data.predicate = predicate;
    triple.data.target = target_value;
    triple.author = "system";
    triple.timestamp = "2026-01-01T00:00:00Z";
    triples_.push_back(triple);
  }

  return instance_uri;
}

}  // namespace living_web
