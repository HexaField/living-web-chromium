// Graph Store - standalone implementation
#ifndef LIVING_WEB_GRAPH_STORE_H_
#define LIVING_WEB_GRAPH_STORE_H_

#include "types.h"
#include <unordered_map>
#include <algorithm>

namespace living_web {

class GraphStore {
 public:
  GraphStore(const std::string& uuid, const std::string& name)
      : uuid_(uuid), name_(name) {}
  ~GraphStore() = default;

  GraphStore(const GraphStore&) = delete;
  GraphStore& operator=(const GraphStore&) = delete;

  const std::string& uuid() const { return uuid_; }
  const std::string& name() const { return name_; }
  size_t size() const { return triples_.size(); }

  bool AddTriple(const SignedTriple& triple) {
    for (const auto& existing : triples_) {
      if (existing == triple) return false;
    }
    triples_.push_back(triple);
    return true;
  }

  bool AddTriples(const std::vector<SignedTriple>& triples) {
    for (const auto& triple : triples) {
      for (const auto& existing : triples_) {
        if (existing == triple) return false;
      }
    }
    for (const auto& triple : triples) {
      triples_.push_back(triple);
    }
    return true;
  }

  bool RemoveTriple(const SignedTriple& triple) {
    auto it = std::find(triples_.begin(), triples_.end(), triple);
    if (it != triples_.end()) {
      triples_.erase(it);
      return true;
    }
    return false;
  }

  std::vector<SignedTriple> QueryTriples(const TripleQuery& query) const {
    std::vector<SignedTriple> results;
    for (const auto& triple : triples_) {
      if (!triple.data.Matches(query.source, query.target, query.predicate))
        continue;
      if (query.from_date && triple.timestamp < *query.from_date) continue;
      if (query.until_date && triple.timestamp >= *query.until_date) continue;
      results.push_back(triple);
    }
    std::sort(results.begin(), results.end(),
              [](const SignedTriple& a, const SignedTriple& b) {
                return a.timestamp > b.timestamp;
              });
    if (query.limit && results.size() > *query.limit) {
      results.resize(*query.limit);
    }
    return results;
  }

  std::vector<SignedTriple> Snapshot() const {
    auto result = triples_;
    std::sort(result.begin(), result.end(),
              [](const SignedTriple& a, const SignedTriple& b) {
                return a.timestamp < b.timestamp;
              });
    return result;
  }

  // Shape operations
  bool AddShape(const std::string& name, const std::string& shacl_json);
  std::vector<std::string> GetShapeInstances(const std::string& shape_name) const;
  std::string CreateShapeInstance(const std::string& shape_name,
                                  const std::string& data_json);

  // Access internal triples for SPARQL engine
  const std::vector<SignedTriple>& triples() const { return triples_; }

 private:
  std::string uuid_;
  std::string name_;
  std::vector<SignedTriple> triples_;
  std::unordered_map<std::string, std::string> shapes_;
};

}  // namespace living_web

#endif  // LIVING_WEB_GRAPH_STORE_H_
