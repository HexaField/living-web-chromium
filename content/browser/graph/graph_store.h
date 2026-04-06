// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GRAPH_STORE_H_
#define CONTENT_BROWSER_GRAPH_GRAPH_STORE_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/files/file_path.h"
#include "content/browser/graph/triple.h"

namespace content {

// TripleQuery — filter for querying triples.
struct TripleQuery {
  TripleQuery();
  ~TripleQuery();
  TripleQuery(const TripleQuery&);
  TripleQuery& operator=(const TripleQuery&);
  TripleQuery(TripleQuery&&);
  TripleQuery& operator=(TripleQuery&&);

  std::optional<std::string> source;
  std::optional<std::string> target;
  std::optional<std::string> predicate;
  std::optional<std::string> from_date;
  std::optional<std::string> until_date;
  std::optional<uint32_t> limit;
};

// GraphStore — an in-memory triple store for a single PersonalGraph.
//
// This is the foundation of the Living Web browser implementation.
// Currently in-memory; designed for later replacement with Oxigraph
// (Rust FFI) for full SPARQL 1.1 support.
//
// Thread-safety: GraphStore is accessed only on the IO thread
// (or a dedicated graph sequence). No internal locking.
class GraphStore {
 public:
  // |persistence_dir| is the directory under which graph JSON files are stored.
  // If empty, persistence is disabled (in-memory only).
  GraphStore(const std::string& uuid,
             const std::string& name,
             const base::FilePath& persistence_dir = base::FilePath());
  ~GraphStore();

  // Disallow copy.
  GraphStore(const GraphStore&) = delete;
  GraphStore& operator=(const GraphStore&) = delete;

  const std::string& uuid() const { return uuid_; }
  const std::string& name() const { return name_; }

  // Add a signed triple. Returns false if duplicate.
  bool AddTriple(const SignedTriple& triple);

  // Add multiple triples atomically. All-or-nothing: if any fails
  // validation, none are added.
  bool AddTriples(const std::vector<SignedTriple>& triples);

  // Remove a signed triple. Returns true if found and removed.
  bool RemoveTriple(const SignedTriple& triple);

  // Query triples matching the filter, ordered by timestamp desc.
  std::vector<SignedTriple> QueryTriples(const TripleQuery& query) const;

  // Get all triples, ordered by timestamp ascending.
  std::vector<SignedTriple> Snapshot() const;

  // Execute a SPARQL query. Currently supports basic triple patterns only.
  // Returns JSON string (for SELECT: array of bindings).
  // Full SPARQL requires Oxigraph integration.
  std::string QuerySparql(const std::string& sparql) const;

  // Triple count.
  size_t size() const { return triples_.size(); }

  // Shape operations
  bool AddShape(const std::string& name, const std::string& shacl_json);
  std::vector<std::string> GetShapes() const;
  bool RemoveShape(const std::string& name);
  std::vector<std::string> GetShapeInstances(const std::string& shape_name) const;
  std::string CreateShapeInstance(const std::string& shape_name,
                                  const std::string& instance_uri,
                                  const std::string& data_json);

 private:
  // Simple SPARQL BGP parser — extracts basic triple patterns from
  // SELECT ... WHERE { ?s ?p ?o . } queries.
  struct SparqlPattern {
    std::string subject;   // variable name or URI
    std::string predicate; // variable name or URI
    std::string object;    // variable name or URI/literal
  };
  std::vector<SparqlPattern> ParseBasicGraphPatterns(
      const std::string& sparql) const;

  std::string uuid_;
  std::string name_;
  std::vector<SignedTriple> triples_;

  // Shape registry: name → JSON definition
  const std::unordered_map<std::string, std::string>& shapes() const { return shapes_; }
  std::unordered_map<std::string, std::string> shapes_;

  // Persistence
  base::FilePath persistence_dir_;
  base::FilePath GetPersistencePath() const;
  void LoadFromDisk();
  void PersistToDisk();
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GRAPH_STORE_H_
