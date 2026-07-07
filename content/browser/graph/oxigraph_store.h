// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// C++ RAII wrapper over the Oxigraph FFI (third_party/oxigraph_ffi/include/owg.h)
// for the Living Web graph substrate (Spec 02 — Personal Linked Data Graphs).
//
// This is the single owner of the FFI boundary: it converts owned `OwgBuf`
// results into std::string (freeing them), surfaces `owg_last_error` as C++
// error strings, and manages store-handle lifetime. Everything above this layer
// (the graph service, the standalone harness) speaks std::string and never
// touches raw ABI pointers. It provides exactly the three Spec 02 capabilities —
// an RDF 1.2 quad store, rdfc-1.0 canonicalisation, and holonic SPARQL — none of
// which is reimplemented in C++.

#ifndef CONTENT_BROWSER_GRAPH_OXIGRAPH_STORE_H_
#define CONTENT_BROWSER_GRAPH_OXIGRAPH_STORE_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace living_web {

// RDF serialisation format (mirrors OwgFormat in owg.h).
enum class RdfFormat : int {
  kNQuads = 0,
  kNTriples = 1,
  kTurtle = 2,
  kTriG = 3,
};

// Blank-node hashing function for rdfc-1.0 (mirrors OwgHash in owg.h).
enum class CanonHash : int {
  kSha256 = 0,
  kSha384 = 1,
};

// Kind of a SPARQL result (mirrors OwgQueryKind in owg.h).
enum class SparqlResultKind : int {
  kSolutions = 0,  // SELECT  -> SPARQL 1.1 JSON Results
  kBoolean = 1,    // ASK     -> SPARQL 1.1 JSON Results (boolean)
  kGraph = 2,      // CONSTRUCT/DESCRIBE -> RDF 1.2 N-Triples
};

// A named graph contributed to a holonic SPARQL dataset (§7.2): its `graph://`
// IRI and the RDF 1.2 N-Quads of its triples.
struct NamedGraphInput {
  std::string iri;
  std::string nquads;
};

// The outcome of a SPARQL evaluation.
struct SparqlResult {
  bool ok = false;
  std::string error;
  SparqlResultKind kind = SparqlResultKind::kSolutions;
  std::string payload;  // JSON results, or N-Triples for CONSTRUCT/DESCRIBE
};

// Owns an Oxigraph store handle.
class OxigraphStore {
 public:
  // Creates a fresh in-memory store. Check ok() before use.
  OxigraphStore();
  // Opens (creating if absent) a persistent RocksDB store at |path|.
  explicit OxigraphStore(const std::string& path);
  ~OxigraphStore();

  OxigraphStore(const OxigraphStore&) = delete;
  OxigraphStore& operator=(const OxigraphStore&) = delete;
  OxigraphStore(OxigraphStore&& other) noexcept;
  OxigraphStore& operator=(OxigraphStore&& other) noexcept;

  bool ok() const { return handle_ != nullptr; }
  const std::string& last_error() const { return last_error_; }

  // Loads RDF 1.2 N-Quads into the default graph (atomic). Returns false on a
  // parse/commit error (see last_error()).
  bool LoadNquads(const std::string& nquads);

  // Removes the quads described by |nquads|; returns the number removed, or -1
  // on error.
  int64_t RemoveNquads(const std::string& nquads);

  // Empties the store.
  bool Clear();

  // Number of quads in the store, or -1 on error.
  int64_t Len();

  // Serialises the whole store as RDF 1.2 N-Quads (non-canonical order).
  bool DumpNquads(std::string* out);

  // Serialises the store's default graph in |format|.
  bool Serialize(RdfFormat format, std::string* out);

  // Evaluates a SPARQL 1.2 query with |named_graphs| loaded as named graphs.
  SparqlResult Query(const std::string& sparql,
                     const std::vector<NamedGraphInput>& named_graphs);

  // Applies a SPARQL 1.2 Update to the store's default graph as one atomic
  // transaction. Used by removeTriple to delete a data triple together with its
  // blank-node reifier (bound as a variable). Returns false on error.
  bool Update(const std::string& sparql);

  // ---- stateless helpers (no store handle required) ----

  // Computes the Spec 02 §5.2 `graph://<hash>` content-address IRI of an RDF 1.2
  // N-Quads document: "graph://" + lowercase-hex SHA-256 of the rdfc-1.0
  // canonical N-Quads bytes. Returns false on error.
  static bool GraphIri(const std::string& nquads,
                       std::string* out,
                       std::string* error);

  // Canonicalises an RDF 1.2 N-Quads document with rdfc-1.0, returning the exact
  // canonical UTF-8 bytes Spec 02 §5.2 hashes. Returns false on error.
  static bool Canonicalize(const std::string& nquads,
                           CanonHash hash,
                           std::string* out,
                           std::string* error);

  // Converts an RDF 1.2 document between syntaxes. Returns false on error.
  static bool Convert(const std::string& data,
                      RdfFormat in_format,
                      RdfFormat out_format,
                      std::string* out,
                      std::string* error);

 private:
  void* handle_ = nullptr;
  std::string last_error_;
};

}  // namespace living_web

#endif  // CONTENT_BROWSER_GRAPH_OXIGRAPH_STORE_H_
