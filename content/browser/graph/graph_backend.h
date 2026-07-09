// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GraphBackend — the browser-process port of the §4/§5/§7 `Graph` algorithms of
// Spec 02 (Personal Linked Data Graphs). It is a faithful C++ port of
// living_web::Graph (standalone/graph_provider.h) onto the browser identity
// backend content::DIDKeyProvider; the two share the Chromium-independent cores
// (content/browser/graph/rdf_serialization.*, oxigraph_store.*, sparql_results.*)
// verbatim, so the standalone conformance harness and the browser never diverge
// on the bytes hashed, signed, or queried.
//
// One GraphBackend owns one in-memory Oxigraph store holding a graph's data
// triples and their reifier triples together (all in the default graph); the
// `graph://` content-address IRI is recomputed lazily after every mutation.
// Every fallible method returns bool and, on failure, sets last_error() to the
// DOMException name the renderer surface raises ("InvalidStateError",
// "NotAllowedError", "DataError", "NotSupportedError", "QuotaExceededError").

#ifndef CONTENT_BROWSER_GRAPH_GRAPH_BACKEND_H_
#define CONTENT_BROWSER_GRAPH_GRAPH_BACKEND_H_

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/graph/oxigraph_store.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph/sparql_results.h"

namespace content {

// ---- Spec 02 API value types ----------------------------------------------
//
// These mirror the shapes that live in standalone/graph_provider.h so the two
// ports stay conceptually identical. The RDF term types (living_web::Triple,
// ObjectTerm, LiteralValue, Reifier) are reused from the shared core.

// §3.3 GraphTrustLevel.
enum class GraphTrustLevel { kLocal, kExternal };

// §5.3 SnapshotFormat.
enum class SnapshotFormat { kNQuadsCanonical, kNQuads, kTurtle, kJsonLd };

// §5.3.4 supportedSnapshotFormats: the formats this user agent both produces and
// consumes. nquads-canonical / nquads / turtle are REQUIRED; jsonld is OPTIONAL
// and NOT advertised because RDF 1.2 triple terms (carried by every reifier)
// have no stable JSON-LD 1.2 (@triple) form in current tooling. GetAsSnapshot
// (§5.4) and FromSnapshot (§5.5) reject any format absent from this set with
// NotSupportedError. Backs GraphManager.supportedSnapshotFormats in blink.
inline std::vector<SnapshotFormat> SupportedSnapshotFormats() {
  return {SnapshotFormat::kNQuadsCanonical, SnapshotFormat::kNQuads,
          SnapshotFormat::kTurtle};
}

inline bool IsSnapshotFormatSupported(SnapshotFormat format) {
  for (SnapshotFormat f : SupportedSnapshotFormats()) {
    if (f == format)
      return true;
  }
  return false;
}

// §5.3 GraphSignBy.
enum class GraphSignBy { kAgent, kGraph, kBoth };

// §3.5 TripleQuery. Every supplied field combines with logical AND.
struct TripleQuery {
  std::optional<std::string> subject;
  std::optional<std::string> predicate;
  std::optional<living_web::ObjectTerm> object;
  std::optional<std::string> author;      // reifier prov://author
  std::optional<std::string> from_date;   // reifier prov://timestamp >= fromDate
  std::optional<std::string> until_date;  // reifier prov://timestamp <  untilDate
  std::optional<uint64_t> offset;
  std::optional<uint64_t> limit;
};

// §5.3 SnapshotProof.
struct SnapshotProof {
  std::string role;       // "agent" or "graph"
  std::string author;     // signing DID
  std::string method;     // verification method URI
  std::string signature;  // multibase-encoded
};

// §5.3 GraphSnapshot.
struct GraphSnapshot {
  std::string graph_iri;
  std::optional<std::string> graph_did;
  SnapshotFormat format = SnapshotFormat::kNQuadsCanonical;
  std::string timestamp;
  std::string data;
  std::vector<SnapshotProof> proofs;
};

// ---- GraphBackend (§3.3, §4, §5, §7) --------------------------------------

class GraphBackend {
 public:
  GraphBackend(DIDKeyProvider* identity,
               std::string id,
               GraphTrustLevel trust);

  GraphBackend(const GraphBackend&) = delete;
  GraphBackend& operator=(const GraphBackend&) = delete;

  ~GraphBackend();

  // ---- attributes (§3.3) ----
  const std::string& id() const { return id_; }
  const std::optional<std::string>& did() const { return did_; }
  const std::optional<std::string>& display_name() const {
    return display_name_;
  }
  GraphTrustLevel trust_level() const { return trust_level_; }
  bool dissolved() const { return dissolved_; }
  const std::string& last_error() const { return last_error_; }

  void set_did(std::string did) { did_ = std::move(did); }
  void set_display_name(std::string name) { display_name_ = std::move(name); }
  void set_on_triple_added(std::function<void(const living_web::Triple&)> cb) {
    on_triple_added_ = std::move(cb);
  }
  void set_on_triple_removed(std::function<void(const living_web::Triple&)> cb) {
    on_triple_removed_ = std::move(cb);
  }

  // The current snapshot IRI (§3.3, §5.2). Recomputed on first read after any
  // mutation; the cached value is invalidated by every write.
  bool GetIri(std::string* out);

  // ---- read / query operations (§4.2) ----

  // §4.2 queryTriples: data triples (never reifier triples) matching |query|,
  // sorted by reifier timestamp descending, ties broken by subject ascending.
  bool QueryTriples(const TripleQuery& query,
                    std::vector<living_web::Triple>* out);

  // §4.2 snapshot: the data triples currently in the graph, ordered by reifier
  // timestamp ascending. (For the addressable, signed form see GetAsSnapshot.)
  bool Snapshot(std::vector<living_web::Triple>* out);

  // §4.2 provenance: every reifier whose rdf:reifies target matches |triple|.
  bool Provenance(const living_web::Triple& triple,
                  std::vector<living_web::Reifier>* out);

  // §4.2 / §7.2 querySparql: evaluate a SPARQL 1.2 query over a dataset whose
  // default graph is this graph's full triple set and whose named graphs are the
  // supplied |named_graphs|, each keyed by its current IRI. The optional timeout
  // is enforced by the asynchronous browser overlay; this synchronous evaluation
  // runs the query to completion.
  living_web::SparqlResult QuerySparql(
      const std::string& sparql,
      const std::vector<GraphBackend*>& named_graphs,
      std::optional<uint64_t> timeout_ms = std::nullopt);

  // ---- mutation operations (§4.2, §4.3) ----

  // §4.2 addTriple: sign, reify, and commit one triple atomically.
  bool AddTriple(const living_web::Triple& triple,
                 living_web::Triple* out = nullptr);

  // §4.2 addTriples: the same algorithm as a single atomic batch. Steps 1-4 run
  // per triple (abort-all on any failure); the commit is one transaction; the
  // IRI advances once; one tripleadded fires per triple, in input order.
  bool AddTriples(const std::vector<living_web::Triple>& triples,
                  std::vector<living_web::Triple>* out = nullptr);

  // §4.2 removeTriple: delete the data triple together with every reifier that
  // reifies it, as one atomic SPARQL 1.2 Update. |*out_removed| reports whether
  // anything matched. A blank-node data-triple subject cannot be targeted by a
  // DELETE template and is treated as a no-op (see SPEC_COMPLIANCE amendment).
  bool RemoveTriple(const living_web::Triple& triple, bool* out_removed);

  // §5.4 getAsSnapshot: produce a transportable, signed snapshot.
  bool GetAsSnapshot(SnapshotFormat format,
                     GraphSignBy sign_by,
                     GraphSnapshot* out);

  // §4.3 dissolve: release the store and mark the graph dissolved. Idempotent;
  // every other operation rejects with "InvalidStateError" afterwards.
  bool Dissolve();

  // Loads pre-verified N-Quads directly into the store without re-signing. Used
  // by GraphBackendManager::FromSnapshot (§5.5 step 6). Returns false and sets
  // last_error() on a store error.
  bool LoadVerifiedNquads(const std::string& nquads);

  // Serialises the whole store (data triples + their reifier triples) as RDF 1.2
  // N-Quads. Used by the Spec 03 fork path (GroupBackendManager::ForkGroup,
  // §4.8 step 2) to copy a parent group's full, verifiable history into the
  // child before the parent identity is stripped. Returns false and sets
  // last_error() on a store error.
  bool DumpNquads(std::string* out);

 private:
  // The stable identifier the §3.2.1 signature binds to: the DID if set, else id.
  std::string GraphIdentifier() const { return did_.value_or(id_); }

  // §4.2 step 4: compute the §3.2.1 signature payload, sign it with signRaw, and
  // assemble the six-line reifier N-Quads document for |triple|. |label| is the
  // reifier blank node (unique within a single load call). Sets last_error() on
  // a signing failure (a locked/unknown credential -> "InvalidStateError").
  bool BuildReifierDoc(const living_web::Triple& triple,
                       const std::string& label,
                       const DIDKeyPair* active,
                       std::string* out);

  // §5.4 step 5: sign |payload32| with the active credential and fill a proof.
  bool SignProof(const DIDKeyPair* active,
                 const std::string& payload32,
                 const std::string& role,
                 SnapshotProof* out);

  static std::string TermToNode(const living_web::SparqlTerm& t);
  static living_web::ObjectTerm TermToObject(const living_web::SparqlTerm& t);

  // The shared WHERE prefix binding a reifier to a data triple `?s ?p ?o`.
  static std::string ReifierWherePrefix(bool with_author);

  std::string BuildFilters(const TripleQuery& q) const;

  bool RunSelectTriples(const std::string& q,
                        std::vector<living_web::Triple>* out);

  raw_ptr<DIDKeyProvider> identity_;  // Not owned.
  living_web::OxigraphStore store_;
  std::string id_;
  std::optional<std::string> did_;
  std::optional<std::string> display_name_;
  GraphTrustLevel trust_level_;
  bool dissolved_ = false;
  std::optional<std::string> cached_iri_;
  std::string last_error_;
  std::function<void(const living_web::Triple&)> on_triple_added_;
  std::function<void(const living_web::Triple&)> on_triple_removed_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GRAPH_BACKEND_H_
