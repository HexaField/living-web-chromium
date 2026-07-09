// Living Web Standalone Library
// Personal Linked Data Graphs (Spec 02) — the evolving-graph runtime.
//
// This header-only module implements the §4/§5/§7 `Graph` and `GraphManager`
// algorithms of Spec 02 on top of the Chromium-independent cores:
//   * content/browser/graph/rdf_serialization.*  — RDF 1.2 term syntax + the
//     §3.2.1 signature pre-image;
//   * content/browser/graph/oxigraph_store.*      — the RDF 1.2 quad store,
//     rdfc-1.0 canonicalisation, the `graph://` content address, and SPARQL 1.2
//     (query + update), all delegated to Oxigraph via the FFI;
//   * content/browser/graph/sparql_results.*      — SPARQL 1.1 JSON Results decode.
//
// The identical cores back the browser-process graph service, so the standalone
// harness and the browser never diverge on the bytes hashed, signed, or queried.
// Nothing here is a stub: every §4/§5/§7 algorithm is implemented in full.
#ifndef LIVING_WEB_GRAPH_PROVIDER_H_
#define LIVING_WEB_GRAPH_PROVIDER_H_

#include "types.h"
#include "base_shim.h"
#include "crypto_sha2.h"
#include "did_key_provider.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph/oxigraph_store.h"
#include "content/browser/graph/sparql_results.h"
#include "content/browser/did/did_key_codec.h"
#include "third_party/ed25519/ed25519.h"

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <functional>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace living_web {

// ---- Spec 02 API value types ----------------------------------------------

// §3.3 GraphTrustLevel.
enum class GraphTrustLevel { kLocal, kExternal };

// §5.3 SnapshotFormat.
enum class SnapshotFormat { kNQuadsCanonical, kNQuads, kTurtle, kJsonLd };

// §5.3 SnapshotFormat enum tokens (the wire/IDL form).
inline const char* SnapshotFormatToken(SnapshotFormat f) {
  switch (f) {
    case SnapshotFormat::kNQuadsCanonical:
      return "nquads-canonical";
    case SnapshotFormat::kNQuads:
      return "nquads";
    case SnapshotFormat::kTurtle:
      return "turtle";
    case SnapshotFormat::kJsonLd:
      return "jsonld";
  }
  return "";
}

// §5.3.4 supportedSnapshotFormats: the formats this user agent both produces and
// consumes. nquads-canonical / nquads / turtle are REQUIRED; jsonld is OPTIONAL
// and NOT advertised here because RDF 1.2 triple terms (carried by every
// reifier) have no stable JSON-LD 1.2 (@triple) form in current tooling.
// getAsSnapshot (§5.4) and fromSnapshot (§5.5) reject any format absent from
// this set with NotSupportedError. Backs GraphManager.supportedSnapshotFormats.
inline std::vector<SnapshotFormat> SupportedSnapshotFormats() {
  return {SnapshotFormat::kNQuadsCanonical, SnapshotFormat::kNQuads,
          SnapshotFormat::kTurtle};
}

// True iff |format| is advertised by SupportedSnapshotFormats().
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
  std::optional<ObjectTerm> object;
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

// ---- internal SPARQL-text helpers -----------------------------------------

namespace graph_detail {

// Current time as an RFC 3339 UTC string (§3.2.3).
inline std::string NowRfc3339() {
  std::time_t now = std::time(nullptr);
  std::tm* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

// Escapes a string for a double-quoted N-Triples/SPARQL string literal.
inline std::string EscapeDq(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char b[8];
          std::snprintf(b, sizeof(b), "\\u%04X", c);
          out += b;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

// Escapes an IRI for a SPARQL IRIREF (`<...>`): every character disallowed in an
// IRIREF is emitted as a UCHAR (`\uXXXX`) escape, which SPARQL parses back to the
// same code point. This keeps the reference well-formed and blocks query
// injection through a caller-supplied IRI.
inline std::string SparqlIriEscape(const std::string& iri) {
  std::string out;
  out.reserve(iri.size());
  for (unsigned char c : iri) {
    if (c < 0x20 || c == '<' || c == '>' || c == '"' || c == '{' || c == '}' ||
        c == '|' || c == '^' || c == '`' || c == '\\' || c == ' ') {
      char b[8];
      std::snprintf(b, sizeof(b), "\\u%04X", c);
      out += b;
    } else {
      out += static_cast<char>(c);
    }
  }
  return out;
}

inline std::string SparqlIriRef(const std::string& iri) {
  return "<" + SparqlIriEscape(iri) + ">";
}

inline std::string SparqlSubject(const std::string& s) {
  return IsBlankNode(s) ? s : SparqlIriRef(s);
}

inline std::string SparqlObject(const ObjectTerm& o) {
  if (o.is_literal())
    return SerializeLiteral(*o.literal);
  return IsBlankNode(o.iri_or_bnode) ? o.iri_or_bnode
                                     : SparqlIriRef(o.iri_or_bnode);
}

// An RDF 1.2 triple term `<<( s p o )>>` with every IRI escaped for SPARQL.
inline std::string SparqlTripleTerm(const Triple& t) {
  return "<<( " + SparqlSubject(t.subject) + " " + SparqlIriRef(t.predicate) +
         " " + SparqlObject(t.object) + " )>>";
}

// A concrete data-triple line `<s> <p> <o> .` with every IRI escaped for SPARQL.
inline std::string SparqlDataLine(const Triple& t) {
  return SparqlSubject(t.subject) + " " + SparqlIriRef(t.predicate) + " " +
         SparqlObject(t.object) + " .";
}

}  // namespace graph_detail

// ---- Graph (§3.3, §4, §5, §7) ---------------------------------------------

// An evolving graph: the live, mutable object of Spec 02. Data triples and their
// reifier triples live together in one in-memory Oxigraph store (all in the
// default graph); the `graph://` IRI is recomputed lazily after every mutation.
//
// Every fallible method returns bool and, on failure, sets last_error() to the
// DOMException name the browser surface raises ("InvalidStateError",
// "NotAllowedError", "DataError", "NotSupportedError", "QuotaExceededError").
class Graph {
 public:
  Graph(DIDKeyProvider* identity, std::string id, GraphTrustLevel trust)
      : identity_(identity), id_(std::move(id)), trust_level_(trust) {}

  Graph(const Graph&) = delete;
  Graph& operator=(const Graph&) = delete;

  // ---- attributes (§3.3) ----
  const std::string& id() const { return id_; }
  const std::optional<std::string>& did() const { return did_; }
  const std::optional<std::string>& display_name() const {
    return display_name_;
  }
  GraphTrustLevel trust_level() const { return trust_level_; }
  bool dissolved() const { return dissolved_; }
  const std::string& last_error() const { return last_error_; }

  void set_display_name(std::string name) { display_name_ = std::move(name); }
  void set_on_triple_added(std::function<void(const Triple&)> cb) {
    on_triple_added_ = std::move(cb);
  }
  void set_on_triple_removed(std::function<void(const Triple&)> cb) {
    on_triple_removed_ = std::move(cb);
  }

  // The current snapshot IRI (§3.3, §5.2). Recomputed on first read after any
  // mutation; the cached value is invalidated by every write.
  bool GetIri(std::string* out) {
    if (dissolved_) {
      last_error_ = "InvalidStateError";
      return false;
    }
    if (!cached_iri_) {
      std::string dump;
      if (!store_.DumpNquads(&dump)) {
        last_error_ = store_.last_error();
        return false;
      }
      std::string iri, err;
      if (!OxigraphStore::GraphIri(dump, &iri, &err)) {
        last_error_ = err;
        return false;
      }
      cached_iri_ = iri;
    }
    *out = *cached_iri_;
    return true;
  }

  // ---- read / query operations (§4.2) ----

  // §4.2 queryTriples: data triples (never reifier triples) matching |query|,
  // sorted by reifier timestamp descending, ties broken by subject ascending.
  bool QueryTriples(const TripleQuery& query, std::vector<Triple>* out) {
    if (dissolved_) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::string q = "SELECT ?s ?p ?o ?author ?ts WHERE {\n" +
                    ReifierWherePrefix(/*with_author=*/true) + BuildFilters(query) +
                    "}\nORDER BY DESC(?ts) ASC(?s)";
    if (query.offset)
      q += "\nOFFSET " + std::to_string(*query.offset);
    if (query.limit)
      q += "\nLIMIT " + std::to_string(*query.limit);
    return RunSelectTriples(q, out);
  }

  // §4.2 snapshot: the data triples currently in the graph, ordered by reifier
  // timestamp ascending. (For the addressable, signed form see GetAsSnapshot.)
  bool Snapshot(std::vector<Triple>* out) {
    if (dissolved_) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::string q = "SELECT ?s ?p ?o ?ts WHERE {\n"
                    "?r <" + std::string(kRdfReifies) + "> <<( ?s ?p ?o )>> .\n"
                    "?r <" + std::string(kProvTimestamp) + "> ?ts .\n"
                    "}\nORDER BY ASC(?ts) ASC(?s)";
    return RunSelectTriples(q, out);
  }

  // §4.2 provenance: every reifier whose rdf:reifies target matches |triple|.
  bool Provenance(const Triple& triple, std::vector<Reifier>* out) {
    if (dissolved_) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::string q =
        "SELECT ?r ?author ?ts ?method ?sig WHERE {\n"
        "?r <" + std::string(kRdfReifies) + "> " +
        graph_detail::SparqlTripleTerm(triple) + " .\n"
        "?r <" + std::string(kProvAuthor) + "> ?author .\n"
        "?r <" + std::string(kProvTimestamp) + "> ?ts .\n"
        "?r <" + std::string(kProvMethod) + "> ?method .\n"
        "?r <" + std::string(kProvSignature) + "> ?sig .\n"
        "}";
    SparqlResult r = store_.Query(q, {});
    if (!r.ok) {
      last_error_ = r.error;
      return false;
    }
    SparqlSelect sel;
    std::string err;
    if (!DecodeSparqlSelect(r.payload, &sel, &err)) {
      last_error_ = err;
      return false;
    }
    out->clear();
    for (const auto& sol : sel.solutions) {
      const SparqlTerm* rr = sol.Get("r");
      const SparqlTerm* author = sol.Get("author");
      const SparqlTerm* ts = sol.Get("ts");
      const SparqlTerm* method = sol.Get("method");
      const SparqlTerm* sig = sol.Get("sig");
      if (!rr || !author || !ts || !method || !sig)
        continue;
      Reifier reif;
      reif.id = TermToNode(*rr);
      reif.triple = triple;
      reif.author = author->value;
      reif.timestamp = ts->value;
      reif.method = method->value;
      reif.signature = sig->value;
      out->push_back(std::move(reif));
    }
    return true;
  }

  // §4.2 / §7.2 querySparql: evaluate a SPARQL 1.2 query over a dataset whose
  // default graph is this graph's full triple set and whose named graphs are the
  // supplied |named_graphs|, each keyed by its current IRI. The optional timeout
  // is enforced by the asynchronous browser overlay; the synchronous harness
  // runs the query to completion.
  SparqlResult QuerySparql(const std::string& sparql,
                           const std::vector<Graph*>& named_graphs,
                           std::optional<uint64_t> /*timeout_ms*/ = std::nullopt) {
    SparqlResult r;
    if (dissolved_) {
      r.ok = false;
      r.error = "InvalidStateError";
      return r;
    }
    std::vector<NamedGraphInput> inputs;
    inputs.reserve(named_graphs.size());
    for (Graph* g : named_graphs) {
      if (!g)
        continue;
      std::string iri;
      if (!g->GetIri(&iri)) {
        r.ok = false;
        r.error = g->last_error_;
        return r;
      }
      std::string nq;
      if (!g->store_.DumpNquads(&nq)) {
        r.ok = false;
        r.error = g->store_.last_error();
        return r;
      }
      inputs.push_back({iri, nq});
    }
    return store_.Query(sparql, inputs);
  }

  // ---- mutation operations (§4.2, §4.3) ----

  // §4.2 addTriple: sign, reify, and commit one triple atomically.
  bool AddTriple(const Triple& triple, Triple* out = nullptr) {
    if (dissolved_) {  // step 1
      last_error_ = "InvalidStateError";
      return false;
    }
    const DIDKeyPair* active = identity_->GetActiveCredential();  // step 2
    if (!active) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::string doc;  // steps 3-4
    if (!BuildReifierDoc(triple, "_:r", active, &doc))
      return false;
    if (!store_.LoadNquads(doc)) {  // step 5
      last_error_ = store_.last_error();
      return false;
    }
    cached_iri_.reset();  // step 6
    if (on_triple_added_)  // step 7
      on_triple_added_(triple);
    if (out)  // step 8
      *out = triple;
    return true;
  }

  // §4.2 addTriples: the same algorithm as a single atomic batch. Steps 1-4 run
  // per triple (abort-all on any failure); the commit is one transaction; the IRI
  // advances once; one tripleadded fires per triple, in input order.
  bool AddTriples(const std::vector<Triple>& triples,
                  std::vector<Triple>* out = nullptr) {
    if (dissolved_) {
      last_error_ = "InvalidStateError";
      return false;
    }
    const DIDKeyPair* active = identity_->GetActiveCredential();
    if (!active) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::string doc;
    for (size_t i = 0; i < triples.size(); ++i) {
      std::string one;
      // Distinct reifier labels are REQUIRED within a single load call.
      if (!BuildReifierDoc(triples[i], "_:r" + std::to_string(i), active, &one))
        return false;
      doc += one;
    }
    if (!triples.empty() && !store_.LoadNquads(doc)) {
      last_error_ = store_.last_error();
      return false;
    }
    cached_iri_.reset();
    if (on_triple_added_)
      for (const auto& t : triples)
        on_triple_added_(t);
    if (out)
      *out = triples;
    return true;
  }

  // §4.2 removeTriple: delete the data triple together with every reifier that
  // reifies it, as one atomic SPARQL 1.2 Update. |*out_removed| reports whether
  // anything matched. A blank-node data-triple subject cannot be targeted by a
  // DELETE template and is treated as a no-op (see SPEC_COMPLIANCE amendment).
  bool RemoveTriple(const Triple& triple, bool* out_removed) {
    if (dissolved_) {
      last_error_ = "InvalidStateError";
      return false;
    }
    *out_removed = false;
    if (IsBlankNode(triple.subject))
      return true;
    std::string upd =
        "DELETE {\n" + graph_detail::SparqlDataLine(triple) +
        "\n?r ?rp ?rv .\n} WHERE {\n"
        "?r <" + std::string(kRdfReifies) + "> " +
        graph_detail::SparqlTripleTerm(triple) + " .\n"
        "?r ?rp ?rv .\n}";
    int64_t before = store_.Len();
    if (!store_.Update(upd)) {
      last_error_ = store_.last_error();
      return false;
    }
    int64_t after = store_.Len();
    if (before >= 0 && after >= 0 && after < before) {
      *out_removed = true;
      cached_iri_.reset();
      if (on_triple_removed_)
        on_triple_removed_(triple);
    }
    return true;
  }

  // §5.4 getAsSnapshot: produce a transportable, signed snapshot.
  bool GetAsSnapshot(SnapshotFormat format,
                     GraphSignBy sign_by,
                     GraphSnapshot* out) {
    if (dissolved_) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::string dump;
    if (!store_.DumpNquads(&dump)) {  // step 1
      last_error_ = store_.last_error();
      return false;
    }
    std::string graph_iri, err;
    if (!OxigraphStore::GraphIri(dump, &graph_iri, &err)) {  // step 2
      last_error_ = err;
      return false;
    }
    // step 3: format check (§5.3.4) then serialise the full triple set.
    if (!IsSnapshotFormatSupported(format)) {
      last_error_ = "NotSupportedError";
      return false;
    }
    std::string data;
    switch (format) {
      case SnapshotFormat::kNQuadsCanonical:
        if (!OxigraphStore::Canonicalize(dump, CanonHash::kSha256, &data, &err)) {
          last_error_ = err;
          return false;
        }
        break;
      case SnapshotFormat::kNQuads:
        data = dump;
        break;
      case SnapshotFormat::kTurtle:
        if (!store_.Serialize(RdfFormat::kTurtle, &data)) {
          last_error_ = store_.last_error();
          return false;
        }
        break;
      case SnapshotFormat::kJsonLd:
        last_error_ = "NotSupportedError";
        return false;
    }
    std::string timestamp = graph_detail::NowRfc3339();  // step 4
    // step 5: proofPayload = SHA-256(graphIri || "|" || timestamp).
    std::string payload = crypto::SHA256HashString(graph_iri + "|" + timestamp);
    const DIDKeyPair* active = identity_->GetActiveCredential();
    bool want_agent =
        sign_by == GraphSignBy::kAgent || sign_by == GraphSignBy::kBoth;
    bool want_graph =
        sign_by == GraphSignBy::kGraph || sign_by == GraphSignBy::kBoth;
    if ((want_agent || want_graph) && !active) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::vector<SnapshotProof> proofs;
    if (want_agent) {
      SnapshotProof p;
      if (!SignProof(active, payload, "agent", &p))
        return false;
      proofs.push_back(std::move(p));
    }
    if (want_graph) {
      if (!did_ || active->did != *did_) {
        last_error_ = "NotAllowedError";
        return false;
      }
      SnapshotProof p;
      if (!SignProof(active, payload, "graph", &p))
        return false;
      proofs.push_back(std::move(p));
    }
    out->graph_iri = graph_iri;  // step 6
    out->graph_did = did_;
    out->format = format;
    out->timestamp = timestamp;
    out->data = std::move(data);
    out->proofs = std::move(proofs);
    return true;
  }

  // §4.3 dissolve: release the store and mark the graph dissolved. Idempotent;
  // every other operation rejects with "InvalidStateError" afterwards.
  bool Dissolve() {
    if (dissolved_)
      return true;
    store_.Clear();
    dissolved_ = true;
    cached_iri_.reset();
    on_triple_added_ = nullptr;
    on_triple_removed_ = nullptr;
    return true;
  }

 private:
  friend class GraphManager;
  // Spec 03 §4.2/§4.8: the group service binds a did:graph identifier onto a
  // host graph (Groupify) and forks a groupified graph by copying its store and
  // stripping the parent identity. Both operations set did_ and read/replace
  // store_ directly on graphs the caller already owns.
  friend class GroupManager;

  // The stable identifier the §3.2.1 signature binds to: the DID if set, else id.
  std::string GraphIdentifier() const { return did_.value_or(id_); }

  // §4.2 step 4: compute the §3.2.1 signature payload, sign it with signRaw, and
  // assemble the six-line reifier N-Quads document for |triple|. |label| is the
  // reifier blank node (unique within a single load call). Sets last_error_ on a
  // signing failure (a locked/unknown credential -> "InvalidStateError").
  bool BuildReifierDoc(const Triple& triple,
                       const std::string& label,
                       const DIDKeyPair* active,
                       std::string* out) {
    std::string timestamp = graph_detail::NowRfc3339();
    std::string preimage =
        BuildSignaturePreimage(triple, timestamp, GraphIdentifier());
    std::string payload = crypto::SHA256HashString(preimage);
    auto sig = identity_->SignRaw(
        active->id, std::vector<uint8_t>(payload.begin(), payload.end()));
    if (!sig) {
      last_error_ = "InvalidStateError";
      return false;
    }
    std::string sig_mb = did_key::MultibaseEncode(*sig);
    std::string method =
        active->did + "#" + *did_key::Ed25519PublicKeyMultibase(active->public_key);
    *out = BuildTripleWithReifierNquads(triple, label, active->did, timestamp,
                                        method, sig_mb);
    return true;
  }

  // §5.4 step 5: sign |payload32| with the active credential and fill a proof.
  bool SignProof(const DIDKeyPair* active,
                 const std::string& payload32,
                 const std::string& role,
                 SnapshotProof* out) {
    auto sig = identity_->SignRaw(
        active->id,
        std::vector<uint8_t>(payload32.begin(), payload32.end()));
    if (!sig) {
      last_error_ = "InvalidStateError";
      return false;
    }
    out->role = role;
    out->author = active->did;
    out->method =
        active->did + "#" + *did_key::Ed25519PublicKeyMultibase(active->public_key);
    out->signature = did_key::MultibaseEncode(*sig);
    return true;
  }

  static std::string TermToNode(const SparqlTerm& t) {
    if (t.type == SparqlTermType::kBlankNode)
      return "_:" + t.value;
    return t.value;
  }

  static ObjectTerm TermToObject(const SparqlTerm& t) {
    switch (t.type) {
      case SparqlTermType::kBlankNode:
        return ObjectTerm::Blank("_:" + t.value);
      case SparqlTermType::kLiteral: {
        LiteralValue lv;
        lv.lexical = t.value;
        lv.datatype = t.datatype.value_or(kXsdString);
        if (t.language)
          lv.language = t.language;
        return ObjectTerm::Literal(lv);
      }
      case SparqlTermType::kTriple:  // never the object of a data triple
      case SparqlTermType::kUri:
      default:
        return ObjectTerm::Iri(t.value);
    }
  }

  // The shared WHERE prefix binding a reifier to a data triple `?s ?p ?o`.
  static std::string ReifierWherePrefix(bool with_author) {
    std::string w = "?r <" + std::string(kRdfReifies) + "> <<( ?s ?p ?o )>> .\n";
    if (with_author)
      w += "?r <" + std::string(kProvAuthor) + "> ?author .\n";
    w += "?r <" + std::string(kProvTimestamp) + "> ?ts .\n";
    return w;
  }

  std::string BuildFilters(const TripleQuery& q) const {
    std::string f;
    if (q.subject) {
      if (IsBlankNode(*q.subject))
        f += "FILTER(STR(?s) = \"" + graph_detail::EscapeDq(q.subject->substr(2)) +
             "\")\n";
      else
        f += "FILTER(?s = " + graph_detail::SparqlIriRef(*q.subject) + ")\n";
    }
    if (q.predicate)
      f += "FILTER(?p = " + graph_detail::SparqlIriRef(*q.predicate) + ")\n";
    if (q.object) {
      const ObjectTerm& o = *q.object;
      if (o.is_literal())
        f += "FILTER(?o = " + SerializeLiteral(*o.literal) + ")\n";
      else if (IsBlankNode(o.iri_or_bnode))
        f += "FILTER(STR(?o) = \"" +
             graph_detail::EscapeDq(o.iri_or_bnode.substr(2)) + "\")\n";
      else
        f += "FILTER(?o = " + graph_detail::SparqlIriRef(o.iri_or_bnode) + ")\n";
    }
    if (q.author)
      f += "FILTER(?author = " + graph_detail::SparqlIriRef(*q.author) + ")\n";
    if (q.from_date)
      f += "FILTER(?ts >= \"" + graph_detail::EscapeDq(*q.from_date) + "\"^^<" +
           std::string(kXsdDateTime) + ">)\n";
    if (q.until_date)
      f += "FILTER(?ts < \"" + graph_detail::EscapeDq(*q.until_date) + "\"^^<" +
           std::string(kXsdDateTime) + ">)\n";
    return f;
  }

  bool RunSelectTriples(const std::string& q, std::vector<Triple>* out) {
    SparqlResult r = store_.Query(q, {});
    if (!r.ok) {
      last_error_ = r.error;
      return false;
    }
    SparqlSelect sel;
    std::string err;
    if (!DecodeSparqlSelect(r.payload, &sel, &err)) {
      last_error_ = err;
      return false;
    }
    out->clear();
    for (const auto& sol : sel.solutions) {
      const SparqlTerm* s = sol.Get("s");
      const SparqlTerm* p = sol.Get("p");
      const SparqlTerm* o = sol.Get("o");
      if (!s || !p || !o)
        continue;
      Triple t;
      t.subject = TermToNode(*s);
      t.predicate = p->value;
      t.object = TermToObject(*o);
      out->push_back(std::move(t));
    }
    return true;
  }

  DIDKeyProvider* identity_;
  OxigraphStore store_;
  std::string id_;
  std::optional<std::string> did_;
  std::optional<std::string> display_name_;
  GraphTrustLevel trust_level_;
  bool dissolved_ = false;
  mutable std::optional<std::string> cached_iri_;
  std::string last_error_;
  std::function<void(const Triple&)> on_triple_added_;
  std::function<void(const Triple&)> on_triple_removed_;
};

// ---- GraphManager (§3.4, §4.1, §5.5) --------------------------------------

// navigator.graph: the entry point for creating and materialising graphs. Holds
// a non-owning pointer to the identity provider used to sign triples/snapshots.
class GraphManager {
 public:
  explicit GraphManager(DIDKeyProvider* identity) : identity_(identity) {}

  // §3.4 / §5.3.4 supportedSnapshotFormats (static, UA-wide capability). Mirrors
  // the free function so callers can reach it through the manager, as script does
  // via GraphManager.supportedSnapshotFormats.
  static std::vector<SnapshotFormat> supportedSnapshotFormats() {
    return SupportedSnapshotFormats();
  }

  // §4.1 create: a fresh, empty, local graph. Its IRI is the empty-set IRI until
  // the first write; its did is null; its trustLevel is "local".
  std::unique_ptr<Graph> Create(
      std::optional<std::string> display_name = std::nullopt) {
    std::string id =
        "urn:graph:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
    auto g = std::make_unique<Graph>(identity_, id, GraphTrustLevel::kLocal);
    if (display_name)
      g->set_display_name(*display_name);
    return g;
  }

  // §5.5 fromSnapshot: verify and materialise a graph from a snapshot. On failure
  // returns nullptr and sets |*error| to the DOMException name.
  std::unique_ptr<Graph> FromSnapshot(const GraphSnapshot& snap,
                                      GraphTrustLevel trust,
                                      std::string* error) {
    auto fail = [&](const char* name) -> std::unique_ptr<Graph> {
      if (error)
        *error = name;
      return nullptr;
    };

    // Step 1: format check (§5.3.4). Any format absent from the advertised set
    // -> NotSupportedError. jsonld is defined but not advertised here, because
    // RDF 1.2 triple terms have no stable JSON-LD 1.2 (@triple) form in current
    // tooling; nquads-canonical / nquads / turtle are REQUIRED and accepted.
    if (!IsSnapshotFormatSupported(snap.format))
      return fail("NotSupportedError");

    // §9.7: bound snapshot.data before any parsing (DoS defence).
    constexpr size_t kMaxSnapshotBytes = 100u * 1024u * 1024u;
    if (snap.data.size() > kMaxSnapshotBytes)
      return fail("QuotaExceededError");

    // Step 2: proof check. Empty proofs, or any failing proof, -> DataError.
    if (snap.proofs.empty())
      return fail("DataError");
    std::string payload =
        crypto::SHA256HashString(snap.graph_iri + "|" + snap.timestamp);
    for (const auto& pr : snap.proofs) {
      auto pub = did_key::ParseDidKeyEd25519(pr.author);
      auto sig = did_key::MultibaseDecode(pr.signature);
      if (!pub || pub->size() != 32 || !sig || sig->size() != 64)
        return fail("DataError");
      if (ed25519_verify(sig->data(),
                         reinterpret_cast<const uint8_t*>(payload.data()),
                         payload.size(), pub->data()) != 1)
        return fail("DataError");
    }

    // Step 3: parse snapshot.data into N-Quads for loading.
    std::string nquads, err;
    switch (snap.format) {
      case SnapshotFormat::kNQuadsCanonical:
      case SnapshotFormat::kNQuads:
        nquads = snap.data;
        break;
      case SnapshotFormat::kTurtle:
        if (!OxigraphStore::Convert(snap.data, RdfFormat::kTurtle,
                                    RdfFormat::kNQuads, &nquads, &err))
          return fail("DataError");
        break;
      case SnapshotFormat::kJsonLd:
        return fail("NotSupportedError");  // unreachable (rejected at step 1)
    }

    // Step 4: hash check. Recanonicalise + hash and compare to the claimed IRI.
    std::string expected;
    if (!OxigraphStore::GraphIri(nquads, &expected, &err))
      return fail("DataError");
    if (expected != snap.graph_iri)
      return fail("DataError");

    // Step 5: allocate a fresh id + store.
    std::string id =
        "urn:graph:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
    auto graph = std::make_unique<Graph>(identity_, id, trust);

    // Step 6: insert every triple without re-signing.
    if (!graph->store_.LoadNquads(nquads)) {
      if (error)
        *error = graph->store_.last_error();
      return nullptr;
    }

    // Step 7: DID attachment from the snapshot's authoritative graphDid.
    if (snap.graph_did)
      graph->did_ = *snap.graph_did;

    // Step 8: trust level (set at construction).

    // Step 9: verify invariant (defensive) — dissolve + DataError on mismatch.
    std::string iri;
    if (!graph->GetIri(&iri) || iri != snap.graph_iri) {
      graph->Dissolve();
      return fail("DataError");
    }
    return graph;  // Step 10
  }

  // §5.5 with the default "external" trust level.
  std::unique_ptr<Graph> FromSnapshot(const GraphSnapshot& snap,
                                      std::string* error) {
    return FromSnapshot(snap, GraphTrustLevel::kExternal, error);
  }

 private:
  DIDKeyProvider* identity_;
};

}  // namespace living_web

#endif  // LIVING_WEB_GRAPH_PROVIDER_H_
