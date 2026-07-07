// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/graph_backend.h"

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>

#include "content/browser/did/did_key_codec.h"
#include "crypto/sha2.h"

namespace content {

namespace {

// ---- internal SPARQL-text helpers -----------------------------------------
//
// Ported verbatim from graph_provider.h's graph_detail namespace so the SPARQL
// text (and thus the query semantics) match the standalone harness exactly.

using living_web::IsBlankNode;
using living_web::kXsdDateTime;
using living_web::ObjectTerm;
using living_web::SerializeLiteral;
using living_web::Triple;

// Current time as an RFC 3339 UTC string (§3.2.3).
std::string NowRfc3339() {
  std::time_t now = std::time(nullptr);
  std::tm* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

// Escapes a string for a double-quoted N-Triples/SPARQL string literal.
std::string EscapeDq(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
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
std::string SparqlIriEscape(const std::string& iri) {
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

std::string SparqlIriRef(const std::string& iri) {
  return "<" + SparqlIriEscape(iri) + ">";
}

std::string SparqlSubject(const std::string& s) {
  return IsBlankNode(s) ? s : SparqlIriRef(s);
}

std::string SparqlObject(const ObjectTerm& o) {
  if (o.is_literal())
    return SerializeLiteral(*o.literal);
  return IsBlankNode(o.iri_or_bnode) ? o.iri_or_bnode
                                     : SparqlIriRef(o.iri_or_bnode);
}

// An RDF 1.2 triple term `<<( s p o )>>` with every IRI escaped for SPARQL.
std::string SparqlTripleTerm(const Triple& t) {
  return "<<( " + SparqlSubject(t.subject) + " " + SparqlIriRef(t.predicate) +
         " " + SparqlObject(t.object) + " )>>";
}

// A concrete data-triple line `<s> <p> <o> .` with every IRI escaped for SPARQL.
std::string SparqlDataLine(const Triple& t) {
  return SparqlSubject(t.subject) + " " + SparqlIriRef(t.predicate) + " " +
         SparqlObject(t.object) + " .";
}

}  // namespace

using living_web::DecodeSparqlSelect;
using living_web::kProvAuthor;
using living_web::kProvMethod;
using living_web::kProvSignature;
using living_web::kProvTimestamp;
using living_web::kRdfReifies;
using living_web::kXsdString;
using living_web::LiteralValue;
using living_web::NamedGraphInput;
using living_web::OxigraphStore;
using living_web::Reifier;
using living_web::SparqlResult;
using living_web::SparqlSelect;
using living_web::SparqlTerm;
using living_web::SparqlTermType;

GraphBackend::GraphBackend(DIDKeyProvider* identity,
                           std::string id,
                           GraphTrustLevel trust)
    : identity_(identity), id_(std::move(id)), trust_level_(trust) {}

GraphBackend::~GraphBackend() = default;

bool GraphBackend::GetIri(std::string* out) {
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

bool GraphBackend::QueryTriples(const TripleQuery& query,
                                std::vector<Triple>* out) {
  if (dissolved_) {
    last_error_ = "InvalidStateError";
    return false;
  }
  std::string q = "SELECT ?s ?p ?o ?author ?ts WHERE {\n" +
                  ReifierWherePrefix(/*with_author=*/true) +
                  BuildFilters(query) + "}\nORDER BY DESC(?ts) ASC(?s)";
  if (query.offset)
    q += "\nOFFSET " + std::to_string(*query.offset);
  if (query.limit)
    q += "\nLIMIT " + std::to_string(*query.limit);
  return RunSelectTriples(q, out);
}

bool GraphBackend::Snapshot(std::vector<Triple>* out) {
  if (dissolved_) {
    last_error_ = "InvalidStateError";
    return false;
  }
  std::string q =
      "SELECT ?s ?p ?o ?ts WHERE {\n"
      "?r <" +
      std::string(kRdfReifies) +
      "> <<( ?s ?p ?o )>> .\n"
      "?r <" +
      std::string(kProvTimestamp) +
      "> ?ts .\n"
      "}\nORDER BY ASC(?ts) ASC(?s)";
  return RunSelectTriples(q, out);
}

bool GraphBackend::Provenance(const Triple& triple,
                              std::vector<Reifier>* out) {
  if (dissolved_) {
    last_error_ = "InvalidStateError";
    return false;
  }
  std::string q =
      "SELECT ?r ?author ?ts ?method ?sig WHERE {\n"
      "?r <" +
      std::string(kRdfReifies) + "> " + SparqlTripleTerm(triple) +
      " .\n"
      "?r <" +
      std::string(kProvAuthor) +
      "> ?author .\n"
      "?r <" +
      std::string(kProvTimestamp) +
      "> ?ts .\n"
      "?r <" +
      std::string(kProvMethod) +
      "> ?method .\n"
      "?r <" +
      std::string(kProvSignature) +
      "> ?sig .\n"
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

SparqlResult GraphBackend::QuerySparql(
    const std::string& sparql,
    const std::vector<GraphBackend*>& named_graphs,
    std::optional<uint64_t> /*timeout_ms*/) {
  SparqlResult r;
  if (dissolved_) {
    r.ok = false;
    r.error = "InvalidStateError";
    return r;
  }
  std::vector<NamedGraphInput> inputs;
  inputs.reserve(named_graphs.size());
  for (GraphBackend* g : named_graphs) {
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

bool GraphBackend::AddTriple(const Triple& triple, Triple* out) {
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
  cached_iri_.reset();     // step 6
  if (on_triple_added_)    // step 7
    on_triple_added_(triple);
  if (out)                 // step 8
    *out = triple;
  return true;
}

bool GraphBackend::AddTriples(const std::vector<Triple>& triples,
                              std::vector<Triple>* out) {
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
  if (on_triple_added_) {
    for (const auto& t : triples)
      on_triple_added_(t);
  }
  if (out)
    *out = triples;
  return true;
}

bool GraphBackend::RemoveTriple(const Triple& triple, bool* out_removed) {
  if (dissolved_) {
    last_error_ = "InvalidStateError";
    return false;
  }
  *out_removed = false;
  if (IsBlankNode(triple.subject))
    return true;
  std::string upd =
      "DELETE {\n" + SparqlDataLine(triple) +
      "\n?r ?rp ?rv .\n} WHERE {\n"
      "?r <" +
      std::string(kRdfReifies) + "> " + SparqlTripleTerm(triple) +
      " .\n"
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

bool GraphBackend::GetAsSnapshot(SnapshotFormat format,
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
      if (!OxigraphStore::Canonicalize(dump, living_web::CanonHash::kSha256,
                                       &data, &err)) {
        last_error_ = err;
        return false;
      }
      break;
    case SnapshotFormat::kNQuads:
      data = dump;
      break;
    case SnapshotFormat::kTurtle:
      if (!store_.Serialize(living_web::RdfFormat::kTurtle, &data)) {
        last_error_ = store_.last_error();
        return false;
      }
      break;
    case SnapshotFormat::kJsonLd:
      last_error_ = "NotSupportedError";
      return false;
  }
  std::string timestamp = NowRfc3339();  // step 4
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

bool GraphBackend::Dissolve() {
  if (dissolved_)
    return true;
  store_.Clear();
  dissolved_ = true;
  cached_iri_.reset();
  on_triple_added_ = nullptr;
  on_triple_removed_ = nullptr;
  return true;
}

bool GraphBackend::LoadVerifiedNquads(const std::string& nquads) {
  if (!store_.LoadNquads(nquads)) {
    last_error_ = store_.last_error();
    return false;
  }
  cached_iri_.reset();
  return true;
}

bool GraphBackend::DumpNquads(std::string* out) {
  if (dissolved_) {
    last_error_ = "InvalidStateError";
    return false;
  }
  if (!store_.DumpNquads(out)) {
    last_error_ = store_.last_error();
    return false;
  }
  return true;
}

bool GraphBackend::BuildReifierDoc(const Triple& triple,
                                   const std::string& label,
                                   const DIDKeyPair* active,
                                   std::string* out) {
  std::string timestamp = NowRfc3339();
  std::string preimage = living_web::BuildSignaturePreimage(triple, timestamp,
                                                            GraphIdentifier());
  std::string payload = crypto::SHA256HashString(preimage);
  auto sig = identity_->SignRaw(
      active->id, std::vector<uint8_t>(payload.begin(), payload.end()));
  if (!sig) {
    last_error_ = "InvalidStateError";
    return false;
  }
  std::string sig_mb = living_web::did_key::MultibaseEncode(*sig);
  std::string method =
      active->did + "#" +
      *living_web::did_key::Ed25519PublicKeyMultibase(active->public_key);
  *out = living_web::BuildTripleWithReifierNquads(triple, label, active->did,
                                                 timestamp, method, sig_mb);
  return true;
}

bool GraphBackend::SignProof(const DIDKeyPair* active,
                             const std::string& payload32,
                             const std::string& role,
                             SnapshotProof* out) {
  auto sig = identity_->SignRaw(
      active->id, std::vector<uint8_t>(payload32.begin(), payload32.end()));
  if (!sig) {
    last_error_ = "InvalidStateError";
    return false;
  }
  out->role = role;
  out->author = active->did;
  out->method =
      active->did + "#" +
      *living_web::did_key::Ed25519PublicKeyMultibase(active->public_key);
  out->signature = living_web::did_key::MultibaseEncode(*sig);
  return true;
}

// static
std::string GraphBackend::TermToNode(const SparqlTerm& t) {
  if (t.type == SparqlTermType::kBlankNode)
    return "_:" + t.value;
  return t.value;
}

// static
ObjectTerm GraphBackend::TermToObject(const SparqlTerm& t) {
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

// static
std::string GraphBackend::ReifierWherePrefix(bool with_author) {
  std::string w =
      "?r <" + std::string(kRdfReifies) + "> <<( ?s ?p ?o )>> .\n";
  if (with_author)
    w += "?r <" + std::string(kProvAuthor) + "> ?author .\n";
  w += "?r <" + std::string(kProvTimestamp) + "> ?ts .\n";
  return w;
}

std::string GraphBackend::BuildFilters(const TripleQuery& q) const {
  std::string f;
  if (q.subject) {
    if (IsBlankNode(*q.subject))
      f += "FILTER(STR(?s) = \"" + EscapeDq(q.subject->substr(2)) + "\")\n";
    else
      f += "FILTER(?s = " + SparqlIriRef(*q.subject) + ")\n";
  }
  if (q.predicate)
    f += "FILTER(?p = " + SparqlIriRef(*q.predicate) + ")\n";
  if (q.object) {
    const ObjectTerm& o = *q.object;
    if (o.is_literal())
      f += "FILTER(?o = " + SerializeLiteral(*o.literal) + ")\n";
    else if (IsBlankNode(o.iri_or_bnode))
      f += "FILTER(STR(?o) = \"" + EscapeDq(o.iri_or_bnode.substr(2)) + "\")\n";
    else
      f += "FILTER(?o = " + SparqlIriRef(o.iri_or_bnode) + ")\n";
  }
  if (q.author)
    f += "FILTER(?author = " + SparqlIriRef(*q.author) + ")\n";
  if (q.from_date)
    f += "FILTER(?ts >= \"" + EscapeDq(*q.from_date) + "\"^^<" +
         std::string(kXsdDateTime) + ">)\n";
  if (q.until_date)
    f += "FILTER(?ts < \"" + EscapeDq(*q.until_date) + "\"^^<" +
         std::string(kXsdDateTime) + ">)\n";
  return f;
}

bool GraphBackend::RunSelectTriples(const std::string& q,
                                    std::vector<Triple>* out) {
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

}  // namespace content
