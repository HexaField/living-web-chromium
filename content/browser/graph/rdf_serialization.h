// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// RDF 1.2 term and statement serialisation for the Living Web graph substrate
// (Spec 02 — Personal Linked Data Graphs).
//
// This is the Chromium-independent core shared by the standalone test harness
// (standalone/graph_provider.h) and the browser-process graph service
// (content/browser/graph/graph_host.cc), so the bytes fed to Oxigraph — and the
// signature payload — never diverge between the two. It builds RDF 1.2 N-Triples
// / N-Quads text (including the `<<( s p o )>>` triple-term syntax reifiers use)
// and computes the §3.2.1 signature payload. Parsing and canonicalisation are
// delegated to Oxigraph via the FFI; this module only *produces* term syntax.

#ifndef CONTENT_BROWSER_GRAPH_RDF_SERIALIZATION_H_
#define CONTENT_BROWSER_GRAPH_RDF_SERIALIZATION_H_

#include <optional>
#include <string>
#include <vector>

namespace living_web {

// Well-known IRIs used throughout Spec 02.
inline constexpr char kRdfReifies[] =
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#reifies";
inline constexpr char kRdfLangString[] =
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";
inline constexpr char kXsdString[] =
    "http://www.w3.org/2001/XMLSchema#string";
inline constexpr char kXsdDateTime[] =
    "http://www.w3.org/2001/XMLSchema#dateTime";
inline constexpr char kProvAuthor[] = "prov://author";
inline constexpr char kProvTimestamp[] = "prov://timestamp";
inline constexpr char kProvMethod[] = "prov://method";
inline constexpr char kProvSignature[] = "prov://signature";

// An RDF 1.2 literal value (Spec 02 §3.1 `LiteralValue`).
struct LiteralValue {
  std::string lexical;
  std::string datatype = kXsdString;
  std::optional<std::string> language;  // meaningful only for rdf:langString

  bool operator==(const LiteralValue& o) const {
    return lexical == o.lexical && datatype == o.datatype &&
           language == o.language;
  }
};

// The object position of a triple: an IRI, a blank node (identifier beginning
// `_:`), or a literal. IRIs and blank nodes are carried in |iri_or_bnode|; a
// literal is carried in |literal| (and takes precedence when present).
struct ObjectTerm {
  std::optional<LiteralValue> literal;
  std::string iri_or_bnode;

  static ObjectTerm Iri(const std::string& iri) {
    ObjectTerm t;
    t.iri_or_bnode = iri;
    return t;
  }
  static ObjectTerm Blank(const std::string& label) {
    ObjectTerm t;
    t.iri_or_bnode = label;  // caller supplies the leading "_:"
    return t;
  }
  static ObjectTerm Literal(const LiteralValue& v) {
    ObjectTerm t;
    t.literal = v;
    return t;
  }

  bool is_literal() const { return literal.has_value(); }

  bool operator==(const ObjectTerm& o) const {
    return literal == o.literal && iri_or_bnode == o.iri_or_bnode;
  }
};

// A single RDF 1.2 triple (Spec 02 §3.1). |subject| is an IRI or a `_:`-prefixed
// blank-node identifier; |predicate| is an IRI (REQUIRED); |object| is an
// ObjectTerm.
struct Triple {
  std::string subject;
  std::string predicate;
  ObjectTerm object;

  bool operator==(const Triple& o) const {
    return subject == o.subject && predicate == o.predicate &&
           object == o.object;
  }
};

// The per-triple provenance record (Spec 02 §3.7 `Reifier`).
struct Reifier {
  std::string id;         // blank-node identifier in the current graph state
  Triple triple;          // the reified data triple
  std::string author;     // prov://author (a DID URI)
  std::string timestamp;  // prov://timestamp (RFC 3339)
  std::string method;     // prov://method (verification method URI)
  std::string signature;  // prov://signature (multibase-encoded)
};

// ---- serialisation ---------------------------------------------------------

// Escapes a literal lexical form per RDF 1.2 N-Triples (§ ECHAR + UCHAR for
// C0 controls). Backslash, double-quote, LF, CR and TAB take their short
// escapes; other control characters below U+0020 use \u00XX.
std::string EscapeLiteral(const std::string& lexical);

// True when |s| denotes a blank node (begins with "_:").
bool IsBlankNode(const std::string& s);

// Serialises an IRI or blank node as an N-Triples term: `<iri>` or `_:label`.
std::string SerializeIriOrBlank(const std::string& iri_or_bnode);

// Serialises a literal per §3.1: `"lex"^^<dt>`, `"lex"@lang`, or `"lex"`.
std::string SerializeLiteral(const LiteralValue& value);

// Serialises an object term (IRI, blank node, or literal).
std::string SerializeObject(const ObjectTerm& object);

// Serialises a triple as one N-Triples 1.2 line terminated by " ." with no
// trailing newline. This is exactly `canonical(triple)` in the §3.2.1 signature
// payload, and one line of an N-Quads document (default graph) for the store.
std::string SerializeTripleNt(const Triple& triple);

// Serialises a triple as an RDF 1.2 triple term: `<<( s p o )>>`.
std::string SerializeTripleTerm(const Triple& triple);

// Builds the full N-Quads document written to the store for one accepted triple
// (§4.2 step 5): the asserted data triple, the `rdf:reifies` triple whose object
// is the data triple's triple term, and the four `prov://*` triples — six lines,
// all in the default graph, sharing the blank-node reifier label |reifier_label|
// (e.g. "_:r"). Loaded in a single FFI call so the reifier stays linked.
std::string BuildTripleWithReifierNquads(const Triple& triple,
                                         const std::string& reifier_label,
                                         const std::string& author,
                                         const std::string& timestamp,
                                         const std::string& method,
                                         const std::string& signature);

// The bytes hashed to form the §3.2.1 signature payload's pre-image:
//   canonical(triple) ‖ "|" ‖ timestamp ‖ "|" ‖ graphIdentifier
// The caller applies SHA-256 to the returned string and signs the digest with
// `signRaw`.
std::string BuildSignaturePreimage(const Triple& triple,
                                   const std::string& timestamp,
                                   const std::string& graph_identifier);

}  // namespace living_web

#endif  // CONTENT_BROWSER_GRAPH_RDF_SERIALIZATION_H_
