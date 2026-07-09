// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/rdf_serialization.h"

#include <cstdio>

namespace living_web {

std::string EscapeLiteral(const std::string& lexical) {
  std::string out;
  out.reserve(lexical.size() + 8);
  for (unsigned char c : lexical) {
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
          // Remaining C0 controls use the \u00XX UCHAR form.
          char buf[7];
          std::snprintf(buf, sizeof(buf), "\\u%04X", c);
          out += buf;
        } else {
          // Printable ASCII and UTF-8 continuation bytes pass through; N-Triples
          // 1.2 permits raw UTF-8 in string literals.
          out += static_cast<char>(c);
        }
        break;
    }
  }
  return out;
}

bool IsBlankNode(const std::string& s) {
  return s.size() >= 2 && s[0] == '_' && s[1] == ':';
}

std::string SerializeIriOrBlank(const std::string& iri_or_bnode) {
  if (IsBlankNode(iri_or_bnode))
    return iri_or_bnode;
  return "<" + iri_or_bnode + ">";
}

std::string SerializeLiteral(const LiteralValue& value) {
  std::string out = "\"" + EscapeLiteral(value.lexical) + "\"";
  if (value.language.has_value() && !value.language->empty()) {
    out += "@" + *value.language;
  } else if (value.datatype != kXsdString) {
    out += "^^<" + value.datatype + ">";
  }
  return out;
}

std::string SerializeObject(const ObjectTerm& object) {
  if (object.is_literal())
    return SerializeLiteral(*object.literal);
  return SerializeIriOrBlank(object.iri_or_bnode);
}

std::string SerializeTripleNt(const Triple& triple) {
  return SerializeIriOrBlank(triple.subject) + " " +
         SerializeIriOrBlank(triple.predicate) + " " +
         SerializeObject(triple.object) + " .";
}

std::string SerializeTripleTerm(const Triple& triple) {
  return "<<( " + SerializeIriOrBlank(triple.subject) + " " +
         SerializeIriOrBlank(triple.predicate) + " " +
         SerializeObject(triple.object) + " )>>";
}

std::string BuildTripleWithReifierNquads(const Triple& triple,
                                         const std::string& reifier_label,
                                         const std::string& author,
                                         const std::string& timestamp,
                                         const std::string& method,
                                         const std::string& signature) {
  std::string out;
  // 1. The asserted data triple.
  out += SerializeTripleNt(triple);
  out += "\n";
  // 2. reifier rdf:reifies <<( s p o )>> .
  out += reifier_label + " <" + kRdfReifies + "> " +
         SerializeTripleTerm(triple) + " .\n";
  // 3. reifier prov://author <did> .
  out += reifier_label + " <" + kProvAuthor + "> <" + author + "> .\n";
  // 4. reifier prov://timestamp "ts"^^xsd:dateTime .
  LiteralValue ts_lit;
  ts_lit.lexical = timestamp;
  ts_lit.datatype = kXsdDateTime;
  out += reifier_label + " <" + kProvTimestamp + "> " +
         SerializeLiteral(ts_lit) + " .\n";
  // 5. reifier prov://method <method> .
  out += reifier_label + " <" + kProvMethod + "> <" + method + "> .\n";
  // 6. reifier prov://signature "sig" .  (xsd:string, multibase-encoded)
  LiteralValue sig_lit;
  sig_lit.lexical = signature;
  out += reifier_label + " <" + kProvSignature + "> " +
         SerializeLiteral(sig_lit) + " .\n";
  return out;
}

std::string BuildSignaturePreimage(const Triple& triple,
                                   const std::string& timestamp,
                                   const std::string& graph_identifier) {
  return SerializeTripleNt(triple) + "|" + timestamp + "|" + graph_identifier;
}

}  // namespace living_web
