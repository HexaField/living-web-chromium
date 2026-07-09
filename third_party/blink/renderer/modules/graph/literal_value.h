// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// LiteralValue — an RDF 1.2 literal term (Personal Linked Data Graphs spec
// §3.1). Carries the lexical form, its XSD datatype URI (defaulting to
// xsd:string), and an optional BCP 47 language tag (only meaningful for
// rdf:langString). Script-constructible; also produced by the runtime when a
// Triple.object crosses the Mojo boundary as a literal.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_LITERAL_VALUE_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_LITERAL_VALUE_H_

#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class LiteralValueInit;

class LiteralValue final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // §3.1 constructor(DOMString lexicalValue, optional LiteralValueInit init).
  static LiteralValue* Create(const String& lexical_value,
                              const LiteralValueInit* init);

  // Internal construction from already-resolved fields (Mojo -> renderer).
  LiteralValue(const String& lexical_value,
               const String& datatype,
               const String& language)
      : lexical_value_(lexical_value),
        datatype_(datatype),
        language_(language) {}

  const String& lexicalValue() const { return lexical_value_; }
  const String& datatype() const { return datatype_; }
  // Null when absent (only rdf:langString literals carry a language tag).
  const String& language() const { return language_; }

  void Trace(Visitor* visitor) const override {
    ScriptWrappable::Trace(visitor);
  }

 private:
  String lexical_value_;
  String datatype_;
  String language_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_LITERAL_VALUE_H_
