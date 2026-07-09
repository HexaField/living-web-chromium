// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Triple — an RDF 1.2 subject/predicate/object statement (Personal Linked Data
// Graphs spec §3.1). The object is a union: an IRI / blank-node string, or a
// LiteralValue. Script-constructible; also produced by the runtime when a
// triple crosses the Mojo boundary.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_TRIPLE_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_TRIPLE_H_

#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class V8UnionUSVStringOrLiteralValue;

class Triple final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // §3.1 constructor(USVString subject, USVString predicate,
  //                  (USVString or LiteralValue) object).
  static Triple* Create(const String& subject,
                        const String& predicate,
                        V8UnionUSVStringOrLiteralValue* object);

  Triple(const String& subject,
         const String& predicate,
         V8UnionUSVStringOrLiteralValue* object)
      : subject_(subject), predicate_(predicate), object_(object) {}

  const String& subject() const { return subject_; }
  const String& predicate() const { return predicate_; }
  V8UnionUSVStringOrLiteralValue* object() const { return object_.Get(); }

  void Trace(Visitor* visitor) const override;

 private:
  String subject_;
  String predicate_;
  Member<V8UnionUSVStringOrLiteralValue> object_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_TRIPLE_H_
