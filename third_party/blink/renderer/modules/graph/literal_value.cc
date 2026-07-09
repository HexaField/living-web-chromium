// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/literal_value.h"

#include "third_party/blink/renderer/bindings/modules/v8/v8_literal_value_init.h"

namespace blink {

namespace {

// §3.1: datatype defaults to xsd:string when the caller supplies no init.
constexpr char kXsdString[] = "http://www.w3.org/2001/XMLSchema#string";

}  // namespace

// static
LiteralValue* LiteralValue::Create(const String& lexical_value,
                                   const LiteralValueInit* init) {
  String datatype = kXsdString;
  String language;
  if (init) {
    if (init->hasDatatype())
      datatype = init->datatype();
    if (init->hasLanguage())
      language = init->language();
  }
  return MakeGarbageCollected<LiteralValue>(lexical_value, datatype, language);
}

}  // namespace blink
