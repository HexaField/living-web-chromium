// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// JSON Canonicalization Scheme (JCS), RFC 8785. The Decentralised Identity
// Web Platform specification (§6.4) mandates that sign() canonicalise its
// payload with JCS before hashing, and verify() reproduce the identical byte
// sequence. This is a complete implementation: object members are ordered by
// the UTF-16 code-unit value of their keys, strings use JCS minimal escaping,
// and numbers are serialised with the ECMAScript Number::toString algorithm
// (shortest round-tripping representation).
//
// No Chromium dependencies — shared verbatim between the browser backend and
// the standalone harness so both produce byte-identical canonical forms.

#ifndef CONTENT_BROWSER_DID_JCS_H_
#define CONTENT_BROWSER_DID_JCS_H_

#include <optional>
#include <string>

namespace living_web {
namespace jcs {

// Parses |json| (a UTF-8 JSON document per RFC 8259 / I-JSON) and returns its
// canonical serialisation per RFC 8785. Returns nullopt if the input is not
// well-formed JSON.
std::optional<std::string> Canonicalize(const std::string& json);

// Serialises a single IEEE-754 double using the ECMAScript Number::toString
// algorithm (RFC 8785 §3.2.2.3). Exposed for testing.
std::string SerializeNumber(double value);

}  // namespace jcs
}  // namespace living_web

#endif  // CONTENT_BROWSER_DID_JCS_H_
