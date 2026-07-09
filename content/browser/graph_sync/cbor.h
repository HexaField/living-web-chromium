// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Deterministic CBOR (RFC 8949) codec — the wire encoding for the Default Sync
// Module (Spec 09 §5.1). Introduced by Spec 09.
//
// This is a Chromium-independent core (namespace `living_web::cbor`, pure-std, no
// Chromium and no standalone-shim dependencies) shared byte-for-byte by the
// browser default-sync backend and the standalone harness
// (standalone/default_sync_provider.h), so the wire bytes a frame is encoded to —
// and, critically, the AEAD associated-data of an encrypted frame (Spec 09
// §6.3.10 step 4, "the deterministic CBOR encoding of the routing header") —
// never diverge between the two build worlds.
//
// `Encode` emits the RFC 8949 §4.2.1 *core deterministic encoding*:
//   * integers use the shortest argument form;
//   * every string, array and map is definite-length;
//   * map keys are sorted in bytewise-lexicographic order of their encodings.
// `Decode` is strict: it accepts only the definite-length subset of major types
// 0–5 and the three simple values (false/true/null), and rejects trailing bytes,
// truncation, indefinite-length items, tags, and floats. It does not require the
// *input* to be minimally encoded (a receiver tolerates any well-formed producer);
// re-`Encode`-ing a decoded value always yields the canonical form.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_CBOR_H_
#define CONTENT_BROWSER_GRAPH_SYNC_CBOR_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace living_web {
namespace cbor {

// The CBOR data-item kinds this codec supports. Floats, tags, and indefinite
// items are intentionally excluded — the wire protocol never uses them.
enum class Type {
  kUint,   // major 0 — unsigned integer in [0, 2^64)
  kNint,   // major 1 — negative integer; |u| holds n where value == -1 - n
  kBytes,  // major 2 — byte string
  kText,   // major 3 — UTF-8 text string
  kArray,  // major 4 — array
  kMap,    // major 5 — map
  kBool,   // major 7 — simple 20 (false) / 21 (true)
  kNull,   // major 7 — simple 22 (null)
};

// A decoded / to-be-encoded CBOR value. A tagged union kept deliberately simple:
// the inactive members are just empty. `u` doubles as the unsigned magnitude for
// both kUint (the value) and kNint (the value is -1 - u).
struct Value {
  Type type = Type::kNull;
  uint64_t u = 0;
  std::string str;                            // kBytes / kText payload
  std::vector<Value> arr;                     // kArray elements
  std::vector<std::pair<Value, Value>> map;   // kMap entries (unsorted; Encode sorts)
  bool b = false;                             // kBool

  // ---- constructors ----
  static Value Uint(uint64_t v);
  static Value Nint(uint64_t n);   // the value -1 - n (n >= 0)
  static Value Int(int64_t v);     // dispatches to Uint / Nint
  static Value Bytes(std::string s);
  static Value Text(std::string s);
  static Value Array(std::vector<Value> a);
  static Value Map(std::vector<std::pair<Value, Value>> m);
  static Value Bool(bool v);
  static Value Null();

  // ---- typed accessors (for decoding) ----
  bool AsUint(uint64_t* out) const;
  bool AsInt(int64_t* out) const;      // accepts kUint (in int64 range) and kNint
  bool AsText(std::string* out) const;
  bool AsBytes(std::string* out) const;
  bool AsBool(bool* out) const;
  bool IsNull() const { return type == Type::kNull; }
  bool IsArray() const { return type == Type::kArray; }
  bool IsMap() const { return type == Type::kMap; }

  // Map lookup by a text key. Returns nullptr if absent or not a map. The first
  // matching entry wins (a deterministic map has at most one).
  const Value* Find(const std::string& text_key) const;
};

// Deterministic encode (RFC 8949 §4.2.1). Total function.
std::string Encode(const Value& v);

// Strict decode of a single top-level item that must consume all of |in|.
// Returns false (leaving |*out| unspecified) on any malformed / unsupported /
// truncated input, or if bytes remain after the item.
bool Decode(const std::string& in, Value* out);

}  // namespace cbor
}  // namespace living_web

#endif  // CONTENT_BROWSER_GRAPH_SYNC_CBOR_H_
