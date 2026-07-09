// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/cbor.h"

#include <algorithm>
#include <cstring>

namespace living_web {
namespace cbor {

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

Value Value::Uint(uint64_t v) {
  Value out;
  out.type = Type::kUint;
  out.u = v;
  return out;
}

Value Value::Nint(uint64_t n) {
  Value out;
  out.type = Type::kNint;
  out.u = n;  // encodes the value -1 - n
  return out;
}

Value Value::Int(int64_t v) {
  if (v < 0) {
    // -1 - n == v  =>  n == -1 - v == -(v + 1). Computed on the unsigned side
    // to avoid overflow at v == INT64_MIN.
    return Nint(static_cast<uint64_t>(-(v + 1)));
  }
  return Uint(static_cast<uint64_t>(v));
}

Value Value::Bytes(std::string s) {
  Value out;
  out.type = Type::kBytes;
  out.str = std::move(s);
  return out;
}

Value Value::Text(std::string s) {
  Value out;
  out.type = Type::kText;
  out.str = std::move(s);
  return out;
}

Value Value::Array(std::vector<Value> a) {
  Value out;
  out.type = Type::kArray;
  out.arr = std::move(a);
  return out;
}

Value Value::Map(std::vector<std::pair<Value, Value>> m) {
  Value out;
  out.type = Type::kMap;
  out.map = std::move(m);
  return out;
}

Value Value::Bool(bool v) {
  Value out;
  out.type = Type::kBool;
  out.b = v;
  return out;
}

Value Value::Null() {
  Value out;
  out.type = Type::kNull;
  return out;
}

// ---------------------------------------------------------------------------
// Typed accessors
// ---------------------------------------------------------------------------

bool Value::AsUint(uint64_t* out) const {
  if (type != Type::kUint)
    return false;
  *out = u;
  return true;
}

bool Value::AsInt(int64_t* out) const {
  if (type == Type::kUint) {
    if (u > static_cast<uint64_t>(INT64_MAX))
      return false;
    *out = static_cast<int64_t>(u);
    return true;
  }
  if (type == Type::kNint) {
    // value == -1 - u. Representable in int64 iff u <= INT64_MAX (then value
    // >= -1 - INT64_MAX == INT64_MIN).
    if (u > static_cast<uint64_t>(INT64_MAX))
      return false;
    *out = -1 - static_cast<int64_t>(u);
    return true;
  }
  return false;
}

bool Value::AsText(std::string* out) const {
  if (type != Type::kText)
    return false;
  *out = str;
  return true;
}

bool Value::AsBytes(std::string* out) const {
  if (type != Type::kBytes)
    return false;
  *out = str;
  return true;
}

bool Value::AsBool(bool* out) const {
  if (type != Type::kBool)
    return false;
  *out = b;
  return true;
}

const Value* Value::Find(const std::string& text_key) const {
  if (type != Type::kMap)
    return nullptr;
  for (const auto& kv : map) {
    if (kv.first.type == Type::kText && kv.first.str == text_key)
      return &kv.second;
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

namespace {

// Appends the RFC 8949 §3 "initial byte + argument" head for |major| carrying
// unsigned |arg|, using the shortest form (deterministic requirement).
void EncodeHead(std::string* out, uint8_t major, uint64_t arg) {
  const uint8_t mt = static_cast<uint8_t>(major << 5);
  if (arg < 24) {
    out->push_back(static_cast<char>(mt | static_cast<uint8_t>(arg)));
  } else if (arg <= 0xff) {
    out->push_back(static_cast<char>(mt | 24));
    out->push_back(static_cast<char>(arg & 0xff));
  } else if (arg <= 0xffff) {
    out->push_back(static_cast<char>(mt | 25));
    out->push_back(static_cast<char>((arg >> 8) & 0xff));
    out->push_back(static_cast<char>(arg & 0xff));
  } else if (arg <= 0xffffffffULL) {
    out->push_back(static_cast<char>(mt | 26));
    out->push_back(static_cast<char>((arg >> 24) & 0xff));
    out->push_back(static_cast<char>((arg >> 16) & 0xff));
    out->push_back(static_cast<char>((arg >> 8) & 0xff));
    out->push_back(static_cast<char>(arg & 0xff));
  } else {
    out->push_back(static_cast<char>(mt | 27));
    for (int shift = 56; shift >= 0; shift -= 8)
      out->push_back(static_cast<char>((arg >> shift) & 0xff));
  }
}

void EncodeValue(std::string* out, const Value& v);

void EncodeValue(std::string* out, const Value& v) {
  switch (v.type) {
    case Type::kUint:
      EncodeHead(out, 0, v.u);
      return;
    case Type::kNint:
      EncodeHead(out, 1, v.u);
      return;
    case Type::kBytes:
      EncodeHead(out, 2, v.str.size());
      out->append(v.str);
      return;
    case Type::kText:
      EncodeHead(out, 3, v.str.size());
      out->append(v.str);
      return;
    case Type::kArray:
      EncodeHead(out, 4, v.arr.size());
      for (const Value& e : v.arr)
        EncodeValue(out, e);
      return;
    case Type::kMap: {
      // Deterministic map ordering (RFC 8949 §4.2.1): sort entries by the
      // bytewise-lexicographic order of the *encoded key*.
      std::vector<std::pair<std::string, std::string>> entries;
      entries.reserve(v.map.size());
      for (const auto& kv : v.map) {
        std::string ek;
        EncodeValue(&ek, kv.first);
        std::string ev;
        EncodeValue(&ev, kv.second);
        entries.emplace_back(std::move(ek), std::move(ev));
      }
      std::sort(entries.begin(), entries.end(),
                [](const std::pair<std::string, std::string>& a,
                   const std::pair<std::string, std::string>& b) {
                  return a.first < b.first;
                });
      EncodeHead(out, 5, entries.size());
      for (const auto& e : entries) {
        out->append(e.first);
        out->append(e.second);
      }
      return;
    }
    case Type::kBool:
      // Major 7, simple value 20 (false) / 21 (true).
      out->push_back(static_cast<char>(0xe0 | (v.b ? 21 : 20)));
      return;
    case Type::kNull:
      // Major 7, simple value 22.
      out->push_back(static_cast<char>(0xe0 | 22));
      return;
  }
}

}  // namespace

std::string Encode(const Value& v) {
  std::string out;
  EncodeValue(&out, v);
  return out;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

namespace {

// A cursor over the input. All reads are bounds-checked; any violation makes
// the whole decode fail (strictness requirement).
struct Reader {
  const uint8_t* p;
  const uint8_t* end;

  bool ReadByte(uint8_t* out) {
    if (p >= end)
      return false;
    *out = *p++;
    return true;
  }

  bool ReadBytes(size_t n, const uint8_t** start) {
    if (static_cast<size_t>(end - p) < n)
      return false;
    *start = p;
    p += n;
    return true;
  }
};

// Reads the argument for an initial byte whose low 5 bits are |info|. Rejects
// indefinite length (31) and the reserved additional-info values 28–30.
bool ReadArgument(Reader* r, uint8_t info, uint64_t* arg) {
  if (info < 24) {
    *arg = info;
    return true;
  }
  switch (info) {
    case 24: {
      uint8_t b;
      if (!r->ReadByte(&b))
        return false;
      *arg = b;
      return true;
    }
    case 25: {
      const uint8_t* s;
      if (!r->ReadBytes(2, &s))
        return false;
      *arg = (static_cast<uint64_t>(s[0]) << 8) | s[1];
      return true;
    }
    case 26: {
      const uint8_t* s;
      if (!r->ReadBytes(4, &s))
        return false;
      *arg = (static_cast<uint64_t>(s[0]) << 24) |
             (static_cast<uint64_t>(s[1]) << 16) |
             (static_cast<uint64_t>(s[2]) << 8) | s[3];
      return true;
    }
    case 27: {
      const uint8_t* s;
      if (!r->ReadBytes(8, &s))
        return false;
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v = (v << 8) | s[i];
      *arg = v;
      return true;
    }
    default:
      // 28, 29, 30 reserved; 31 indefinite — all rejected.
      return false;
  }
}

bool DecodeValue(Reader* r, Value* out);

bool DecodeValue(Reader* r, Value* out) {
  uint8_t ib;
  if (!r->ReadByte(&ib))
    return false;
  const uint8_t major = ib >> 5;
  const uint8_t info = ib & 0x1f;

  switch (major) {
    case 0: {  // unsigned integer
      uint64_t arg;
      if (!ReadArgument(r, info, &arg))
        return false;
      *out = Value::Uint(arg);
      return true;
    }
    case 1: {  // negative integer
      uint64_t arg;
      if (!ReadArgument(r, info, &arg))
        return false;
      *out = Value::Nint(arg);
      return true;
    }
    case 2:      // byte string
    case 3: {    // text string
      uint64_t len;
      if (!ReadArgument(r, info, &len))
        return false;
      const uint8_t* s;
      if (!r->ReadBytes(static_cast<size_t>(len), &s))
        return false;
      std::string payload(reinterpret_cast<const char*>(s),
                          static_cast<size_t>(len));
      *out = (major == 2) ? Value::Bytes(std::move(payload))
                          : Value::Text(std::move(payload));
      return true;
    }
    case 4: {  // array
      uint64_t n;
      if (!ReadArgument(r, info, &n))
        return false;
      std::vector<Value> elems;
      elems.reserve(static_cast<size_t>(std::min<uint64_t>(n, 1024)));
      for (uint64_t i = 0; i < n; ++i) {
        Value e;
        if (!DecodeValue(r, &e))
          return false;
        elems.push_back(std::move(e));
      }
      *out = Value::Array(std::move(elems));
      return true;
    }
    case 5: {  // map
      uint64_t n;
      if (!ReadArgument(r, info, &n))
        return false;
      std::vector<std::pair<Value, Value>> entries;
      entries.reserve(static_cast<size_t>(std::min<uint64_t>(n, 1024)));
      for (uint64_t i = 0; i < n; ++i) {
        Value k;
        if (!DecodeValue(r, &k))
          return false;
        Value val;
        if (!DecodeValue(r, &val))
          return false;
        entries.emplace_back(std::move(k), std::move(val));
      }
      *out = Value::Map(std::move(entries));
      return true;
    }
    case 7: {  // simple values (subset)
      switch (info) {
        case 20:
          *out = Value::Bool(false);
          return true;
        case 21:
          *out = Value::Bool(true);
          return true;
        case 22:
          *out = Value::Null();
          return true;
        default:
          // Other simple values, floats (25/26/27), and simple-8bit (24) are
          // all rejected — the wire protocol never uses them.
          return false;
      }
    }
    default:
      // Major 6 (tags) is rejected.
      return false;
  }
}

}  // namespace

bool Decode(const std::string& in, Value* out) {
  Reader r{reinterpret_cast<const uint8_t*>(in.data()),
           reinterpret_cast<const uint8_t*>(in.data()) + in.size()};
  Value v;
  if (!DecodeValue(&r, &v))
    return false;
  if (r.p != r.end)
    return false;  // trailing bytes are not allowed
  *out = std::move(v);
  return true;
}

}  // namespace cbor
}  // namespace living_web
