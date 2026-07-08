// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/shapes/shape_definition.h"

#include <cmath>
#include <cstddef>

#include "content/browser/did/jcs.h"

namespace living_web {

namespace {

constexpr size_t kNpos = std::string::npos;

size_t SkipWs(const std::string& s, size_t i) {
  while (i < s.size() &&
         (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) {
    ++i;
  }
  return i;
}

// Index just past the JSON string starting at s[i] (s[i] == '"'); kNpos if the
// string is unterminated.
size_t ScanString(const std::string& s, size_t i) {
  for (size_t j = i + 1; j < s.size(); ++j) {
    if (s[j] == '\\') {
      ++j;  // skip the escaped character
      continue;
    }
    if (s[j] == '"')
      return j + 1;
  }
  return kNpos;
}

// Index just past the JSON value beginning at the first non-whitespace character
// at or after |i|; kNpos on malformation. Handles strings, objects, arrays, and
// bare primitives (number/true/false/null).
size_t ScanValue(const std::string& s, size_t i) {
  i = SkipWs(s, i);
  if (i >= s.size())
    return kNpos;
  char c = s[i];
  if (c == '"')
    return ScanString(s, i);
  if (c == '{' || c == '[') {
    char open = c;
    char close = (c == '{') ? '}' : ']';
    int depth = 0;
    for (size_t j = i; j < s.size(); ++j) {
      char d = s[j];
      if (d == '"') {
        size_t e = ScanString(s, j);
        if (e == kNpos)
          return kNpos;
        j = e - 1;  // loop's ++j lands just past the string
        continue;
      }
      if (d == open) {
        ++depth;
      } else if (d == close) {
        --depth;
        if (depth == 0)
          return j + 1;
      }
    }
    return kNpos;
  }
  size_t j = i;
  while (j < s.size()) {
    char d = s[j];
    if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\t' ||
        d == '\n' || d == '\r') {
      break;
    }
    ++j;
  }
  return (j == i) ? kNpos : j;
}

std::string JsonUnescape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '\\' || i + 1 >= s.size()) {
      out += s[i];
      continue;
    }
    char e = s[++i];
    switch (e) {
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'n': out += '\n'; break;
      case 't': out += '\t'; break;
      case 'r': out += '\r'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'u': {
        if (i + 4 < s.size()) {
          auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
          };
          int h0 = hex(s[i + 1]), h1 = hex(s[i + 2]), h2 = hex(s[i + 3]),
              h3 = hex(s[i + 4]);
          if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0) {
            unsigned cp = (h0 << 12) | (h1 << 8) | (h2 << 4) | h3;
            if (cp < 0x80) {
              out += static_cast<char>(cp);
            } else if (cp < 0x800) {
              out += static_cast<char>(0xC0 | (cp >> 6));
              out += static_cast<char>(0x80 | (cp & 0x3F));
            } else {
              out += static_cast<char>(0xE0 | (cp >> 12));
              out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
              out += static_cast<char>(0x80 | (cp & 0x3F));
            }
            i += 4;
            break;
          }
        }
        out += 'u';
        break;
      }
      default:
        out += e;
    }
  }
  return out;
}

// The verbatim raw substring of a top-level object field's value (string, array,
// object, or primitive). Returns false if |obj| is not a JSON object or the field
// is absent.
bool RawField(const std::string& obj, const std::string& field,
              std::string* out) {
  size_t i = SkipWs(obj, 0);
  if (i >= obj.size() || obj[i] != '{')
    return false;
  ++i;
  while (true) {
    i = SkipWs(obj, i);
    if (i >= obj.size() || obj[i] == '}')
      return false;
    if (obj[i] != '"')
      return false;
    size_t key_end = ScanString(obj, i);
    if (key_end == kNpos)
      return false;
    std::string key = JsonUnescape(obj.substr(i + 1, key_end - i - 2));
    i = SkipWs(obj, key_end);
    if (i >= obj.size() || obj[i] != ':')
      return false;
    ++i;
    size_t val_start = SkipWs(obj, i);
    size_t val_end = ScanValue(obj, val_start);
    if (val_end == kNpos)
      return false;
    if (key == field) {
      *out = obj.substr(val_start, val_end - val_start);
      return true;
    }
    i = SkipWs(obj, val_end);
    if (i >= obj.size())
      return false;
    if (obj[i] == ',') {
      ++i;
      continue;
    }
    return false;  // '}' or anything else: field not found
  }
}

// A top-level string field, unescaped. False if absent or not a JSON string.
bool StringField(const std::string& obj, const std::string& field,
                 std::string* out) {
  std::string raw;
  if (!RawField(obj, field, &raw))
    return false;
  if (raw.empty() || raw[0] != '"')
    return false;
  size_t e = ScanString(raw, 0);
  if (e == kNpos)
    return false;
  *out = JsonUnescape(raw.substr(1, e - 2));
  return true;
}

// True iff the field is present. |*is_string| reports whether it is a JSON
// string. Lets a caller distinguish "absent" (OPTIONAL: fine) from "present but
// wrong JSON type" (malformed → SyntaxError).
bool FieldPresent(const std::string& obj, const std::string& field,
                  bool* is_string) {
  std::string raw;
  if (!RawField(obj, field, &raw)) {
    *is_string = false;
    return false;
  }
  *is_string = !raw.empty() && raw[0] == '"';
  return true;
}

// A top-level numeric field. |*found| is set iff the field is present; the return
// value is true only when the present value is a JSON number (written to |*out|).
bool NumberField(const std::string& obj, const std::string& field, double* out,
                 bool* found) {
  *found = false;
  std::string raw;
  if (!RawField(obj, field, &raw))
    return false;
  *found = true;
  if (raw.empty())
    return false;
  char c = raw[0];
  if (c == '"' || c == '{' || c == '[')
    return false;  // present but not a number
  // ScanValue trims to the bare token, so the whole of |raw| must parse.
  size_t consumed = 0;
  double v = 0.0;
  try {
    v = std::stod(raw, &consumed);
  } catch (...) {
    return false;
  }
  if (consumed != raw.size())
    return false;
  *out = v;
  return true;
}

// A top-level boolean field. |*found| is set iff the field is present; the return
// value is true only when the present value is a JSON boolean (written to |*out|).
bool BoolField(const std::string& obj, const std::string& field, bool* out,
               bool* found) {
  *found = false;
  std::string raw;
  if (!RawField(obj, field, &raw))
    return false;
  *found = true;
  if (raw == "true") {
    *out = true;
    return true;
  }
  if (raw == "false") {
    *out = false;
    return true;
  }
  return false;  // present but not a boolean
}

// Split the raw `[ ... ]` substring of a JSON array into its top-level element
// substrings (verbatim, each trimmed of surrounding whitespace). Returns false if
// |raw| is not a JSON array.
bool RawArrayElements(const std::string& raw, std::vector<std::string>* out) {
  out->clear();
  size_t i = SkipWs(raw, 0);
  if (i >= raw.size() || raw[i] != '[')
    return false;
  ++i;
  i = SkipWs(raw, i);
  if (i < raw.size() && raw[i] == ']')
    return true;  // empty array
  while (i < raw.size()) {
    size_t vs = SkipWs(raw, i);
    size_t ve = ScanValue(raw, vs);
    if (ve == kNpos)
      return false;
    out->push_back(raw.substr(vs, ve - vs));
    i = SkipWs(raw, ve);
    if (i >= raw.size())
      return false;
    if (raw[i] == ',') {
      ++i;
      continue;
    }
    if (raw[i] == ']')
      return true;
    return false;
  }
  return false;
}

bool IsLowerHex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

bool IsDigits(const std::string& v, size_t begin, size_t end) {
  if (begin >= end)
    return false;
  for (size_t i = begin; i < end; ++i) {
    if (v[i] < '0' || v[i] > '9')
      return false;
  }
  return true;
}

bool IsXsdInteger(const std::string& v) {
  size_t i = 0;
  if (!v.empty() && (v[0] == '+' || v[0] == '-'))
    i = 1;
  return IsDigits(v, i, v.size());
}

bool IntegerIsZero(const std::string& v) {
  size_t i = 0;
  if (!v.empty() && (v[0] == '+' || v[0] == '-'))
    i = 1;
  for (; i < v.size(); ++i) {
    if (v[i] != '0')
      return false;
  }
  return true;
}

bool IsXsdDecimal(const std::string& v) {
  size_t i = 0;
  if (!v.empty() && (v[0] == '+' || v[0] == '-'))
    i = 1;
  bool digits = false, dot = false;
  for (; i < v.size(); ++i) {
    if (v[i] == '.') {
      if (dot)
        return false;
      dot = true;
    } else if (v[i] >= '0' && v[i] <= '9') {
      digits = true;
    } else {
      return false;
    }
  }
  return digits;
}

bool IsXsdDouble(const std::string& v) {
  if (v == "INF" || v == "+INF" || v == "-INF" || v == "NaN")
    return true;
  size_t i = 0;
  if (!v.empty() && (v[0] == '+' || v[0] == '-'))
    i = 1;
  bool digits = false, dot = false;
  size_t j = i;
  for (; j < v.size(); ++j) {
    char c = v[j];
    if (c == '.') {
      if (dot)
        return false;
      dot = true;
    } else if (c >= '0' && c <= '9') {
      digits = true;
    } else if (c == 'e' || c == 'E') {
      break;
    } else {
      return false;
    }
  }
  if (!digits)
    return false;
  if (j < v.size() && (v[j] == 'e' || v[j] == 'E')) {
    ++j;
    if (j < v.size() && (v[j] == '+' || v[j] == '-'))
      ++j;
    return IsDigits(v, j, v.size());
  }
  return true;
}

bool IsXsdBoolean(const std::string& v) {
  return v == "true" || v == "false" || v == "1" || v == "0";
}

// Structural XSD dateTime: [-]?YYYY(+)-MM-DDThh:mm:ss(.s+)?(Z|(+|-)hh:mm)?
bool IsXsdDateTime(const std::string& v) {
  size_t i = 0;
  if (i < v.size() && v[i] == '-')
    ++i;
  auto digits = [&](int n) -> bool {
    for (int k = 0; k < n; ++k) {
      if (i >= v.size() || v[i] < '0' || v[i] > '9')
        return false;
      ++i;
    }
    return true;
  };
  auto lit = [&](char c) -> bool {
    if (i >= v.size() || v[i] != c)
      return false;
    ++i;
    return true;
  };
  if (!digits(4))
    return false;
  if (!lit('-') || !digits(2) || !lit('-') || !digits(2))
    return false;
  if (!lit('T'))
    return false;
  if (!digits(2) || !lit(':') || !digits(2) || !lit(':') || !digits(2))
    return false;
  if (i < v.size() && v[i] == '.') {
    ++i;
    if (!digits(1))
      return false;
    while (i < v.size() && v[i] >= '0' && v[i] <= '9')
      ++i;
  }
  if (i < v.size()) {
    if (v[i] == 'Z') {
      ++i;
    } else if (v[i] == '+' || v[i] == '-') {
      ++i;
      if (!digits(2) || !lit(':') || !digits(2))
        return false;
    } else {
      return false;
    }
  }
  return i == v.size();
}

// Structural XSD date: [-]?YYYY-MM-DD(Z|(+|-)hh:mm)?
bool IsXsdDate(const std::string& v) {
  size_t i = 0;
  if (i < v.size() && v[i] == '-')
    ++i;
  auto digits = [&](int n) -> bool {
    for (int k = 0; k < n; ++k) {
      if (i >= v.size() || v[i] < '0' || v[i] > '9')
        return false;
      ++i;
    }
    return true;
  };
  auto lit = [&](char c) -> bool {
    if (i >= v.size() || v[i] != c)
      return false;
    ++i;
    return true;
  };
  if (!digits(4) || !lit('-') || !digits(2) || !lit('-') || !digits(2))
    return false;
  if (i < v.size()) {
    if (v[i] == 'Z') {
      ++i;
    } else if (v[i] == '+' || v[i] == '-') {
      ++i;
      if (!digits(2) || !lit(':') || !digits(2))
        return false;
    } else {
      return false;
    }
  }
  return i == v.size();
}

}  // namespace

bool IsValidShapePropertyName(const std::string& name) {
  if (name.empty())
    return false;
  char c0 = name[0];
  bool head = (c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_';
  if (!head)
    return false;
  for (size_t i = 1; i < name.size(); ++i) {
    char c = name[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_';
    if (!ok)
      return false;
  }
  return true;
}

namespace {

// Parse one §4.2 property object. Returns false + |*error| on malformation.
bool ParseProperty(const std::string& elem, ShapePropertyDef* out,
                   std::string* error) {
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    return false;
  };
  ShapePropertyDef p;

  if (!StringField(elem, "path", &p.path) || p.path.empty())
    return fail("shape property: missing or empty required field \"path\"");
  if (!StringField(elem, "name", &p.name) || p.name.empty())
    return fail("shape property: missing or empty required field \"name\"");
  if (!IsValidShapePropertyName(p.name)) {
    return fail("shape property: \"name\" must match [a-zA-Z_][a-zA-Z0-9_]*: " +
                p.name);
  }

  bool is_string = false;
  if (FieldPresent(elem, "datatype", &is_string)) {
    if (!is_string)
      return fail("shape property: \"datatype\" must be a string");
    std::string dt;
    StringField(elem, "datatype", &dt);
    if (dt.empty())
      return fail("shape property: \"datatype\" must be a non-empty string");
    p.datatype = dt;
  }

  {
    double v = 0.0;
    bool found = false;
    if (NumberField(elem, "minCount", &v, &found)) {
      if (v < 0 || v != std::floor(v))
        return fail("shape property: \"minCount\" must be a non-negative integer");
      p.min_count = static_cast<unsigned long>(v);
    } else if (found) {
      return fail("shape property: \"minCount\" must be a number");
    }
  }
  {
    double v = 0.0;
    bool found = false;
    if (NumberField(elem, "maxCount", &v, &found)) {
      if (v < 0 || v != std::floor(v))
        return fail("shape property: \"maxCount\" must be a non-negative integer");
      p.max_count = static_cast<unsigned long>(v);
    } else if (found) {
      return fail("shape property: \"maxCount\" must be a number");
    }
  }
  {
    bool b = false, found = false;
    if (BoolField(elem, "writable", &b, &found))
      p.writable = b;
    else if (found)
      return fail("shape property: \"writable\" must be a boolean");
  }
  {
    bool b = false, found = false;
    if (BoolField(elem, "readOnly", &b, &found))
      p.read_only = b;
    else if (found)
      return fail("shape property: \"readOnly\" must be a boolean");
  }
  // §4.2 — readOnly implies writable:false.
  if (p.read_only)
    p.writable = false;

  {
    std::string rp;
    if (StringField(elem, "resolveProtocol", &rp))
      p.resolve_protocol = rp;
  }
  {
    std::string g;
    if (StringField(elem, "getter", &g))
      p.getter = g;
  }

  if (p.max_count.has_value() && *p.max_count < p.min_count) {
    return fail("shape property \"" + p.name +
                "\": \"maxCount\" is less than \"minCount\"");
  }

  *out = p;
  return true;
}

// Parse one §4.3 constructor action. Accepts the canonical subject/object keys
// and the §12 source/target aliases.
bool ParseConstructorAction(const std::string& elem, ShapeConstructorAction* out,
                            std::string* error) {
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    return false;
  };
  ShapeConstructorAction a;

  if (!StringField(elem, "action", &a.action_uri) || a.action_uri.empty())
    return fail("constructor action: missing required field \"action\"");
  if (a.action_uri == kShapeActionAddLink) {
    a.kind = ShapeActionKind::kAddLink;
  } else if (a.action_uri == kShapeActionSetSingleTarget) {
    a.kind = ShapeActionKind::kSetSingleTarget;
  } else if (a.action_uri == kShapeActionAddCollectionTarget) {
    a.kind = ShapeActionKind::kAddCollectionTarget;
  } else {
    return fail("constructor action: unknown action URI \"" + a.action_uri +
                "\" (expected a shape://actions/* form)");
  }

  if (!StringField(elem, "subject", &a.subject) &&
      !StringField(elem, "source", &a.subject)) {
    return fail("constructor action: missing required field \"subject\"");
  }
  if (a.subject != "this")
    return fail("constructor action: \"subject\" MUST be \"this\"");

  if (!StringField(elem, "predicate", &a.predicate) || a.predicate.empty())
    return fail("constructor action: missing required field \"predicate\"");

  if (!StringField(elem, "object", &a.object) &&
      !StringField(elem, "target", &a.object)) {
    return fail("constructor action: missing required field \"object\"");
  }
  if (a.object.empty())
    return fail("constructor action: \"object\" must be non-empty");

  *out = a;
  return true;
}

}  // namespace

bool ParseShapeDefinition(const std::string& json, ShapeDefinition* out,
                          std::string* error) {
  ShapeDefinition s;
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    s.valid = false;
    *out = s;
    return false;
  };

  if (!StringField(json, "targetClass", &s.target_class) ||
      s.target_class.empty()) {
    return fail("shape: missing or empty required field \"targetClass\"");
  }

  bool is_string = false;
  if (FieldPresent(json, "extends", &is_string)) {
    if (!is_string)
      return fail("shape: \"extends\" must be a string URI");
    std::string ext;
    StringField(json, "extends", &ext);
    if (ext.empty())
      return fail("shape: \"extends\" must be a non-empty URI");
    s.extends = ext;
  }

  std::string props_raw;
  if (!RawField(json, "properties", &props_raw))
    return fail("shape: missing required field \"properties\"");
  std::vector<std::string> prop_elems;
  if (!RawArrayElements(props_raw, &prop_elems))
    return fail("shape: \"properties\" must be an array");
  for (const std::string& pe : prop_elems) {
    ShapePropertyDef p;
    if (!ParseProperty(pe, &p, error))
      return fail(error ? *error : "shape: malformed property");
    for (const ShapePropertyDef& seen : s.properties) {
      if (seen.name == p.name)
        return fail("shape: duplicate property name \"" + p.name + "\"");
    }
    s.properties.push_back(p);
  }

  std::string ctor_raw;
  if (!RawField(json, "constructor", &ctor_raw))
    return fail("shape: missing required field \"constructor\"");
  std::vector<std::string> ctor_elems;
  if (!RawArrayElements(ctor_raw, &ctor_elems))
    return fail("shape: \"constructor\" must be an array");
  for (const std::string& ce : ctor_elems) {
    ShapeConstructorAction a;
    if (!ParseConstructorAction(ce, &a, error))
      return fail(error ? *error : "shape: malformed constructor action");
    s.constructor.push_back(a);
  }

  s.valid = true;
  if (error)
    error->clear();
  *out = s;
  return true;
}

std::optional<std::string> CanonicalizeShapeJson(const std::string& json) {
  return jcs::Canonicalize(json);
}

std::string FormatShapeAddress(const std::string& raw_sha256_digest) {
  static const char* kHex = "0123456789abcdef";
  std::string out = kShapeAddressPrefix;
  out.reserve(out.size() + raw_sha256_digest.size() * 2);
  for (unsigned char c : raw_sha256_digest) {
    out += kHex[c >> 4];
    out += kHex[c & 0x0F];
  }
  return out;
}

bool IsWellFormedShapeAddress(const std::string& s) {
  const std::string prefix = kShapeAddressPrefix;  // "sha256:"
  const size_t kHexLen = 64;
  if (s.size() != prefix.size() + kHexLen)
    return false;
  if (s.compare(0, prefix.size(), prefix) != 0)
    return false;
  for (size_t i = prefix.size(); i < s.size(); ++i) {
    if (!IsLowerHex(s[i]))
      return false;
  }
  return true;
}

std::string NormalizeDatatype(const std::string& datatype) {
  if (datatype.empty())
    return std::string();
  if (datatype == kShapeDatatypeUri)
    return kShapeDatatypeUri;
  const std::string kPrefix = "xsd:";
  if (datatype.size() > kPrefix.size() &&
      datatype.compare(0, kPrefix.size(), kPrefix) == 0) {
    return std::string(kXsdNamespace) + datatype.substr(kPrefix.size());
  }
  return datatype;  // full URI (XSD or otherwise) passthrough
}

bool IsUriDatatype(const std::string& normalized_datatype) {
  return normalized_datatype == kShapeDatatypeUri;
}

bool ValidateLexicalForDatatype(const std::string& value,
                                const std::string& normalized_datatype) {
  if (normalized_datatype.empty())
    return true;  // no datatype declared: no check
  if (normalized_datatype == kShapeDatatypeUri) {
    if (value.empty())
      return false;
    for (char c : value) {
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        return false;
    }
    return true;
  }

  const std::string ns = kXsdNamespace;
  if (normalized_datatype.size() <= ns.size() ||
      normalized_datatype.compare(0, ns.size(), ns) != 0) {
    return true;  // non-XSD typed literal: accept as opaque
  }
  const std::string t = normalized_datatype.substr(ns.size());

  if (t == "string" || t == "normalizedString" || t == "token" ||
      t == "language" || t == "Name" || t == "NCName" || t == "NMTOKEN") {
    return true;  // string family: any lexical value
  }
  if (t == "anyURI")
    return !value.empty();
  if (t == "boolean")
    return IsXsdBoolean(value);
  if (t == "decimal")
    return IsXsdDecimal(value);
  if (t == "double" || t == "float")
    return IsXsdDouble(value);
  if (t == "dateTime")
    return IsXsdDateTime(value);
  if (t == "date")
    return IsXsdDate(value);

  // Integer family — syntax plus the sign constraints of the bounded subtypes.
  if (t == "integer" || t == "int" || t == "long" || t == "short" ||
      t == "byte" || t == "nonNegativeInteger" || t == "positiveInteger" ||
      t == "nonPositiveInteger" || t == "negativeInteger" ||
      t == "unsignedLong" || t == "unsignedInt" || t == "unsignedShort" ||
      t == "unsignedByte") {
    if (!IsXsdInteger(value))
      return false;
    const bool neg = value[0] == '-';
    const bool zero = IntegerIsZero(value);
    if (t == "nonNegativeInteger" || t == "unsignedLong" ||
        t == "unsignedInt" || t == "unsignedShort" || t == "unsignedByte") {
      return !neg || zero;  // -0 is permitted
    }
    if (t == "positiveInteger")
      return !neg && !zero;
    if (t == "nonPositiveInteger")
      return neg || zero;
    if (t == "negativeInteger")
      return neg && !zero;
    return true;  // integer/int/long/short/byte: any signed integer
  }

  return true;  // other XSD datatype: accept as opaque typed literal
}

bool ShapeNarrows(const ShapeDefinition& parent, const ShapeDefinition& child,
                  std::string* reason) {
  auto fail = [&](const std::string& r) {
    if (reason)
      *reason = r;
    return false;
  };
  for (const ShapePropertyDef& cp : child.properties) {
    const ShapePropertyDef* pp = FindPropertyByName(parent, cp.name);
    if (!pp)
      continue;  // a property the child adds: always permitted

    if (cp.min_count < pp->min_count) {
      return fail("property \"" + cp.name +
                  "\": minCount loosened below parent");
    }

    if (pp->max_count.has_value()) {
      if (!cp.max_count.has_value()) {
        return fail("property \"" + cp.name +
                    "\": maxCount unbounded under a bounded parent");
      }
      if (*cp.max_count > *pp->max_count) {
        return fail("property \"" + cp.name +
                    "\": maxCount loosened above parent");
      }
    }

    if (pp->datatype.has_value()) {
      if (!cp.datatype.has_value()) {
        return fail("property \"" + cp.name +
                    "\": datatype removed (parent constrained it)");
      }
      if (NormalizeDatatype(*cp.datatype) != NormalizeDatatype(*pp->datatype)) {
        return fail("property \"" + cp.name +
                    "\": datatype differs from parent (not a proven narrowing)");
      }
    }

    if (!pp->writable && cp.writable) {
      return fail("property \"" + cp.name +
                  "\": writable loosened from false to true");
    }
    if (pp->read_only && !cp.read_only) {
      return fail("property \"" + cp.name +
                  "\": readOnly loosened from true to false");
    }
  }
  if (reason)
    reason->clear();
  return true;
}

SetterKind SetterKindFor(const ShapePropertyDef& property) {
  if (!property.writable || property.read_only)
    return SetterKind::kNone;
  if (property.max_count.has_value() && *property.max_count == 1)
    return SetterKind::kScalar;
  return SetterKind::kCollection;
}

const ShapePropertyDef* FindPropertyByName(const ShapeDefinition& shape,
                                           const std::string& name) {
  for (const ShapePropertyDef& p : shape.properties) {
    if (p.name == name)
      return &p;
  }
  return nullptr;
}

const ShapePropertyDef* FindPropertyByPath(const ShapeDefinition& shape,
                                           const std::string& path) {
  for (const ShapePropertyDef& p : shape.properties) {
    if (p.path == path)
      return &p;
  }
  return nullptr;
}

}  // namespace living_web
