// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/module_runtime/module_manifest.h"

#include <cstddef>

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

// The verbatim raw substring of a top-level object field's value (string,
// array, object, or primitive). Returns false if |obj| is not a JSON object or
// the field is absent.
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

// A top-level array-of-strings field. |*found| is set true iff the field is
// present (so the caller can distinguish "absent" from "present but malformed").
// Returns true only when the value is a JSON array whose every element is a
// string; the unescaped elements are written to |*out|.
bool StringArrayField(const std::string& obj, const std::string& field,
                      std::vector<std::string>* out, bool* found) {
  *found = false;
  out->clear();
  std::string raw;
  if (!RawField(obj, field, &raw))
    return false;
  *found = true;
  size_t i = SkipWs(raw, 0);
  if (i >= raw.size() || raw[i] != '[')
    return false;
  ++i;
  i = SkipWs(raw, i);
  if (i < raw.size() && raw[i] == ']')
    return true;  // empty array
  while (i < raw.size()) {
    size_t vs = SkipWs(raw, i);
    if (vs >= raw.size() || raw[vs] != '"')
      return false;  // non-string element
    size_t ve = ScanString(raw, vs);
    if (ve == kNpos)
      return false;
    out->push_back(JsonUnescape(raw.substr(vs + 1, ve - vs - 2)));
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

}  // namespace

std::string FormatModuleContentHash(const std::string& raw_sha256_digest) {
  static const char* kHex = "0123456789abcdef";
  std::string out = "sha256-";
  out.reserve(7 + raw_sha256_digest.size() * 2);
  for (unsigned char c : raw_sha256_digest) {
    out += kHex[c >> 4];
    out += kHex[c & 0x0F];
  }
  return out;
}

bool IsWellFormedContentHash(const std::string& s) {
  static const char kPrefix[] = "sha256-";
  const size_t kPrefixLen = 7;      // strlen("sha256-")
  const size_t kHexLen = 64;        // 32-byte SHA-256 digest → 64 hex chars
  if (s.size() != kPrefixLen + kHexLen)
    return false;
  if (s.compare(0, kPrefixLen, kPrefix) != 0)
    return false;
  for (size_t i = kPrefixLen; i < s.size(); ++i) {
    if (!IsLowerHex(s[i]))
      return false;
  }
  return true;
}

bool ParseModuleManifest(const std::string& json,
                         ModuleManifest* out,
                         std::string* error) {
  ModuleManifest m;
  auto fail = [&](const std::string& e) {
    if (error)
      *error = e;
    m.valid = false;
    *out = m;
    return false;
  };

  if (!StringField(json, "name", &m.name) || m.name.empty())
    return fail("manifest: missing or empty required field \"name\"");
  if (!StringField(json, "version", &m.version) || m.version.empty())
    return fail("manifest: missing or empty required field \"version\"");
  if (!StringField(json, "wasmContentHash", &m.wasm_content_hash) ||
      m.wasm_content_hash.empty()) {
    return fail("manifest: missing or empty required field \"wasmContentHash\"");
  }
  if (!IsWellFormedContentHash(m.wasm_content_hash)) {
    return fail(
        "manifest: \"wasmContentHash\" is not a well-formed content hash "
        "(expected \"sha256-\" + 64 lowercase hex)");
  }

  bool found = false;
  if (!StringArrayField(json, "supportedConstraintKinds",
                        &m.supported_constraint_kinds, &found)) {
    return fail(found
                    ? "manifest: \"supportedConstraintKinds\" must be an array "
                      "of strings"
                    : "manifest: missing required field "
                      "\"supportedConstraintKinds\"");
  }
  if (!StringArrayField(json, "capabilitiesRequired", &m.capabilities_required,
                        &found)) {
    return fail(
        found
            ? "manifest: \"capabilitiesRequired\" must be an array of strings"
            : "manifest: missing required field \"capabilitiesRequired\"");
  }

  // Optional fields: absence is not an error; a present-but-non-string value is
  // simply ignored (§8.2 permits additional metadata of any shape).
  StringField(json, "publisher", &m.publisher);
  StringField(json, "description", &m.description);

  m.valid = true;
  if (error)
    error->clear();
  *out = m;
  return true;
}

bool ManifestBindsContentHash(const ModuleManifest& manifest,
                              const std::string& computed_content_hash) {
  return !manifest.wasm_content_hash.empty() &&
         manifest.wasm_content_hash == computed_content_hash;
}

bool ConstraintKindsCompatible(const std::vector<std::string>& child_supported,
                               const std::vector<std::string>& parent_in_force,
                               std::vector<std::string>* missing) {
  if (missing)
    missing->clear();
  bool ok = true;
  for (const std::string& kind : parent_in_force) {
    bool present = false;
    for (const std::string& c : child_supported) {
      if (c == kind) {
        present = true;
        break;
      }
    }
    if (!present) {
      ok = false;
      if (missing)
        missing->push_back(kind);
      else
        return false;
    }
  }
  return ok;
}

}  // namespace living_web
