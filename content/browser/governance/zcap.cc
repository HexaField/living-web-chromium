// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/governance/zcap.h"

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
  // Bare primitive: run to the next structural delimiter or whitespace.
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
            // Minimal UTF-8 encode of the BMP code point.
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

std::string Trim(const std::string& s) {
  size_t a = SkipWs(s, 0);
  size_t b = s.size();
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\n' ||
                   s[b - 1] == '\r')) {
    --b;
  }
  return s.substr(a, b - a);
}

}  // namespace

std::vector<std::string> DefaultRootActions() {
  return {kActionCreateLink,        kActionRemoveLink,
          kActionUpdateGovernance,  kActionUpdateDIDDocument,
          kActionDelegateCapability, kActionMountContext,
          kActionForkGraph,         kActionAnnounceFork};
}

std::string BuildDelegationProofPreimage(const ZcapProofFields& f) {
  std::string p = "living-web/zcap/delegation/v1";
  p += '\n';
  p += f.id;
  p += '\n';
  p += f.invoker;
  p += '\n';
  p += f.parent_capability;
  p += '\n';
  p += f.actions;
  p += '\n';
  p += f.resource;
  p += '\n';
  p += f.caveats;
  p += '\n';
  p += f.proof_purpose;
  p += '\n';
  p += f.created;
  return p;
}

std::vector<std::string> ParseActions(const std::string& raw) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= raw.size()) {
    size_t comma = raw.find(',', start);
    std::string tok =
        raw.substr(start, comma == kNpos ? kNpos : comma - start);
    std::string t = Trim(tok);
    if (!t.empty())
      out.push_back(t);
    if (comma == kNpos)
      break;
    start = comma + 1;
  }
  return out;
}

std::string JoinActions(const std::vector<std::string>& actions) {
  std::string out;
  for (size_t i = 0; i < actions.size(); ++i) {
    if (i)
      out += ',';
    out += actions[i];
  }
  return out;
}

bool ActionInSet(const std::string& action, const std::string& actions_raw) {
  for (const auto& a : ParseActions(actions_raw))
    if (a == action)
      return true;
  return false;
}

bool ActionsSubset(const std::string& child_raw,
                   const std::string& parent_raw) {
  std::vector<std::string> parent = ParseActions(parent_raw);
  for (const auto& c : ParseActions(child_raw)) {
    bool found = false;
    for (const auto& p : parent) {
      if (p == c) {
        found = true;
        break;
      }
    }
    if (!found)
      return false;
  }
  return true;
}

bool SplitJsonArray(const std::string& json, std::vector<std::string>* out) {
  out->clear();
  size_t i = SkipWs(json, 0);
  if (i >= json.size() || json[i] != '[')
    return false;
  ++i;
  i = SkipWs(json, i);
  if (i < json.size() && json[i] == ']')
    return true;  // empty array
  while (i < json.size()) {
    size_t start = SkipWs(json, i);
    size_t end = ScanValue(json, start);
    if (end == kNpos)
      return false;
    out->push_back(json.substr(start, end - start));
    i = SkipWs(json, end);
    if (i >= json.size())
      return false;
    if (json[i] == ',') {
      ++i;
      continue;
    }
    if (json[i] == ']')
      return true;
    return false;
  }
  return false;
}

std::optional<std::string> JsonRawField(const std::string& object,
                                        const std::string& field) {
  size_t i = SkipWs(object, 0);
  if (i >= object.size() || object[i] != '{')
    return std::nullopt;
  ++i;
  while (true) {
    i = SkipWs(object, i);
    if (i >= object.size())
      return std::nullopt;
    if (object[i] == '}')
      return std::nullopt;
    if (object[i] != '"')
      return std::nullopt;
    size_t key_end = ScanString(object, i);
    if (key_end == kNpos)
      return std::nullopt;
    std::string key = JsonUnescape(object.substr(i + 1, key_end - i - 2));
    i = SkipWs(object, key_end);
    if (i >= object.size() || object[i] != ':')
      return std::nullopt;
    ++i;
    size_t val_start = SkipWs(object, i);
    size_t val_end = ScanValue(object, val_start);
    if (val_end == kNpos)
      return std::nullopt;
    if (key == field)
      return object.substr(val_start, val_end - val_start);
    i = SkipWs(object, val_end);
    if (i >= object.size())
      return std::nullopt;
    if (object[i] == ',') {
      ++i;
      continue;
    }
    if (object[i] == '}')
      return std::nullopt;
    return std::nullopt;
  }
}

std::optional<std::string> JsonStringField(const std::string& object,
                                           const std::string& field) {
  auto raw = JsonRawField(object, field);
  if (!raw)
    return std::nullopt;
  const std::string& r = *raw;
  if (r.empty() || r[0] != '"')
    return std::nullopt;
  size_t e = ScanString(r, 0);
  if (e == kNpos)
    return std::nullopt;
  return JsonUnescape(r.substr(1, e - 2));
}

bool CaveatsAttenuationOk(const std::string& parent_raw,
                          const std::string& child_raw) {
  std::string p = Trim(parent_raw);
  if (p.empty())
    return true;  // no parent caveats to preserve
  std::vector<std::string> pe;
  if (!SplitJsonArray(p, &pe))
    return false;  // malformed parent caveats → fail closed
  if (pe.empty())
    return true;
  std::string c = Trim(child_raw);
  if (c.empty())
    return false;
  std::vector<std::string> ce;
  if (!SplitJsonArray(c, &ce))
    return false;
  for (const auto& pel : pe) {
    bool found = false;
    for (const auto& cel : ce) {
      if (pel == cel) {
        found = true;
        break;
      }
    }
    if (!found)
      return false;
  }
  return true;
}

}  // namespace living_web
