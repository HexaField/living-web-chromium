// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/jcs.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace living_web {
namespace jcs {

namespace {

// ---------------------------------------------------------------------------
// JSON value model
// ---------------------------------------------------------------------------

struct Value {
  enum class Type { kNull, kBool, kNumber, kString, kArray, kObject };
  Type type = Type::kNull;
  bool boolean = false;
  double number = 0.0;
  std::string string;  // decoded UTF-8 (for kString) or key storage
  std::vector<Value> array;
  std::vector<std::pair<std::string, Value>> object;  // key (UTF-8) -> value
};

// ---------------------------------------------------------------------------
// Parser (recursive descent, RFC 8259)
// ---------------------------------------------------------------------------

class Parser {
 public:
  explicit Parser(const std::string& input) : s_(input) {}

  bool Parse(Value& out) {
    SkipWhitespace();
    if (!ParseValue(out))
      return false;
    SkipWhitespace();
    return pos_ == s_.size();  // No trailing garbage.
  }

 private:
  void SkipWhitespace() {
    while (pos_ < s_.size()) {
      char c = s_[pos_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        ++pos_;
      else
        break;
    }
  }

  bool AtEnd() const { return pos_ >= s_.size(); }
  char Peek() const { return s_[pos_]; }

  bool ParseValue(Value& out) {
    if (AtEnd())
      return false;
    switch (Peek()) {
      case '{':
        return ParseObject(out);
      case '[':
        return ParseArray(out);
      case '"':
        out.type = Value::Type::kString;
        return ParseString(out.string);
      case 't':
      case 'f':
        return ParseBool(out);
      case 'n':
        return ParseNull(out);
      default:
        return ParseNumber(out);
    }
  }

  bool ParseObject(Value& out) {
    out.type = Value::Type::kObject;
    ++pos_;  // consume '{'
    SkipWhitespace();
    if (!AtEnd() && Peek() == '}') {
      ++pos_;
      return true;
    }
    while (true) {
      SkipWhitespace();
      if (AtEnd() || Peek() != '"')
        return false;
      std::string key;
      if (!ParseString(key))
        return false;
      SkipWhitespace();
      if (AtEnd() || Peek() != ':')
        return false;
      ++pos_;  // consume ':'
      SkipWhitespace();
      Value val;
      if (!ParseValue(val))
        return false;
      // RFC 8785 assumes I-JSON input (no duplicate keys). If a duplicate
      // appears, last-wins, matching ECMAScript JSON.parse object semantics.
      auto it = std::find_if(
          out.object.begin(), out.object.end(),
          [&](const auto& kv) { return kv.first == key; });
      if (it != out.object.end())
        it->second = std::move(val);
      else
        out.object.emplace_back(std::move(key), std::move(val));
      SkipWhitespace();
      if (AtEnd())
        return false;
      if (Peek() == ',') {
        ++pos_;
        continue;
      }
      if (Peek() == '}') {
        ++pos_;
        return true;
      }
      return false;
    }
  }

  bool ParseArray(Value& out) {
    out.type = Value::Type::kArray;
    ++pos_;  // consume '['
    SkipWhitespace();
    if (!AtEnd() && Peek() == ']') {
      ++pos_;
      return true;
    }
    while (true) {
      SkipWhitespace();
      Value val;
      if (!ParseValue(val))
        return false;
      out.array.push_back(std::move(val));
      SkipWhitespace();
      if (AtEnd())
        return false;
      if (Peek() == ',') {
        ++pos_;
        continue;
      }
      if (Peek() == ']') {
        ++pos_;
        return true;
      }
      return false;
    }
  }

  bool ParseBool(Value& out) {
    if (s_.compare(pos_, 4, "true") == 0) {
      out.type = Value::Type::kBool;
      out.boolean = true;
      pos_ += 4;
      return true;
    }
    if (s_.compare(pos_, 5, "false") == 0) {
      out.type = Value::Type::kBool;
      out.boolean = false;
      pos_ += 5;
      return true;
    }
    return false;
  }

  bool ParseNull(Value& out) {
    if (s_.compare(pos_, 4, "null") == 0) {
      out.type = Value::Type::kNull;
      pos_ += 4;
      return true;
    }
    return false;
  }

  // Appends the UTF-8 encoding of |cp| to |out|.
  static void AppendUtf8(uint32_t cp, std::string& out) {
    if (cp <= 0x7f) {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ff) {
      out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
      out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
      out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
  }

  bool ParseHex4(uint32_t& out) {
    if (pos_ + 4 > s_.size())
      return false;
    out = 0;
    for (int i = 0; i < 4; ++i) {
      char c = s_[pos_++];
      out <<= 4;
      if (c >= '0' && c <= '9')
        out |= static_cast<uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f')
        out |= static_cast<uint32_t>(10 + c - 'a');
      else if (c >= 'A' && c <= 'F')
        out |= static_cast<uint32_t>(10 + c - 'A');
      else
        return false;
    }
    return true;
  }

  bool ParseString(std::string& out) {
    out.clear();
    if (AtEnd() || Peek() != '"')
      return false;
    ++pos_;  // consume opening quote
    while (!AtEnd()) {
      unsigned char c = static_cast<unsigned char>(s_[pos_++]);
      if (c == '"')
        return true;
      if (c == '\\') {
        if (AtEnd())
          return false;
        char esc = s_[pos_++];
        switch (esc) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            uint32_t cp;
            if (!ParseHex4(cp))
              return false;
            if (cp >= 0xd800 && cp <= 0xdbff) {
              // High surrogate: MUST be followed by \uDC00..\uDFFF.
              if (pos_ + 1 >= s_.size() || s_[pos_] != '\\' ||
                  s_[pos_ + 1] != 'u') {
                return false;
              }
              pos_ += 2;
              uint32_t lo;
              if (!ParseHex4(lo))
                return false;
              if (lo < 0xdc00 || lo > 0xdfff)
                return false;
              cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
              return false;  // Lone low surrogate.
            }
            AppendUtf8(cp, out);
            break;
          }
          default:
            return false;  // Invalid escape.
        }
      } else if (c < 0x20) {
        return false;  // Unescaped control character.
      } else {
        out.push_back(static_cast<char>(c));  // Raw byte (UTF-8 passthrough).
      }
    }
    return false;  // Unterminated string.
  }

  bool ParseNumber(Value& out) {
    size_t start = pos_;
    if (!AtEnd() && Peek() == '-')
      ++pos_;
    // int part
    if (AtEnd())
      return false;
    if (Peek() == '0') {
      ++pos_;
    } else if (Peek() >= '1' && Peek() <= '9') {
      while (!AtEnd() && Peek() >= '0' && Peek() <= '9')
        ++pos_;
    } else {
      return false;
    }
    // frac part
    if (!AtEnd() && Peek() == '.') {
      ++pos_;
      if (AtEnd() || Peek() < '0' || Peek() > '9')
        return false;
      while (!AtEnd() && Peek() >= '0' && Peek() <= '9')
        ++pos_;
    }
    // exp part
    if (!AtEnd() && (Peek() == 'e' || Peek() == 'E')) {
      ++pos_;
      if (!AtEnd() && (Peek() == '+' || Peek() == '-'))
        ++pos_;
      if (AtEnd() || Peek() < '0' || Peek() > '9')
        return false;
      while (!AtEnd() && Peek() >= '0' && Peek() <= '9')
        ++pos_;
    }
    double value = 0.0;
    auto res = std::from_chars(s_.data() + start, s_.data() + pos_, value);
    if (res.ec != std::errc() || res.ptr != s_.data() + pos_)
      return false;
    if (!std::isfinite(value))
      return false;  // I-JSON: NaN/Infinity are not permitted.
    out.type = Value::Type::kNumber;
    out.number = value;
    return true;
  }

  const std::string& s_;
  size_t pos_ = 0;
};

// ---------------------------------------------------------------------------
// UTF-16 code-unit ordering for object keys (RFC 8785 §3.2.3)
// ---------------------------------------------------------------------------

std::vector<uint16_t> Utf8ToUtf16(const std::string& s) {
  std::vector<uint16_t> out;
  size_t i = 0;
  while (i < s.size()) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    uint32_t cp;
    size_t len;
    if (c < 0x80) {
      cp = c;
      len = 1;
    } else if ((c >> 5) == 0x6) {
      cp = c & 0x1f;
      len = 2;
    } else if ((c >> 4) == 0xe) {
      cp = c & 0x0f;
      len = 3;
    } else {
      cp = c & 0x07;
      len = 4;
    }
    for (size_t k = 1; k < len && i + k < s.size(); ++k)
      cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3f);
    i += len;
    if (cp <= 0xffff) {
      out.push_back(static_cast<uint16_t>(cp));
    } else {
      cp -= 0x10000;
      out.push_back(static_cast<uint16_t>(0xd800 + (cp >> 10)));
      out.push_back(static_cast<uint16_t>(0xdc00 + (cp & 0x3ff)));
    }
  }
  return out;
}

bool KeyLessUtf16(const std::string& a, const std::string& b) {
  return Utf8ToUtf16(a) < Utf8ToUtf16(b);
}

// ---------------------------------------------------------------------------
// Serialisation (RFC 8785 §3.2.2)
// ---------------------------------------------------------------------------

void SerializeString(const std::string& s, std::string& out) {
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          static const char* kHex = "0123456789abcdef";
          out += "\\u00";
          out.push_back(kHex[(c >> 4) & 0xf]);
          out.push_back(kHex[c & 0xf]);
        } else {
          out.push_back(static_cast<char>(c));  // UTF-8 passthrough.
        }
    }
  }
  out.push_back('"');
}

void Serialize(const Value& v, std::string& out) {
  switch (v.type) {
    case Value::Type::kNull:
      out += "null";
      break;
    case Value::Type::kBool:
      out += v.boolean ? "true" : "false";
      break;
    case Value::Type::kNumber:
      out += SerializeNumber(v.number);
      break;
    case Value::Type::kString:
      SerializeString(v.string, out);
      break;
    case Value::Type::kArray: {
      out.push_back('[');
      for (size_t i = 0; i < v.array.size(); ++i) {
        if (i)
          out.push_back(',');
        Serialize(v.array[i], out);
      }
      out.push_back(']');
      break;
    }
    case Value::Type::kObject: {
      std::vector<const std::pair<std::string, Value>*> members;
      members.reserve(v.object.size());
      for (const auto& kv : v.object)
        members.push_back(&kv);
      std::sort(members.begin(), members.end(),
                [](const auto* a, const auto* b) {
                  return KeyLessUtf16(a->first, b->first);
                });
      out.push_back('{');
      for (size_t i = 0; i < members.size(); ++i) {
        if (i)
          out.push_back(',');
        SerializeString(members[i]->first, out);
        out.push_back(':');
        Serialize(members[i]->second, out);
      }
      out.push_back('}');
      break;
    }
  }
}

}  // namespace

std::string SerializeNumber(double value) {
  // ECMAScript Number::toString (ECMA-262 §6.1.6.1.20), as required by
  // RFC 8785 §3.2.2.3. std::to_chars(scientific) yields the shortest
  // significand + exponent (the "s" and "n-k" of the spec algorithm); we then
  // apply the spec's fixed/exponential formatting rules.
  if (value == 0.0)
    return "0";  // Covers +0 and -0 (ECMAScript prints "0" for both).

  std::string sign;
  if (value < 0.0) {
    sign = "-";
    value = -value;
  }

  char buf[64];
  auto res = std::to_chars(buf, buf + sizeof(buf), value,
                           std::chars_format::scientific);
  std::string sci(buf, res.ptr);  // e.g. "1e+00", "1.5e+00", "3.3e-01"

  size_t e_index = sci.find('e');
  std::string mantissa = sci.substr(0, e_index);
  int exponent = std::stoi(sci.substr(e_index + 1));

  // Digits of the significand with the decimal point removed.
  std::string digits;
  for (char c : mantissa) {
    if (c != '.')
      digits.push_back(c);
  }
  int k = static_cast<int>(digits.size());  // number of significant digits
  int n = exponent + 1;  // position of the decimal point relative to digits

  std::string out;
  if (k <= n && n <= 21) {
    // Integer value: all digits then (n-k) trailing zeros.
    out = digits + std::string(n - k, '0');
  } else if (0 < n && n <= 21) {
    out = digits.substr(0, n) + "." + digits.substr(n);
  } else if (-6 < n && n <= 0) {
    out = "0." + std::string(-n, '0') + digits;
  } else {
    // Exponential notation.
    int e = n - 1;
    std::string exp = (e >= 0 ? "+" : "-") + std::to_string(std::abs(e));
    if (k == 1)
      out = digits + "e" + exp;
    else
      out = digits.substr(0, 1) + "." + digits.substr(1) + "e" + exp;
  }
  return sign + out;
}

std::optional<std::string> Canonicalize(const std::string& json) {
  Value root;
  Parser parser(json);
  if (!parser.Parse(root))
    return std::nullopt;
  std::string out;
  Serialize(root, out);
  return out;
}

}  // namespace jcs
}  // namespace living_web
