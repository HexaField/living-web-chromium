// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/sparql_results.h"

#include <cmath>
#include <cstdint>

namespace living_web {
namespace {

// A single-pass recursive-descent JSON parser (RFC 8259). On any error it sets
// |error_| and returns false from the failing production; the top level checks
// for trailing garbage.
class JsonReader {
 public:
  JsonReader(const std::string& text, std::string* error)
      : s_(text), error_(error) {}

  bool ParseDocument(JsonValue* out) {
    SkipWs();
    if (!ParseValue(out))
      return false;
    SkipWs();
    if (pos_ != s_.size())
      return Fail("trailing characters after JSON value");
    return true;
  }

 private:
  bool Fail(const std::string& msg) {
    if (error_ && error_->empty())
      *error_ = msg;
    return false;
  }

  void SkipWs() {
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

  bool ParseValue(JsonValue* out) {
    if (AtEnd())
      return Fail("unexpected end of input");
    switch (Peek()) {
      case '{':
        return ParseObject(out);
      case '[':
        return ParseArray(out);
      case '"': {
        out->type = JsonValue::Type::kString;
        return ParseString(&out->string_value);
      }
      case 't':
      case 'f':
        return ParseBool(out);
      case 'n':
        return ParseNull(out);
      default:
        return ParseNumber(out);
    }
  }

  bool ParseObject(JsonValue* out) {
    out->type = JsonValue::Type::kObject;
    ++pos_;  // consume '{'
    SkipWs();
    if (!AtEnd() && Peek() == '}') {
      ++pos_;
      return true;
    }
    while (true) {
      SkipWs();
      if (AtEnd() || Peek() != '"')
        return Fail("expected object key string");
      std::string key;
      if (!ParseString(&key))
        return false;
      SkipWs();
      if (AtEnd() || Peek() != ':')
        return Fail("expected ':' after object key");
      ++pos_;
      SkipWs();
      JsonValue value;
      if (!ParseValue(&value))
        return false;
      out->object_value[key] = std::move(value);
      SkipWs();
      if (AtEnd())
        return Fail("unterminated object");
      char c = Peek();
      if (c == ',') {
        ++pos_;
        continue;
      }
      if (c == '}') {
        ++pos_;
        return true;
      }
      return Fail("expected ',' or '}' in object");
    }
  }

  bool ParseArray(JsonValue* out) {
    out->type = JsonValue::Type::kArray;
    ++pos_;  // consume '['
    SkipWs();
    if (!AtEnd() && Peek() == ']') {
      ++pos_;
      return true;
    }
    while (true) {
      SkipWs();
      JsonValue value;
      if (!ParseValue(&value))
        return false;
      out->array_value.push_back(std::move(value));
      SkipWs();
      if (AtEnd())
        return Fail("unterminated array");
      char c = Peek();
      if (c == ',') {
        ++pos_;
        continue;
      }
      if (c == ']') {
        ++pos_;
        return true;
      }
      return Fail("expected ',' or ']' in array");
    }
  }

  bool ParseString(std::string* out) {
    // Peek() == '"' guaranteed by caller.
    ++pos_;  // consume opening quote
    out->clear();
    while (true) {
      if (AtEnd())
        return Fail("unterminated string");
      char c = s_[pos_++];
      if (c == '"')
        return true;
      if (c == '\\') {
        if (AtEnd())
          return Fail("unterminated escape");
        char e = s_[pos_++];
        switch (e) {
          case '"':
            *out += '"';
            break;
          case '\\':
            *out += '\\';
            break;
          case '/':
            *out += '/';
            break;
          case 'b':
            *out += '\b';
            break;
          case 'f':
            *out += '\f';
            break;
          case 'n':
            *out += '\n';
            break;
          case 'r':
            *out += '\r';
            break;
          case 't':
            *out += '\t';
            break;
          case 'u':
            if (!ParseUnicodeEscape(out))
              return false;
            break;
          default:
            return Fail("invalid string escape");
        }
      } else if (static_cast<unsigned char>(c) < 0x20) {
        return Fail("unescaped control character in string");
      } else {
        *out += c;  // raw byte (UTF-8 passes through)
      }
    }
  }

  // Reads four hex digits after a "\u", handling UTF-16 surrogate pairs, and
  // appends the UTF-8 encoding of the resulting code point.
  bool ParseUnicodeEscape(std::string* out) {
    uint32_t code = 0;
    if (!ReadHex4(&code))
      return false;
    if (code >= 0xD800 && code <= 0xDBFF) {
      // High surrogate: a low surrogate must follow.
      if (pos_ + 1 >= s_.size() || s_[pos_] != '\\' || s_[pos_ + 1] != 'u')
        return Fail("unpaired high surrogate");
      pos_ += 2;
      uint32_t low = 0;
      if (!ReadHex4(&low))
        return false;
      if (low < 0xDC00 || low > 0xDFFF)
        return Fail("invalid low surrogate");
      code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
    } else if (code >= 0xDC00 && code <= 0xDFFF) {
      return Fail("unexpected low surrogate");
    }
    AppendUtf8(code, out);
    return true;
  }

  bool ReadHex4(uint32_t* out) {
    if (pos_ + 4 > s_.size())
      return Fail("truncated \\u escape");
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
      char c = s_[pos_++];
      v <<= 4;
      if (c >= '0' && c <= '9')
        v |= static_cast<uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f')
        v |= static_cast<uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        v |= static_cast<uint32_t>(c - 'A' + 10);
      else
        return Fail("invalid hex digit in \\u escape");
    }
    *out = v;
    return true;
  }

  static void AppendUtf8(uint32_t code, std::string* out) {
    if (code <= 0x7F) {
      *out += static_cast<char>(code);
    } else if (code <= 0x7FF) {
      *out += static_cast<char>(0xC0 | (code >> 6));
      *out += static_cast<char>(0x80 | (code & 0x3F));
    } else if (code <= 0xFFFF) {
      *out += static_cast<char>(0xE0 | (code >> 12));
      *out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
      *out += static_cast<char>(0x80 | (code & 0x3F));
    } else {
      *out += static_cast<char>(0xF0 | (code >> 18));
      *out += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
      *out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
      *out += static_cast<char>(0x80 | (code & 0x3F));
    }
  }

  bool ParseBool(JsonValue* out) {
    if (s_.compare(pos_, 4, "true") == 0) {
      pos_ += 4;
      out->type = JsonValue::Type::kBool;
      out->bool_value = true;
      return true;
    }
    if (s_.compare(pos_, 5, "false") == 0) {
      pos_ += 5;
      out->type = JsonValue::Type::kBool;
      out->bool_value = false;
      return true;
    }
    return Fail("invalid literal");
  }

  bool ParseNull(JsonValue* out) {
    if (s_.compare(pos_, 4, "null") == 0) {
      pos_ += 4;
      out->type = JsonValue::Type::kNull;
      return true;
    }
    return Fail("invalid literal");
  }

  bool ParseNumber(JsonValue* out) {
    size_t start = pos_;
    if (!AtEnd() && Peek() == '-')
      ++pos_;
    if (AtEnd() || !IsDigit(Peek()))
      return Fail("invalid number");
    if (Peek() == '0') {
      ++pos_;  // a leading zero must stand alone
    } else {
      while (!AtEnd() && IsDigit(Peek()))
        ++pos_;
    }
    if (!AtEnd() && Peek() == '.') {
      ++pos_;
      if (AtEnd() || !IsDigit(Peek()))
        return Fail("invalid fraction");
      while (!AtEnd() && IsDigit(Peek()))
        ++pos_;
    }
    if (!AtEnd() && (Peek() == 'e' || Peek() == 'E')) {
      ++pos_;
      if (!AtEnd() && (Peek() == '+' || Peek() == '-'))
        ++pos_;
      if (AtEnd() || !IsDigit(Peek()))
        return Fail("invalid exponent");
      while (!AtEnd() && IsDigit(Peek()))
        ++pos_;
    }
    out->type = JsonValue::Type::kNumber;
    out->number_value = std::strtod(s_.c_str() + start, nullptr);
    return true;
  }

  static bool IsDigit(char c) { return c >= '0' && c <= '9'; }

  const std::string& s_;
  size_t pos_ = 0;
  std::string* error_;
};

// Decodes one binding value object { "type": ..., "value": ..., ... } into a
// SparqlTerm. Handles uri, literal, typed-literal (legacy), bnode, and the
// RDF-star triple term.
bool DecodeTerm(const JsonValue& node, SparqlTerm* out, std::string* error) {
  if (!node.is_object()) {
    if (error) *error = "binding value is not an object";
    return false;
  }
  const JsonValue* type = node.Find("type");
  if (!type || !type->is_string()) {
    if (error) *error = "binding value missing type";
    return false;
  }
  const std::string& t = type->string_value;
  if (t == "uri") {
    const JsonValue* v = node.Find("value");
    if (!v || !v->is_string()) {
      if (error) *error = "uri binding missing value";
      return false;
    }
    out->type = SparqlTermType::kUri;
    out->value = v->string_value;
    return true;
  }
  if (t == "bnode") {
    const JsonValue* v = node.Find("value");
    if (!v || !v->is_string()) {
      if (error) *error = "bnode binding missing value";
      return false;
    }
    out->type = SparqlTermType::kBlankNode;
    out->value = v->string_value;
    return true;
  }
  if (t == "literal" || t == "typed-literal") {
    const JsonValue* v = node.Find("value");
    if (!v || !v->is_string()) {
      if (error) *error = "literal binding missing value";
      return false;
    }
    out->type = SparqlTermType::kLiteral;
    out->value = v->string_value;
    if (const JsonValue* dt = node.Find("datatype"); dt && dt->is_string())
      out->datatype = dt->string_value;
    if (const JsonValue* lang = node.Find("xml:lang"); lang && lang->is_string())
      out->language = lang->string_value;
    return true;
  }
  if (t == "triple") {
    const JsonValue* v = node.Find("value");
    if (!v || !v->is_object()) {
      if (error) *error = "triple binding missing value";
      return false;
    }
    const JsonValue* subj = v->Find("subject");
    const JsonValue* pred = v->Find("predicate");
    const JsonValue* obj = v->Find("object");
    if (!subj || !pred || !obj) {
      if (error) *error = "triple term missing s/p/o";
      return false;
    }
    out->type = SparqlTermType::kTriple;
    out->components.resize(3);
    return DecodeTerm(*subj, &out->components[0], error) &&
           DecodeTerm(*pred, &out->components[1], error) &&
           DecodeTerm(*obj, &out->components[2], error);
  }
  if (error) *error = "unknown binding term type: " + t;
  return false;
}

}  // namespace

const JsonValue* JsonValue::Find(const std::string& key) const {
  if (type != Type::kObject)
    return nullptr;
  auto it = object_value.find(key);
  return it == object_value.end() ? nullptr : &it->second;
}

bool ParseJson(const std::string& text, JsonValue* out, std::string* error) {
  if (error)
    error->clear();
  JsonReader reader(text, error);
  return reader.ParseDocument(out);
}

bool DecodeSparqlSelect(const std::string& json,
                        SparqlSelect* out,
                        std::string* error) {
  if (error)
    error->clear();
  JsonValue root;
  if (!ParseJson(json, &root, error))
    return false;
  if (!root.is_object()) {
    if (error) *error = "results root is not an object";
    return false;
  }
  const JsonValue* head = root.Find("head");
  if (head) {
    if (const JsonValue* vars = head->Find("vars"); vars && vars->is_array()) {
      for (const JsonValue& var : vars->array_value) {
        if (!var.is_string()) {
          if (error) *error = "head.vars entry is not a string";
          return false;
        }
        out->vars.push_back(var.string_value);
      }
    }
  }
  const JsonValue* results = root.Find("results");
  if (!results || !results->is_object()) {
    if (error) *error = "results object missing";
    return false;
  }
  const JsonValue* bindings = results->Find("bindings");
  if (!bindings || !bindings->is_array()) {
    if (error) *error = "results.bindings is not an array";
    return false;
  }
  for (const JsonValue& row : bindings->array_value) {
    if (!row.is_object()) {
      if (error) *error = "binding row is not an object";
      return false;
    }
    SparqlSolution solution;
    for (const auto& [var, node] : row.object_value) {
      SparqlTerm term;
      if (!DecodeTerm(node, &term, error))
        return false;
      solution.bindings[var] = std::move(term);
    }
    out->solutions.push_back(std::move(solution));
  }
  return true;
}

bool DecodeSparqlBoolean(const std::string& json,
                         bool* out,
                         std::string* error) {
  if (error)
    error->clear();
  JsonValue root;
  if (!ParseJson(json, &root, error))
    return false;
  const JsonValue* boolean = root.Find("boolean");
  if (!boolean || !boolean->is_bool()) {
    if (error) *error = "ASK result missing boolean";
    return false;
  }
  *out = boolean->bool_value;
  return true;
}

}  // namespace living_web
