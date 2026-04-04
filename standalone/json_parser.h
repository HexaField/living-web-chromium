// Minimal JSON parser - no external dependencies
#ifndef LIVING_WEB_JSON_PARSER_H_
#define LIVING_WEB_JSON_PARSER_H_

#include <string>
#include <unordered_map>
#include <vector>

namespace living_web {

// Minimal JSON object representation (string values only, plus array detection)
class JsonObject {
 public:
  bool has(const std::string& key) const {
    return fields_.count(key) > 0 || arrays_.count(key) > 0;
  }

  bool getString(const std::string& key, std::string& out) const {
    auto it = fields_.find(key);
    if (it == fields_.end()) return false;
    out = it->second;
    return true;
  }

  bool getArrayRaw(const std::string& key, std::string& out) const {
    auto it = arrays_.find(key);
    if (it == arrays_.end()) return false;
    out = it->second;
    return true;
  }

  std::unordered_map<std::string, std::string> fields_;
  std::unordered_map<std::string, std::string> arrays_;
};

class JsonParser {
 public:
  // Parse a JSON object string into a JsonObject.
  // Supports: string values, array values (as raw strings), numeric values.
  // Does NOT support nested objects as values (except in arrays).
  static bool Parse(const std::string& json, JsonObject& out) {
    out.fields_.clear();
    out.arrays_.clear();

    size_t i = 0;
    SkipWhitespace(json, i);
    if (i >= json.size() || json[i] != '{') return false;
    i++;

    while (i < json.size()) {
      SkipWhitespace(json, i);
      if (i >= json.size()) return false;
      if (json[i] == '}') return true;
      if (json[i] == ',') { i++; continue; }

      // Parse key
      std::string key;
      if (!ParseString(json, i, key)) return false;

      SkipWhitespace(json, i);
      if (i >= json.size() || json[i] != ':') return false;
      i++;
      SkipWhitespace(json, i);

      if (i >= json.size()) return false;

      if (json[i] == '"') {
        std::string value;
        if (!ParseString(json, i, value)) return false;
        out.fields_[key] = value;
      } else if (json[i] == '[') {
        std::string arr;
        if (!ExtractBracketed(json, i, '[', ']', arr)) return false;
        out.arrays_[key] = arr;
      } else if (json[i] == '{') {
        std::string obj;
        if (!ExtractBracketed(json, i, '{', '}', obj)) return false;
        out.fields_[key] = obj;
      } else {
        // number, bool, null
        size_t start = i;
        while (i < json.size() && json[i] != ',' && json[i] != '}' &&
               json[i] != ' ' && json[i] != '\n' && json[i] != '\r' &&
               json[i] != '\t')
          i++;
        out.fields_[key] = json.substr(start, i - start);
      }
    }
    return false;
  }

  // Parse a JSON array of objects, returning each object as a string.
  static std::vector<std::string> ParseArray(const std::string& json) {
    std::vector<std::string> result;
    size_t i = 0;
    SkipWhitespace(json, i);
    if (i >= json.size() || json[i] != '[') return result;
    i++;

    while (i < json.size()) {
      SkipWhitespace(json, i);
      if (i >= json.size()) break;
      if (json[i] == ']') break;
      if (json[i] == ',') { i++; continue; }

      if (json[i] == '{') {
        std::string obj;
        if (!ExtractBracketed(json, i, '{', '}', obj)) break;
        result.push_back(obj);
      } else if (json[i] == '"') {
        std::string str;
        if (!ParseString(json, i, str)) break;
        result.push_back(str);
      } else {
        // primitive
        size_t start = i;
        while (i < json.size() && json[i] != ',' && json[i] != ']') i++;
        result.push_back(json.substr(start, i - start));
      }
    }
    return result;
  }

 private:
  static void SkipWhitespace(const std::string& s, size_t& i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' ||
                             s[i] == '\n' || s[i] == '\r'))
      i++;
  }

  static bool ParseString(const std::string& s, size_t& i, std::string& out) {
    if (i >= s.size() || s[i] != '"') return false;
    i++;
    out.clear();
    while (i < s.size()) {
      if (s[i] == '\\' && i + 1 < s.size()) {
        i++;
        if (s[i] == '"') out += '"';
        else if (s[i] == '\\') out += '\\';
        else if (s[i] == 'n') out += '\n';
        else if (s[i] == 't') out += '\t';
        else out += s[i];
        i++;
      } else if (s[i] == '"') {
        i++;
        return true;
      } else {
        out += s[i];
        i++;
      }
    }
    return false;
  }

  static bool ExtractBracketed(const std::string& s, size_t& i,
                                 char open, char close, std::string& out) {
    if (i >= s.size() || s[i] != open) return false;
    int depth = 0;
    size_t start = i;
    bool in_string = false;
    while (i < s.size()) {
      if (s[i] == '"' && (i == 0 || s[i - 1] != '\\')) {
        in_string = !in_string;
      } else if (!in_string) {
        if (s[i] == open) depth++;
        else if (s[i] == close) {
          depth--;
          if (depth == 0) {
            i++;
            out = s.substr(start, i - start);
            return true;
          }
        }
      }
      i++;
    }
    return false;
  }
};

}  // namespace living_web

#endif  // LIVING_WEB_JSON_PARSER_H_
