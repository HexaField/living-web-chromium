// Standalone compatibility shims for Chromium base:: APIs
#ifndef LIVING_WEB_STANDALONE_BASE_H_
#define LIVING_WEB_STANDALONE_BASE_H_

#include <cstdio>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <iomanip>

// Minimal logging
#define LOG(level) std::cerr << "[" #level "] "

namespace base {

// UUID generation
class Uuid {
 public:
  static Uuid GenerateRandomV4() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dist;
    
    uint32_t a = dist(gen), b = dist(gen), c = dist(gen), d = dist(gen);
    // Set version 4 and variant bits
    b = (b & 0xFFFF0FFF) | 0x00004000;
    c = (c & 0x3FFFFFFF) | 0x80000000;
    
    char buf[37];
    snprintf(buf, sizeof(buf),
             "%08x-%04x-%04x-%04x-%04x%08x",
             a, (b >> 16) & 0xFFFF, b & 0xFFFF,
             (c >> 16) & 0xFFFF, c & 0xFFFF, d);
    Uuid u;
    u.str_ = buf;
    return u;
  }
  
  std::string AsLowercaseString() const { return str_; }
  
 private:
  std::string str_;
};

// Minimal JSON support - just enough for the graph store
namespace json {

// Simple JSON string value extractor
inline bool ExtractStringField(const std::string& json,
                                const std::string& field,
                                std::string& out) {
  std::string key = "\"" + field + "\"";
  auto pos = json.find(key);
  if (pos == std::string::npos) return false;
  pos = json.find(':', pos + key.size());
  if (pos == std::string::npos) return false;
  pos = json.find('"', pos + 1);
  if (pos == std::string::npos) return false;
  auto end = json.find('"', pos + 1);
  if (end == std::string::npos) return false;
  out = json.substr(pos + 1, end - pos - 1);
  return true;
}

// Check if JSON has a key
inline bool HasField(const std::string& json, const std::string& field) {
  return json.find("\"" + field + "\"") != std::string::npos;
}

// Extract a JSON array (returns the raw substring between [ and ])
inline bool ExtractArray(const std::string& json,
                          const std::string& field,
                          std::string& out) {
  std::string key = "\"" + field + "\"";
  auto pos = json.find(key);
  if (pos == std::string::npos) return false;
  pos = json.find('[', pos);
  if (pos == std::string::npos) return false;
  int depth = 0;
  size_t start = pos;
  for (size_t i = pos; i < json.size(); ++i) {
    if (json[i] == '[') depth++;
    else if (json[i] == ']') {
      depth--;
      if (depth == 0) {
        out = json.substr(start, i - start + 1);
        return true;
      }
    }
  }
  return false;
}

// Extract array of JSON objects (very basic)
inline std::vector<std::string> ExtractObjectArray(const std::string& array_json) {
  std::vector<std::string> result;
  int depth = 0;
  size_t start = 0;
  for (size_t i = 0; i < array_json.size(); ++i) {
    if (array_json[i] == '{') {
      if (depth == 0) start = i;
      depth++;
    } else if (array_json[i] == '}') {
      depth--;
      if (depth == 0) {
        result.push_back(array_json.substr(start, i - start + 1));
      }
    }
  }
  return result;
}

}  // namespace json
}  // namespace base

#endif  // LIVING_WEB_STANDALONE_BASE_H_
