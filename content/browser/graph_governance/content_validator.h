// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GOVERNANCE_CONTENT_VALIDATOR_H_
#define CONTENT_BROWSER_GRAPH_GOVERNANCE_CONTENT_VALIDATOR_H_

#include <string>
#include <vector>
#include <optional>

namespace content {

// ContentValidator — validates triple target content against rules.
// Checks: text length, blocked patterns (regex), URL policy, media types.
class ContentValidator {
 public:
  struct ContentConfig {
    std::vector<std::string> blocked_patterns;  // regex
    std::optional<uint32_t> max_text_length;
    std::optional<uint32_t> min_text_length;
    std::string url_policy;  // "allow_all", "block_all", "allowlist", "blocklist"
    std::vector<std::string> url_list;
    std::vector<std::string> allowed_media_types;
    std::vector<std::string> applies_to_predicates;
  };

  struct ValidateResult {
    bool valid = true;
    std::string reason;
  };

  // Validate content against configuration.
  static ValidateResult Validate(const ContentConfig& config,
                                  const std::string& content,
                                  const std::string& predicate);

  // Check if a string contains URLs.
  static bool ContainsURL(const std::string& text);

  // Extract URLs from text.
  static std::vector<std::string> ExtractURLs(const std::string& text);
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GOVERNANCE_CONTENT_VALIDATOR_H_
