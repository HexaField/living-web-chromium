// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GOVERNANCE_TEMPORAL_ENGINE_H_
#define CONTENT_BROWSER_GRAPH_GOVERNANCE_TEMPORAL_ENGINE_H_

#include <string>
#include <optional>

namespace content {

// TemporalEngine — rate limiting for triple creation.
// Checks min_interval_seconds and max_count_per_window constraints.
class TemporalEngine {
 public:
  struct TemporalConfig {
    std::optional<uint32_t> min_interval_seconds;
    std::optional<uint32_t> max_count_per_window;
    uint32_t window_seconds = 60;
    std::vector<std::string> applies_to_predicates;
  };

  struct CheckResult {
    bool allowed = true;
    std::string reason;
  };

  // Check if an agent can create a triple given temporal constraints.
  // `last_timestamp` — RFC 3339 of agent's most recent matching triple.
  // `count_in_window` — number of matching triples in current window.
  static CheckResult Check(const TemporalConfig& config,
                            const std::string& current_timestamp,
                            const std::string& last_timestamp,
                            uint32_t count_in_window);
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GOVERNANCE_TEMPORAL_ENGINE_H_
