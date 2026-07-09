// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/graph_diff.h"

#include <algorithm>
#include <cstdint>

namespace living_web {

std::string ToLowerHex(const std::string& bytes) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char c : bytes) {
    out.push_back(kDigits[c >> 4]);
    out.push_back(kDigits[c & 0x0f]);
  }
  return out;
}

std::vector<std::string> SortDependencies(
    const std::vector<std::string>& deps) {
  std::vector<std::string> out = deps;
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

std::string BuildRevisionPreimage(
    const std::string& graph_did,
    const std::string& canonical_additions,
    const std::string& canonical_removals,
    const std::vector<std::string>& sorted_dependencies) {
  std::string p = "living-web/sync/revision/v1";
  p += '\n';
  p += graph_did;
  p += '\n';
  p += std::to_string(canonical_additions.size());
  p += '\n';
  p += canonical_additions;
  p += std::to_string(canonical_removals.size());
  p += '\n';
  p += canonical_removals;
  p += std::to_string(sorted_dependencies.size());
  p += '\n';
  for (const auto& dep : sorted_dependencies) {
    p += dep;
    p += '\n';
  }
  return p;
}

std::string BuildCommitIdPreimage(const std::string& revision,
                                  const std::string& author,
                                  const std::string& timestamp,
                                  const std::string& leaf_zcap_id) {
  std::string p = "living-web/sync/commit/v1";
  p += '\n';
  p += revision;
  p += '\n';
  p += author;
  p += '\n';
  p += timestamp;
  p += '\n';
  p += leaf_zcap_id;
  return p;
}

std::string BuildSpaceDerivationInput(SpaceTopology topology,
                                      bool restricted,
                                      const std::string& namespace_id,
                                      const std::string& graph_did,
                                      const std::string& custom_name) {
  switch (topology) {
    case SpaceTopology::kUnified:
      return std::string("lwsync:unified:") + namespace_id;
    case SpaceTopology::kPrivacyTiered:
      return restricted ? std::string("lwsync:dedicated:") + graph_did
                        : std::string("lwsync:public:") + namespace_id;
    case SpaceTopology::kFullyPartitioned:
      return std::string("lwsync:dedicated:") + graph_did;
    case SpaceTopology::kCustom:
      return std::string("lwsync:named:") + custom_name;
  }
  return std::string("lwsync:unified:") + namespace_id;
}

}  // namespace living_web
