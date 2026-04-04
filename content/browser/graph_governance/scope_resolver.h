// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GOVERNANCE_SCOPE_RESOLVER_H_
#define CONTENT_BROWSER_GRAPH_GOVERNANCE_SCOPE_RESOLVER_H_

#include <string>
#include <vector>

namespace content {

class GraphStore;

// ScopeResolver — walks entity hierarchy to build scope chains.
// Used by GovernanceEngine for constraint inheritance.
class ScopeResolver {
 public:
  // Resolve the scope chain from entity up to graph root.
  // Returns ordered list: [entity, parent, grandparent, ..., root].
  static std::vector<std::string> Resolve(const GraphStore& graph,
                                           const std::string& entity);

  // Check if `descendant` is within the scope of `ancestor`.
  static bool IsInScope(const GraphStore& graph,
                         const std::string& descendant,
                         const std::string& ancestor);
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GOVERNANCE_SCOPE_RESOLVER_H_
