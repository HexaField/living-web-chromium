// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_GRAPH_GOVERNANCE_ZCAP_VERIFIER_H_
#define CONTENT_BROWSER_GRAPH_GOVERNANCE_ZCAP_VERIFIER_H_

#include <string>
#include <optional>

namespace content {

class GraphStore;
class DIDKeyProvider;

// ZcapDocument — parsed ZCAP-LD authorization capability.
struct ZcapDocument {
  std::string id;
  std::string invoker;              // DID of authorized agent
  std::string parent_capability;    // parent ZCAP id (empty for root-issued)
  std::vector<std::string> predicates;
  std::string scope_within;         // entity address (empty = whole graph)
  std::string scope_graph;
  std::string expires;              // RFC 3339 or empty
  std::string proof_json;
};

// ZcapVerifier — verifies ZCAP-LD delegation chains.
class ZcapVerifier {
 public:
  // Verify a ZCAP document.
  // Checks: signature, expiry, revocation, delegation chain depth (max 10).
  static bool Verify(const ZcapDocument& zcap,
                      const GraphStore& graph,
                      const DIDKeyProvider& key_provider,
                      const std::string& root_authority_did);

  // Verify the entire delegation chain for a ZCAP.
  static bool VerifyChain(const std::string& zcap_id,
                           const GraphStore& graph,
                           const DIDKeyProvider& key_provider,
                           const std::string& root_authority_did,
                           int max_depth = 10);

  // Check if a ZCAP covers a specific predicate and scope.
  static bool Covers(const ZcapDocument& zcap,
                      const std::string& predicate,
                      const std::string& scope_entity,
                      const GraphStore& graph);
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_GOVERNANCE_ZCAP_VERIFIER_H_
