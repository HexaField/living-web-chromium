// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// SyncBackend — the browser-process port of the Graph Synchronisation Protocol
// (Spec 05). A faithful C++ port of living_web::SyncEngine
// (standalone/sync_provider.h) onto the browser cores content::GraphBackend (the
// Spec 02 host graph a diff is committed to / validated against), content::
// GovernanceBackend (the Spec 04 authority every §9.2.1 capability check is
// delegated to), and content::DIDKeyProvider (which stores the credentials whose
// keys sign diffs). The two ports share the Chromium-independent byte-critical
// core content/browser/graph_sync/graph_diff.{h,cc} — the revision/commitId
// pre-images (pinned by SPEC_COMPLIANCE amendment 05/§5.2.2.1) and the space://
// derivation input — so the bytes a diff is content-addressed and signed over,
// and the sync-space a graph derives, are identical between the standalone
// conformance harness and this backend.
//
// What it implements, normatively:
//   * GraphDiff construction (§5.2.2): committer-authored reifiers, rdfc-1.0
//     canonicalisation of the triples-with-reifiers, revision/commitId hashing,
//     and an Ed25519 signature over the UTF-8 lowercase-hex commitId.
//   * validateDiff (§9.2.1) steps 0–6: bundle-signature verification with
//     authorKey resolution (did:key, or a current capabilityDelegation delegate
//     for graph-DID authors), capability-chain + caveat validation delegated to
//     GovernanceBackend (which honours §9.4 enforcement-mode awareness),
//     per-reifier signature verification with the §5.2.2 committer-binding,
//     dependency validation (§5.2.1), and timestamp plausibility (§14.5).
//   * validateReadAccess (§9.2.2): the mountContext gate.
//   * sync-space derivation (§7.3) and the public/restricted topology
//     classification (§7.2), keyed off read-access constraints not enforcement
//     mode.
//   * graph invitation links (§12): web+graph:// format + parse.
//   * reconnection primitives (§13): the durable diff queue keyed by commitId,
//     exponential backoff (§13.3), and the batching policy (§13.4).
//
// SyncBackend is a per-graph-realm object (like living_web::SyncEngine it carries
// the local per-graph revision chains and operates on whichever GraphBackend* W
// is passed to each call); PersonalGraphManager owns one and shares it with every
// PersonalGraphHost so the §11 renderer surface (a `partial interface Graph` /
// `partial interface GraphManager`) and the §9.3 sync-blocking rule run against a
// single chain view.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_SYNC_BACKEND_H_
#define CONTENT_BROWSER_GRAPH_SYNC_SYNC_BACKEND_H_

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph_sync/graph_diff.h"

namespace content {

// ---- data model (§5) -------------------------------------------------------

// A triple together with the committer-authored reifier that binds its
// provenance (§5.1, [[PERSONAL-LINKED-DATA-GRAPHS]] §3.2). The reifier fields are
// exactly those living_web::BuildTripleWithReifierNquads serialises, so the wire
// bytes a diff is canonicalised over reproduce on any peer.
struct DiffTriple {
  living_web::Triple triple;
  std::string author;     // did:key / did:graph of the committer
  std::string timestamp;  // RFC 3339
  std::string method;     // verification-method id (author '#' multibase key)
  std::string signature;  // multibase Ed25519 over SHA-256(§3.2.1 pre-image)
};

// §5.3 CapabilityProof (the backend resolves the chain from the target graph's
// local store; VerifiablePresentations are a browser/VC concern layered above).
struct CapabilityProof {
  std::vector<std::string> chain;              // ordered leaf → root
  std::vector<std::string> caveats_satisfied;  // audit trail (§5.3)
  bool has_content_caveats = false;            // optimisation hint (§5.3)
};

// §5.1 GraphDiff — the unit of gossip.
struct GraphDiff {
  std::string graph_did;
  std::string revision;   // hex — triple-set identity (§5.2.2)
  std::string commit_id;  // hex — full commit identity (§5.2.2)
  std::vector<DiffTriple> additions;
  std::vector<DiffTriple> removals;
  std::vector<std::string> dependencies;  // DAG heads = revisions (§5.2.1)
  std::optional<CapabilityProof> capability_proof;
  std::string author;     // did:key / did:graph of the committing agent
  std::string timestamp;  // RFC 3339, authoritative commit time (§14.5)
  uint32_t diffs_since_snapshot = 0;  // §5.2.3
  bool snapshot_promotion = false;    // advertises a snapshot promotion (§5.2.1)
  std::string signature;  // multibase Ed25519 over UTF-8 hex commitId (§5.2.2)
};

// §5.6 SyncValidationResult.
struct SyncValidationResult {
  bool accepted = true;
  std::string constraint_kind;  // "capability" | plug-in kind | ""
  std::string constraint_id;
  std::string reason;
};

// Parameters for a commit (§5.2).
struct CommitOptions {
  std::vector<std::string> dependencies;  // parent revisions (unsorted ok)
  std::optional<CapabilityProof> capability_proof;
  uint32_t diffs_since_snapshot = 0;
  bool snapshot_promotion = false;
  std::string timestamp;  // empty → NowRfc3339()
};

namespace sync_detail {

// ---- base64url (RFC 4648 §5, no padding) — invitation space-uri (§12.1) -----

inline std::string Base64UrlEncode(const std::string& in) {
  static const char kEnc[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve((in.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    uint32_t n = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8) |
                 uint8_t(in[i + 2]);
    out.push_back(kEnc[(n >> 18) & 63]);
    out.push_back(kEnc[(n >> 12) & 63]);
    out.push_back(kEnc[(n >> 6) & 63]);
    out.push_back(kEnc[n & 63]);
  }
  if (i + 1 == in.size()) {
    uint32_t n = uint8_t(in[i]) << 16;
    out.push_back(kEnc[(n >> 18) & 63]);
    out.push_back(kEnc[(n >> 12) & 63]);
  } else if (i + 2 == in.size()) {
    uint32_t n = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8);
    out.push_back(kEnc[(n >> 18) & 63]);
    out.push_back(kEnc[(n >> 12) & 63]);
    out.push_back(kEnc[(n >> 6) & 63]);
  }
  return out;
}

inline bool Base64UrlDecode(const std::string& in, std::string* out) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
  };
  out->clear();
  uint32_t buf = 0;
  int bits = 0;
  for (char c : in) {
    int v = val(c);
    if (v < 0)
      return false;
    buf = (buf << 6) | uint32_t(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out->push_back(char((buf >> bits) & 0xff));
    }
  }
  return true;
}

// ---- percent-encoding (RFC 3986 §2.1) — invitation `name` (§12.1) -----------

inline std::string PercentEncode(const std::string& in) {
  static const char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(in.size());
  for (unsigned char c : in) {
    bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                      c == '_' || c == '~';
    if (unreserved) {
      out.push_back(char(c));
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 0x0f]);
    }
  }
  return out;
}

inline bool PercentDecode(const std::string& in, std::string* out) {
  auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  out->clear();
  for (size_t i = 0; i < in.size(); ++i) {
    if (in[i] == '%') {
      if (i + 2 >= in.size())
        return false;
      int hi = hex(in[i + 1]), lo = hex(in[i + 2]);
      if (hi < 0 || lo < 0)
        return false;
      out->push_back(char((hi << 4) | lo));
      i += 2;
    } else if (in[i] == '+') {
      out->push_back(' ');
    } else {
      out->push_back(in[i]);
    }
  }
  return true;
}

// ---- RFC 3339 → Unix epoch seconds (§14.5 plausibility) --------------------

// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard Hinnant's
// algorithm). Valid for the full range this engine ever sees.
inline int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

inline bool Rfc3339ToEpoch(const std::string& s, int64_t* out) {
  int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
  if (std::sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &se) != 6)
    return false;
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60)
    return false;
  int64_t epoch = ((DaysFromCivil(y, unsigned(mo), unsigned(d)) * 24 + h) * 60 +
                   mi) * 60 + se;
  // Timezone designator: 'Z' (or absent) = UTC; else ±HH:MM applied.
  size_t tpos = s.find('T');
  if (tpos != std::string::npos && !s.empty() && s.back() != 'Z') {
    for (size_t i = tpos + 1; i < s.size(); ++i) {
      if (s[i] == '+' || s[i] == '-') {
        int oh = 0, om = 0;
        if (std::sscanf(s.c_str() + i + 1, "%d:%d", &oh, &om) >= 1) {
          int64_t off = int64_t(oh) * 3600 + int64_t(om) * 60;
          epoch += (s[i] == '+') ? -off : off;
        }
        break;
      }
    }
  }
  *out = epoch;
  return true;
}

}  // namespace sync_detail

// ---- reconnection primitives (§13) -----------------------------------------

// §13.3 exponential backoff: initial 5 s, ×2 per failed attempt, capped at
// 300 s. |attempt| is 0 for the first retry. Jitter (§13.3) is left to the
// caller; this returns the deterministic base delay.
inline uint64_t ReconnectBackoffMs(unsigned attempt) {
  uint64_t delay = 5000;
  for (unsigned i = 0; i < attempt && delay < 300000; ++i)
    delay *= 2;
  return delay > 300000 ? 300000 : delay;
}

// §13.4 batching policy constants.
inline constexpr size_t kBatchMaxDiffs = 100;
inline constexpr uint64_t kBatchMaxMillis = 3000;

// §13.1 the durable local diff queue: locally-committed diffs not yet
// acknowledged by a remote peer, indexed and de-duplicated by commitId,
// preserving commit order for the §13.2 flush.
class DiffQueue {
 public:
  // Enqueues |diff| unless its commitId is already queued. Returns true if it
  // was newly enqueued.
  bool Enqueue(const GraphDiff& diff) {
    if (index_.count(diff.commit_id))
      return false;
    index_.insert(diff.commit_id);
    order_.push_back(diff);
    return true;
  }

  bool Contains(const std::string& commit_id) const {
    return index_.count(commit_id) != 0;
  }

  size_t Size() const { return order_.size(); }
  bool Empty() const { return order_.empty(); }

  // §13.4 the next batch to flush: up to |max| diffs in commit order. Does not
  // remove them (they are removed on acknowledgement).
  std::vector<GraphDiff> NextBatch(size_t max = kBatchMaxDiffs) const {
    std::vector<GraphDiff> out;
    for (const auto& d : order_) {
      if (out.size() >= max)
        break;
      out.push_back(d);
    }
    return out;
  }

  // Removes an acknowledged diff (§13.2 step 2). Returns true if present.
  bool Acknowledge(const std::string& commit_id) {
    auto it = index_.find(commit_id);
    if (it == index_.end())
      return false;
    index_.erase(it);
    order_.erase(std::remove_if(order_.begin(), order_.end(),
                                [&](const GraphDiff& d) {
                                  return d.commit_id == commit_id;
                                }),
                 order_.end());
    return true;
  }

  void Clear() {
    index_.clear();
    order_.clear();
  }

 private:
  std::set<std::string> index_;
  std::vector<GraphDiff> order_;
};

// ---- SyncBackend (§5–§14) --------------------------------------------------

class SyncBackend {
 public:
  SyncBackend(DIDKeyProvider* identity, GovernanceBackend* governance)
      : identity_(identity), governance_(governance) {}

  SyncBackend(const SyncBackend&) = delete;
  SyncBackend& operator=(const SyncBackend&) = delete;

  const std::string& last_error() const { return last_error_; }

  // ---- §5.2.2 diff construction ----

  // Builds a signed GraphDiff for |graph W| authored by |author_cred_id|.
  // Computes the committer-authored reifiers, canonicalises the
  // triples-with-reifiers with rdfc-1.0, and derives revision/commitId/signature
  // per §5.2.2 (framed by amendment 05/§5.2.2.1). Records the new revision in the
  // committer's local chain so subsequent commits can depend on it. Does not
  // mutate W (the caller applies the additions to local state if desired).
  bool CommitDiff(GraphBackend* W,
                  const std::string& author_cred_id,
                  const std::vector<living_web::Triple>& additions,
                  const std::vector<living_web::Triple>& removals,
                  const CommitOptions& opts,
                  GraphDiff* out);

  // ---- §9.2.1 validateDiff ----

  // Runs steps 0–6 against the target graph's local state |W|. Returns
  // { accepted: true } or a populated rejection. Deterministic: every honest
  // peer with the same view of W reaches the same verdict (§9.2.1), which is
  // what makes the §9.3 sync-blocking rule converge. On acceptance the diff's
  // revision enters the local chain (so it may satisfy later dependencies and a
  // replay is a no-op, §14.4).
  SyncValidationResult ValidateDiff(GraphBackend* W, const GraphDiff& diff);

  // ---- §9.2.2 validateReadAccess ----

  // The mountContext gate for a snapshot pull or read-mode mount. Accepts when
  // the graph carries no mountContext capability constraint (unrestricted read),
  // or when the supplied proof authorises the operation.
  SyncValidationResult ValidateReadAccess(
      GraphBackend* W,
      const std::string& author_did,
      const std::optional<CapabilityProof>& /*proof*/) {
    SyncValidationResult res;
    GovernanceValidationResult g =
        governance_->CanPerformAction(W, "mountContext", author_did);
    if (!g.allowed)
      Reject(&res, g.constraint_kind.empty() ? "capability" : g.constraint_kind,
             g.rejected_by, g.reason);
    return res;
  }

  // ---- §7 sync spaces ----

  // §7.2 classification: a graph is *restricted* for read iff it binds a
  // capability constraint (which covers the non-triple mountContext action,
  // §7.1). Keys off the constraint's presence, not enforcement mode (§7.2).
  bool IsRestricted(GraphBackend* W) {
    std::optional<std::string> wdid = W ? W->did() : std::nullopt;
    if (!wdid)
      return false;
    for (const GraphConstraint& c : governance_->ConstraintsFor(W, *wdid))
      if (c.kind == living_web::kConstraintKindCapability)
        return true;
    return false;
  }

  // §7.3 space derivation → "space://<sha256-hex>". |custom_name| is used only
  // for the custom topology. The namespace-id is the graph's
  // context://participates_in root (fallback: the graph DID).
  std::optional<std::string> DeriveSpace(
      GraphBackend* W,
      living_web::SpaceTopology topology,
      const std::string& custom_name = std::string());

  // ---- §12 invitation links ----

  struct Invitation {
    std::string relay_host;
    std::string space_uri;
    std::string graph_did;
    std::string module_hash;  // "" → default module (§12.1)
    std::string name;         // "" → absent
  };

  // §12.1 format:
  //   web+graph://<relay-host>/<space-uri-base64url>?did=<did>&module=<hash>&name=<name>
  static std::string FormatInvitation(const std::string& relay_host,
                                      const std::string& space_uri,
                                      const std::string& graph_did,
                                      const std::string& module_hash = "",
                                      const std::string& name = "") {
    std::string uri = "web+graph://" + relay_host + "/" +
                      sync_detail::Base64UrlEncode(space_uri) +
                      "?did=" + sync_detail::PercentEncode(graph_did);
    if (!module_hash.empty())
      uri += "&module=" + sync_detail::PercentEncode(module_hash);
    if (!name.empty())
      uri += "&name=" + sync_detail::PercentEncode(name);
    return uri;
  }

  // §12.2 processing model step 1: parse. `did` is REQUIRED; `module`/`name` are
  // OPTIONAL. Returns false on a malformed URI or a missing DID.
  static bool ParseInvitation(const std::string& uri, Invitation* out) {
    static const std::string kScheme = "web+graph://";
    if (uri.rfind(kScheme, 0) != 0)
      return false;
    std::string rest = uri.substr(kScheme.size());
    size_t slash = rest.find('/');
    if (slash == std::string::npos)
      return false;
    out->relay_host = rest.substr(0, slash);
    std::string after = rest.substr(slash + 1);
    size_t q = after.find('?');
    std::string path = after.substr(0, q);
    if (!sync_detail::Base64UrlDecode(path, &out->space_uri))
      return false;
    out->graph_did.clear();
    out->module_hash.clear();
    out->name.clear();
    bool have_did = false;
    if (q != std::string::npos) {
      std::string query = after.substr(q + 1);
      size_t pos = 0;
      while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        std::string pair = query.substr(pos, amp - pos);
        pos = (amp == std::string::npos) ? query.size() : amp + 1;
        size_t eq = pair.find('=');
        if (eq == std::string::npos)
          continue;
        std::string key = pair.substr(0, eq);
        std::string val;
        if (!sync_detail::PercentDecode(pair.substr(eq + 1), &val))
          return false;
        if (key == "did") {
          out->graph_did = val;
          have_did = true;
        } else if (key == "module") {
          out->module_hash = val;
        } else if (key == "name") {
          out->name = val;
        }
      }
    }
    return have_did && !out->graph_did.empty();
  }

  // ---- test / recovery introspection ----

  // Whether |graph_did| has any locally-known chain (used by the §5.2.1
  // chain-root rule and by recovery).
  bool HasChain(const std::string& graph_did) {
    return !Chain(graph_did).revisions.empty();
  }

  size_t ChainLength(const std::string& graph_did) {
    return Chain(graph_did).revisions.size();
  }

 private:
  struct ChainState {
    std::set<std::string> revisions;                  // known revisions
    std::map<std::string, std::string> ts_of;         // revision → timestamp
    std::map<std::string, std::string> author_max;    // author → max applied ts
  };

  ChainState& Chain(const std::string& graph_did) { return chains_[graph_did]; }

  static SyncValidationResult& Reject(SyncValidationResult* res,
                                      const std::string& kind,
                                      const std::string& id,
                                      const std::string& reason) {
    res->accepted = false;
    res->constraint_kind = kind;
    res->constraint_id = id;
    res->reason = reason;
    return *res;
  }

  // Computes committer-authored reifiers for |triples| (§3.2.1): sign
  // SHA-256(living_web::BuildSignaturePreimage(triple, timestamp, graphDid))
  // with the committer's key. graphDid is the stable graph identifier a receiver
  // reproduces (a synced graph always has a DID, so GraphIdentifier() == DID).
  bool AuthorReifiers(const std::string& graph_did,
                      const DIDKeyPair* author,
                      const std::vector<living_web::Triple>& triples,
                      const std::string& timestamp,
                      const std::string& method,
                      std::vector<DiffTriple>* out);

  // rdfc-1.0 canonical N-Quads of the triples-with-reifiers block. Each triple's
  // six-line reifier document (data triple + rdf:reifies + four prov://) is
  // concatenated under a distinct blank-node label; rdfc-1.0 relabels them
  // canonically, so the input labels do not affect the output. Empty input
  // canonicalises to the empty string.
  static bool CanonicalizeDiffTriples(const std::vector<DiffTriple>& triples,
                                      std::string* out,
                                      std::string* err);

  // §5.2.2 authorKey resolution: the author's did:key, or — for a graph-DID
  // author — the current capabilityDelegation delegate keys projected from the
  // author's DID document in |W|.
  std::vector<std::vector<uint8_t>> ResolveAuthorKeys(GraphBackend* W,
                                                      const std::string& author);

  // §9.2.1 step 0: verify |diff.signature| over the UTF-8 lowercase-hex commitId
  // (signed directly, not re-hashed — amendment 05/§5.2.2.1).
  bool VerifyBundleSignature(GraphBackend* W,
                             const GraphDiff& diff,
                             const std::string& commit_id);

  // §9.2.1 step 4: verify a reifier signature (§3.2.1 payload = SHA-256 of the
  // pre-image, signed raw) against the committer's resolved key. |diff_author| is
  // the diff's committing agent; every reifier MUST be attributed to it (§5.2.2),
  // so a reifier naming a different author is rejected before any key work.
  bool VerifyReifier(GraphBackend* W,
                     const std::string& graph_did,
                     const std::string& diff_author,
                     const DiffTriple& dt);

  // §5.2.1 dependency validation. A |deps|=0 diff is a chain root — valid only
  // as the first diff for the graph or when it advertises a snapshot promotion.
  // Otherwise every named revision MUST already be known locally.
  bool ValidateDependencies(const GraphDiff& diff);

  // §14.5 timestamp plausibility: future bound (>300 s ahead), causal
  // monotonicity (≥ max dependency timestamp), and per-author monotonicity.
  bool CheckTimestamp(const GraphDiff& diff, std::string* reason);

  // Records an accepted (or locally-committed) diff into the graph's chain.
  void RecordAccepted(const GraphDiff& diff);

  raw_ptr<DIDKeyProvider> identity_;      // Not owned.
  raw_ptr<GovernanceBackend> governance_;  // Not owned.
  std::map<std::string, ChainState> chains_;
  std::string last_error_;
  std::string dependency_error_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_SYNC_BACKEND_H_
