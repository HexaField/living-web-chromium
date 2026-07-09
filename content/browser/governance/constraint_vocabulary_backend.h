// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Governance Constraint Vocabulary (Spec 08) — the browser-process binding.
//
// Implements the standard constraint kinds and caveat types of the Governance
// Constraint Vocabulary as plug-in handlers registered against the Spec 04
// content::GovernanceBackend (content/browser/governance/governance_backend.h).
// Spec 04 owns the capability-chain mechanism, enforcement modes, and the
// `expiry` core caveat; this vocabulary supplies *what other constraints and
// caveats exist* — the `credential` / `temporal` / `content` constraint kinds
// (§4–§6) and the `predicate` / `property` / `subject` / `object` / `rateLimit` /
// `cardinality` / `authorOnly` / `shape` / `content` / `credential` caveat types
// (§7).
//
// This is the browser twin of standalone/constraint_vocabulary_provider.h. Every
// pure decision the handlers reach — glob matching, the deny-wins allow/deny
// order, RFC-3339 arithmetic, the §6.2 content-policy order, the living-web VC
// pre-image — lives in the Chromium-independent core
// content/browser/governance/constraint_vocabulary.{h,cc}, shared byte-for-byte
// with the standalone harness so the two build worlds reach identical verdicts.
// This translation unit is the browser *binding* layer: it resolves graph state
// through content::GraphBackend, hashes with //crypto's crypto::SHA256HashString,
// verifies Ed25519 with third_party/ed25519, evaluates blocked-pattern regexes
// with RE2 (linear-time, so no worker thread or timeout is needed — the standalone
// uses std::regex on a bounded thread), and runs the `content` caveat's SPARQL ASK
// against an ephemeral in-memory Oxigraph store.
//
// Two seams are injected rather than hard-wired so the layering stays acyclic:
//   * the `shape` caveat (§7.8) takes a `shape_conforms` callback supplied by the
//     Spec 07 shape service — the vocabulary never re-implements SHACL, and an
//     unresolvable shape fails closed (§9.6);
//   * the regex matcher (§9.3) is the injected core cv::RegexMatcher, defaulting
//     to the RE2 matcher below.

#ifndef CONTENT_BROWSER_GOVERNANCE_CONSTRAINT_VOCABULARY_BACKEND_H_
#define CONTENT_BROWSER_GOVERNANCE_CONSTRAINT_VOCABULARY_BACKEND_H_

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "content/browser/governance/constraint_vocabulary.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/rdf_serialization.h"

namespace content {

class DIDKeyProvider;

namespace cv = living_web::constraint_vocab;

// ---- §7.5 / §7.6 usage ledger ----------------------------------------------

// The per-delegation counters that back the `rateLimit` (sliding window) and
// `cardinality` (lifetime) caveats. Owned by the vocabulary — NOT the backend —
// and injected into the two counting handlers as a shared_ptr, so a single
// process-wide ledger survives across every write the backend authorises. Keyed
// by (zcap.id, author) per §7.5/§7.6. Enforcement is against local state only;
// under concurrent multi-peer writes convergent over-use is possible and MUST be
// coordinated at the sync layer if strict bounds are required (§7.5, §13.11).
class UsageLedger {
 public:
  UsageLedger() = default;
  UsageLedger(const UsageLedger&) = delete;
  UsageLedger& operator=(const UsageLedger&) = delete;

  // §7.5 sliding window: true iff strictly fewer than |max_per_window| uses fall
  // in the trailing [now − window, now]. Records this use on success.
  bool CheckAndRecordRate(const std::string& zcap_id, const std::string& author,
                          int64_t max_per_window, int64_t window_seconds,
                          int64_t now_epoch) {
    if (max_per_window <= 0)
      return false;
    std::vector<int64_t>& uses = rate_[{zcap_id, author}];
    int64_t low = now_epoch - window_seconds;
    int64_t count = 0;
    for (int64_t t : uses)
      if (t >= low && t <= now_epoch)
        ++count;
    if (count >= max_per_window)
      return false;
    uses.push_back(now_epoch);
    return true;
  }

  // §7.6 lifetime cap: true iff strictly fewer than |max| prior uses. Records
  // this use on success.
  bool CheckAndRecordCardinality(const std::string& zcap_id,
                                 const std::string& author, int64_t max) {
    if (max <= 0)
      return false;
    int64_t& n = lifetime_[{zcap_id, author}];
    if (n >= max)
      return false;
    ++n;
    return true;
  }

 private:
  std::map<std::pair<std::string, std::string>, std::vector<int64_t>> rate_;
  std::map<std::pair<std::string, std::string>, int64_t> lifetime_;
};

// The signature the `shape` caveat (§7.8) delegates to: does |triple|'s subject
// conform to the shape named |shape_iri|, resolved against |graph| (and, per
// Spec 07 §7, graphs reachable through its participation chain)? Supplied by the
// Spec 07 shape service; when absent the caveat fails closed (§9.6).
using ShapeConformsFn = std::function<bool(GraphBackend* graph,
                                           const std::string& shape_iri,
                                           const living_web::Triple& triple)>;

// ---- §9.3 RE2 matcher ------------------------------------------------------

// The browser cv::RegexMatcher: evaluates |pattern| against |text| with RE2,
// whose guaranteed linear-time matching removes the ReDoS exposure the standalone
// bounds with a std::regex worker thread — so this matcher never returns
// kTimeout. A malformed pattern cannot match and is reported as kNoMatch (it
// blocks nothing), the same fail-open-on-malformed behaviour as the standalone.
// |timeout_ms| is accepted for signature parity with MakeStdRegexMatcher and is
// unused (RE2 needs no timeout).
cv::RegexMatcher MakeRe2Matcher(
    int timeout_ms = cv::kDefaultRegexTimeoutMillis);

// ---- registration ----------------------------------------------------------

// Configuration for RegisterConstraintVocabulary. Every field is optional; the
// defaults give a fully-functional vocabulary (a fresh ledger, the RE2 matcher,
// and a fail-closed shape caveat).
struct ConstraintVocabOptions {
  // The §7.5/§7.6 counter store. Defaults to a fresh internal ledger; supply one
  // to share counters across backends or to inspect them from a test.
  std::shared_ptr<UsageLedger> ledger;
  // The §9.3 blocked-pattern matcher. Defaults to MakeRe2Matcher().
  cv::RegexMatcher regex_matcher;
  // The §7.8 shape-conformance seam (from the Spec 07 shape service). When unset
  // the shape caveat fails closed (§9.6).
  ShapeConformsFn shape_conforms;
};

// Registers the full Spec 08 vocabulary — the three constraint kinds and ten
// caveat types (§2) — against |engine| via the framework plug-in mechanism
// (§9.3). Unknown kinds/types the engine still fails closed on its own.
void RegisterConstraintVocabulary(GovernanceBackend* engine,
                                  const ConstraintVocabOptions& options = {});

// ---- credential storage / integration helpers (§4.1) -----------------------

// Content address of the JCS-canonical form of |vc_json| (the address at which
// StoreCredential files it, and against which the credential handlers verify).
std::optional<std::string> CredentialAddress(const std::string& vc_json);

// Files |vc_json| into |W| under the §4.1 storage convention: the JCS-canonical
// VC body inline at its content address, linked from |author_did| via
// governance://has_credential. Writes are authored by W's active credential.
// Returns the content address in |*out_addr| on success.
bool StoreCredential(GraphBackend* W, const std::string& author_did,
                     const std::string& vc_json, std::string* out_addr);

// Marks the credential-status subject |status_id| revoked in |W| (writes
// status_id governance://revoked "true"). Authored by W's active credential.
bool RevokeCredentialStatus(GraphBackend* W, const std::string& status_id);

// Builds a living-web-profile VC (§4 amendment) as a JSON document whose Ed25519
// proof over SHA-256(BuildVcProofPreimage) is produced with |issuer_cred_id|.
// |issuer_did| MUST be the did:key of that credential (the profile pins issuers
// to did:key for self-contained verification). |types| is written verbatim, so
// include every type the constraint may require. The returned JSON re-parses to
// exactly the fields the pre-image was built from, so it verifies round-trip.
std::string MakeSignedLivingWebVc(
    DIDKeyProvider* identity, const std::string& issuer_cred_id,
    const std::string& issuer_did, const std::vector<std::string>& types,
    const std::string& subject_did, const std::string& issuance_date,
    const std::optional<std::string>& status_id = std::nullopt);

}  // namespace content

#endif  // CONTENT_BROWSER_GOVERNANCE_CONSTRAINT_VOCABULARY_BACKEND_H_
