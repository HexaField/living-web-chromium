// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Governance Constraint Vocabulary (Spec 08) — the Chromium-independent core.
//
// Spec 08 is a plug-in vocabulary layered on the Graph Capability Framework
// (Spec 04, content/browser/governance/zcap.* + the engine). Spec 04 supplies the
// ConstraintKindHandler / CaveatHandler seams and evaluates `capability`
// constraints and the built-in `expiry` caveat; Spec 08 defines *what other
// constraints and caveats exist* — the `credential` / `temporal` / `content`
// constraint kinds (§4–§6) and the `predicate` / `property` / `subject` /
// `object` / `rateLimit` / `cardinality` / `authorOnly` / `shape` / `content` /
// `credential` caveat types (§7).
//
// This translation unit holds the pure-decision core those handlers share
// byte-for-byte between the standalone harness
// (standalone/constraint_vocabulary_provider.h) and the browser governance
// service. It performs NO hashing, NO regex evaluation, and NO graph I/O — those
// resolve to per-build-world primitives (standalone/crypto_sha2.h vs //crypto;
// std::regex+std::async vs RE2; the standalone Graph vs GraphBackend). What lives
// here is everything whose *bytes or verdict must not diverge*:
//
//   * the §11 governance:// predicate vocabulary and the constraint-kind /
//     caveat-type tokens;
//   * §7.4 glob matching and the §7.2/§7.3 deny-wins allow/deny decision;
//   * RFC-3339 → epoch conversion and the §5.3 timestamp-plausibility partial
//     order (future bound, causal monotonicity, per-author monotonicity);
//   * the §6.2 content policy evaluated over already-resolved object text, with
//     the regex engine injected (§9.3 fail-closed on timeout) so the DoS-timeout
//     policy is identical while the matcher differs per world;
//   * the living-web Verifiable-Credential profile (§4 amendment): the VC JSON
//     shape and the exact field-projection pre-image its Ed25519 proof signs —
//     the caller SHA-256s and verifies, mirroring the ZCAP delegation pre-image
//     in zcap.cc.
//
// Like zcap.cc and shape_definition.cc, this file has no Chromium dependencies
// (only the C++ standard library plus the equally-independent sparql_results.h
// JSON model) so it compiles verbatim in both build worlds.

#ifndef CONTENT_BROWSER_GOVERNANCE_CONSTRAINT_VOCABULARY_H_
#define CONTENT_BROWSER_GOVERNANCE_CONSTRAINT_VOCABULARY_H_

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace living_web {
namespace constraint_vocab {

// ---- constraint-kind tokens (§3, §4.1, §5.1, §6.1) -------------------------
inline constexpr char kKindCredential[] = "credential";
inline constexpr char kKindTemporal[] = "temporal";
inline constexpr char kKindContent[] = "content";

// ---- caveat-type tokens (§7) -----------------------------------------------
inline constexpr char kCaveatPredicate[] = "predicate";
inline constexpr char kCaveatProperty[] = "property";
inline constexpr char kCaveatSubject[] = "subject";
inline constexpr char kCaveatObject[] = "object";
inline constexpr char kCaveatRateLimit[] = "rateLimit";
inline constexpr char kCaveatCardinality[] = "cardinality";
inline constexpr char kCaveatAuthorOnly[] = "authorOnly";
inline constexpr char kCaveatShape[] = "shape";
inline constexpr char kCaveatContent[] = "content";
inline constexpr char kCaveatCredential[] = "credential";

// ---- §11 predicate reference table -----------------------------------------
// credential (§4)
inline constexpr char kGovRequiresCredentialType[] =
    "governance://requires_credential_type";
inline constexpr char kGovCredentialIssuerPattern[] =
    "governance://credential_issuer_pattern";
inline constexpr char kGovCredentialMinAgeHours[] =
    "governance://credential_min_age_hours";
inline constexpr char kGovHasCredential[] = "governance://has_credential";
// temporal (§5)
inline constexpr char kGovTemporalMinIntervalSeconds[] =
    "governance://temporal_min_interval_seconds";
inline constexpr char kGovTemporalMaxCountPerWindow[] =
    "governance://temporal_max_count_per_window";
inline constexpr char kGovTemporalWindowSeconds[] =
    "governance://temporal_window_seconds";
inline constexpr char kGovTemporalAppliesToPredicates[] =
    "governance://temporal_applies_to_predicates";
// content (§6)
inline constexpr char kGovContentAppliesToPredicates[] =
    "governance://content_applies_to_predicates";
inline constexpr char kGovContentBlockedPatterns[] =
    "governance://content_blocked_patterns";
inline constexpr char kGovContentAllowUrls[] = "governance://content_allow_urls";
inline constexpr char kGovContentAllowedDomains[] =
    "governance://content_allowed_domains";
inline constexpr char kGovContentAllowMediaTypes[] =
    "governance://content_allow_media_types";
inline constexpr char kGovContentMaxLength[] = "governance://content_max_length";

// The predicate that carries a content-addressed VC body inline at its own
// address, mirroring Spec 07's `shape://definition` inline-literal convention
// (SPEC_COMPLIANCE amendment 08/§4.1): `<addr> -[credential_body]-> JCS(vc)`.
inline constexpr char kGovCredentialBody[] = "governance://credential_body";

// §4.2.2.7 revocation, evaluated against local state (SPEC_COMPLIANCE amendment
// 08/§4.2): a VC's `credentialStatus.id` is a graph subject; the credential is
// revoked iff that subject bears `governance://revoked "true"`. Absence means
// not-revoked (a peer that has never received a revocation indication treats the
// credential as live). The literal a live-vs-revoked decision compares against is
// fixed so both build worlds reach the same verdict.
inline constexpr char kGovRevoked[] = "governance://revoked";
inline constexpr char kRevokedTrue[] = "true";

// ---- fixed protocol constants ----------------------------------------------
// §5.3 future-bound: a diff timestamp more than this many seconds ahead of the
// receiver's wall clock is inadmissible. Fixed, not configurable, so every honest
// peer computes the same verdict.
inline constexpr int64_t kFutureBoundSeconds = 300;
// §5.1 default temporal window when temporal_window_seconds is unset.
inline constexpr int64_t kDefaultTemporalWindowSeconds = 60;
// §9.3 RECOMMENDED per-pattern regex timeout.
inline constexpr int kDefaultRegexTimeoutMillis = 10;

// ---- string helpers --------------------------------------------------------

// Splits a comma-separated list into trimmed, non-empty tokens (predicate lists,
// domain lists, media-type globs).
std::vector<std::string> SplitOnComma(const std::string& raw);

// Splits a pipe-separated regex list (§6.1) into non-empty segments. Segments are
// NOT trimmed — leading/trailing whitespace is significant inside a regex — but
// empty segments (which would match everything) are dropped.
std::vector<std::string> SplitOnPipe(const std::string& raw);

// Parses a boolean-string literal ("true"/"false", case-insensitive). Returns
// false if the value is neither.
bool ParseBoolString(const std::string& raw, bool* out);

// Parses a base-10 signed integer, rejecting trailing junk. Returns false on any
// malformation.
bool ParseInt64(const std::string& raw, int64_t* out);

// ---- §7.4 glob matching ----------------------------------------------------

// True iff |text| matches |pattern|, where `*` matches any (possibly empty)
// sequence and every other character matches literally. Linear-time, no
// backtracking blowup.
bool GlobMatch(const std::string& pattern, const std::string& text);

// ---- §7.2 / §7.3 allow/deny (deny-wins) ------------------------------------

enum class AllowDeny {
  kAccept,      // permitted
  kDenied,      // value is in |denied|
  kNotAllowed,  // |allowed| is non-empty and does not contain the value
};

// The deny-wins-within-caveat decision of §7.2: denied first, then a non-empty
// allow-list acts as a whitelist.
AllowDeny EvalAllowDeny(const std::vector<std::string>& allowed,
                        const std::vector<std::string>& denied,
                        const std::string& value);

// ---- RFC 3339 → epoch ------------------------------------------------------

// Parses an RFC 3339 date-time (e.g. "2026-07-08T12:34:56Z", with optional
// fractional seconds and a "Z" or "±HH:MM" offset) to whole seconds since the
// Unix epoch (UTC). Returns false on malformation. Uses the days-from-civil
// algorithm, so it is timezone-independent and has no year-2038 limitation.
bool ParseRfc3339ToEpoch(const std::string& rfc3339, int64_t* out_epoch_seconds);

// ---- §5.3 timestamp plausibility -------------------------------------------

// The inputs a receiving peer resolves before admitting a diff's timestamp as the
// basis for temporal-constraint evaluation. |parent_timestamps| are the
// timestamps of the diff's resolved causal parents (deps); |same_author_prior|
// are the timestamps of diffs by the SAME author reachable transitively through
// deps. All are RFC 3339 strings.
struct PlausibilityInput {
  std::string t;
  std::string now;
  std::vector<std::string> parent_timestamps;
  std::vector<std::string> same_author_prior;
};

struct PlausibilityResult {
  bool ok = true;
  std::string reason;  // "" when ok; a machine token otherwise
};

// Applies the three §5.3 checks in order: future bound (t − now ≤ 300 s), causal
// monotonicity (t ≥ every parent timestamp), and per-author monotonicity (t ≥
// every same-author prior timestamp). Any failure is fail-closed (REJECT). An
// unparseable |t| or |now| rejects; unparseable comparands are skipped (they are
// resolved history, not attacker-controlled at this layer).
PlausibilityResult CheckTimestampPlausibility(const PlausibilityInput& in);

// ---- §9.3 injected regex matcher -------------------------------------------

enum class RegexOutcome { kMatch, kNoMatch, kTimeout };

// A per-build-world regex primitive: applies |pattern| to |text| under the §9.3
// timeout. The standalone harness backs this with std::regex on a std::async
// bounded to 10 ms; the browser backs it with RE2 (linear-time). kTimeout (and,
// at the caller's discretion, a compile error) is treated as REJECT.
using RegexMatcher =
    std::function<RegexOutcome(const std::string& pattern, const std::string& text)>;

// ---- URL / domain extraction -----------------------------------------------

// Every http:// or https:// URL run in |text| (whitespace/structural-delimited).
std::vector<std::string> ExtractHttpUrls(const std::string& text);

// The host (authority minus any userinfo and port) of an http(s) URL; "" if the
// input is not a well-formed http(s) URL.
std::string UrlHost(const std::string& url);

// The media type of an RFC 2397 data: URL (`data:[<mediatype>][;...]` — defaults
// to "text/plain" when the mediatype is omitted), or "" if |text| is not a data:
// URL.
std::string DataUrlMediaType(const std::string& text);

// ---- §6.2 content policy ---------------------------------------------------

struct ContentPolicy {
  std::optional<int64_t> max_length;             // content_max_length
  std::vector<std::string> blocked_patterns;     // content_blocked_patterns
  std::optional<bool> allow_urls;                // content_allow_urls
  std::vector<std::string> allowed_domains;      // content_allowed_domains (glob)
  std::vector<std::string> allow_media_types;    // content_allow_media_types (glob)
};

struct ContentResult {
  bool allowed = true;
  std::string reason;  // machine token when rejected
};

// Evaluates §6.2 over the already-resolved object text, in the normative order:
// length → blocked patterns → URL policy → domain whitelist → media type. The
// regex step uses |matcher| and treats kTimeout as REJECT (§9.3). Character
// length is counted in UTF-8 code points. Empty |policy| accepts everything.
ContentResult EvaluateContentText(const ContentPolicy& policy,
                                  const std::string& text,
                                  const RegexMatcher& matcher);

// UTF-8 code-point count of |s| (bytes with the 0b10xxxxxx continuation form are
// not counted), for the §6.2 length check.
size_t Utf8Length(const std::string& s);

// ---- living-web Verifiable-Credential profile (§4 amendment) ---------------

// The subset of a VC the credential constraint / caveat verifies. The living-web
// profile (SPEC_COMPLIANCE amendment 08/§4.2) pins a VC to a JSON object stored
// JCS-canonical at its `sha256:` content address, whose `proof.proofValue` is an
// Ed25519 signature (multibase) over BuildVcProofPreimage(). This avoids a full
// JSON-LD / LD-Proofs stack while binding every field the constraint checks.
struct LivingWebVc {
  std::vector<std::string> types;  // "type" (string or array), order preserved
  std::string issuer;              // "issuer" (string, or object → its "id")
  std::string issuance_date;       // "issuanceDate" or "validFrom" (RFC 3339)
  std::string subject_id;          // "credentialSubject"."id" (holder DID)
  bool has_status = false;         // whether "credentialStatus" is present
  std::string status_id;           // "credentialStatus"."id" (revocation subject)
  std::string proof_purpose;       // "proof"."proofPurpose"
  std::string proof_created;       // "proof"."created"
  std::string proof_method;        // "proof"."verificationMethod"
  std::string proof_value;         // "proof"."proofValue" (multibase Ed25519 sig)
  bool valid = false;
};

// Parses a living-web-profile VC JSON document into |*out|. Returns true iff the
// document is a JSON object carrying a non-empty `type`, `issuer`,
// `credentialSubject.id`, and a `proof` with `proofValue` — the fields the
// signature and constraint checks require. `credentialStatus` is optional. On
// failure returns false and leaves out->valid == false.
bool ParseLivingWebVc(const std::string& json, LivingWebVc* out);

// The exact byte string `proof.proofValue` signs: a versioned tag then the signed
// field projection, one per line (LF-joined, no trailer) — the same construction
// as BuildDelegationProofPreimage in zcap.cc. The caller applies SHA-256 and
// verifies the Ed25519 signature against the key named by `proof.method`.
std::string BuildVcProofPreimage(const LivingWebVc& vc);

}  // namespace constraint_vocab
}  // namespace living_web

#endif  // CONTENT_BROWSER_GOVERNANCE_CONSTRAINT_VOCABULARY_H_
