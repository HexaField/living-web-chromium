// Governance Constraint Vocabulary provider - standalone implementation.
//
// Implements the standard constraint kinds and caveat types of the Governance
// Constraint Vocabulary (Spec 08) as plug-in handlers registered against the
// Spec 04 GovernanceEngine (standalone/capability_provider.h). Spec 04 owns the
// capability-chain mechanism, enforcement modes, and the `expiry` core caveat;
// this vocabulary supplies *what other constraints and caveats exist* — the
// `credential` / `temporal` / `content` constraint kinds (§4–§6) and the
// `predicate` / `property` / `subject` / `object` / `rateLimit` / `cardinality` /
// `authorOnly` / `shape` / `content` / `credential` caveat types (§7).
//
// Every pure decision these handlers reach — glob matching, the deny-wins
// allow/deny order, RFC-3339 arithmetic, the §6.2 content-policy order, the
// living-web VC pre-image — lives in the Chromium-independent core
// content/browser/governance/constraint_vocabulary.{h,cc}, so this harness and
// the browser governance backend reach identical verdicts. This header is the
// standalone *binding* layer: it resolves graph state through the Spec 02 Graph,
// hashes with standalone/crypto_sha2.h, verifies Ed25519 with third_party/ed25519,
// evaluates blocked-pattern regexes with std::regex on a bounded std::thread
// (§9.3), and runs the `content` caveat's SPARQL ASK against an ephemeral
// in-memory Oxigraph store. The browser backend swaps in //crypto, RE2, and its
// GraphBackend but registers structurally identical handlers.
//
// Two seams are injected rather than hard-wired so the layering stays acyclic:
//   * the `shape` caveat (§7.8) takes a `shape_conforms` callback supplied by the
//     Spec 07 shape service — the vocabulary never re-implements SHACL, and an
//     unresolvable shape fails closed (§9.6);
//   * the regex matcher (§9.3) is the injected core RegexMatcher, defaulting to
//     the std::regex-on-a-detached-thread matcher below.
#ifndef LIVING_WEB_CONSTRAINT_VOCABULARY_PROVIDER_H_
#define LIVING_WEB_CONSTRAINT_VOCABULARY_PROVIDER_H_

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "content/browser/did/did_graph.h"
#include "content/browser/did/jcs.h"
#include "content/browser/governance/constraint_vocabulary.h"
#include "content/browser/graph/oxigraph_store.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph/sparql_results.h"
#include "standalone/capability_provider.h"
#include "standalone/crypto_sha2.h"
#include "standalone/did_key_provider.h"
#include "standalone/graph_provider.h"
#include "standalone/group_provider.h"
#include "third_party/ed25519/ed25519.h"

namespace living_web {

namespace cv = constraint_vocab;

// ---- §7.5 / §7.6 usage ledger ----------------------------------------------

// The per-delegation counters that back the `rateLimit` (sliding window) and
// `cardinality` (lifetime) caveats. Owned by the vocabulary — NOT the engine —
// and injected into the two counting handlers as a shared_ptr, so a single
// process-wide ledger survives across every write the engine authorises. Keyed
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
using ShapeConformsFn = std::function<bool(
    Graph* graph, const std::string& shape_iri, const Triple& triple)>;

namespace cvp_detail {

// ---- small shared helpers --------------------------------------------------

// "sha256:" + lowercase-hex SHA-256 of |bytes|, the content-address form Spec 07
// and this spec's §4.1 credential-body convention share.
inline std::string Sha256HexAddr(const std::string& bytes) {
  std::string digest = crypto::SHA256HashString(bytes);
  return "sha256:" + DIDKeyProvider::HexEncode(
                         std::vector<uint8_t>(digest.begin(), digest.end()));
}

// The object's compared text: a literal's lexical form, else the IRI / blank-node
// label. URL, domain, and pattern checks all run over this string.
inline std::string ObjectText(const Triple& t) {
  return t.object.is_literal() ? t.object.literal->lexical
                               : t.object.iri_or_bnode;
}

// Replaces every occurrence of |needle| in |s| with |repl| (single pass).
inline std::string ReplaceAll(const std::string& s, const std::string& needle,
                              const std::string& repl) {
  if (needle.empty())
    return s;
  std::string out;
  size_t pos = 0;
  for (;;) {
    size_t hit = s.find(needle, pos);
    if (hit == std::string::npos) {
      out.append(s, pos, std::string::npos);
      break;
    }
    out.append(s, pos, hit - pos);
    out += repl;
    pos = hit + needle.size();
  }
  return out;
}

// ---- caveat-value JSON accessors (the "value" object per §7) ----------------

inline std::optional<std::string> ValueString(const std::string& value_json,
                                               const std::string& key) {
  JsonValue v;
  std::string err;
  if (!ParseJson(value_json, &v, &err) || !v.is_object())
    return std::nullopt;
  const JsonValue* f = v.Find(key);
  if (!f || !f->is_string())
    return std::nullopt;
  return f->string_value;
}

inline std::optional<int64_t> ValueInt(const std::string& value_json,
                                       const std::string& key) {
  JsonValue v;
  std::string err;
  if (!ParseJson(value_json, &v, &err) || !v.is_object())
    return std::nullopt;
  const JsonValue* f = v.Find(key);
  if (!f)
    return std::nullopt;
  if (f->type == JsonValue::Type::kNumber)
    return static_cast<int64_t>(f->number_value);
  if (f->is_string()) {
    int64_t n = 0;
    if (cv::ParseInt64(f->string_value, &n))
      return n;
  }
  return std::nullopt;
}

inline std::vector<std::string> ValueStringArray(const std::string& value_json,
                                                 const std::string& key) {
  std::vector<std::string> out;
  JsonValue v;
  std::string err;
  if (!ParseJson(value_json, &v, &err) || !v.is_object())
    return out;
  const JsonValue* f = v.Find(key);
  if (!f || !f->is_array())
    return out;
  for (const JsonValue& e : f->array_value)
    if (e.is_string())
      out.push_back(e.string_value);
  return out;
}

// ---- reifier-timestamp / author queries over Spec 02 provenance ------------

// The RFC-3339 timestamps of every reifier authored by |author| whose reified
// triple has a predicate in |preds| (or any predicate when |preds| is empty),
// converted to epoch seconds. This counts an author's write *events* (one per
// reifier), which is the unit §5.2 rate/interval checks operate on.
inline std::vector<int64_t> AuthorWriteEpochs(
    Graph* W, const std::string& author,
    const std::vector<std::string>& preds) {
  std::vector<int64_t> out;
  if (!W || author.empty())
    return out;
  std::string q = "SELECT ?ts WHERE {\n";
  q += "?r <" + std::string(kRdfReifies) + "> <<( ?s ?p ?o )>> .\n";
  q += "?r <" + std::string(kProvAuthor) + "> <" + author + "> .\n";
  q += "?r <" + std::string(kProvTimestamp) + "> ?ts .\n";
  if (!preds.empty()) {
    q += "VALUES ?p {";
    for (const std::string& p : preds)
      q += " <" + p + ">";
    q += " }\n";
  }
  q += "}";
  SparqlResult r = W->QuerySparql(q, {});
  if (!r.ok)
    return out;
  SparqlSelect sel;
  std::string err;
  if (!DecodeSparqlSelect(r.payload, &sel, &err))
    return out;
  for (const SparqlSolution& sol : sel.solutions) {
    const SparqlTerm* ts = sol.Get("ts");
    if (!ts)
      continue;
    int64_t e = 0;
    if (cv::ParseRfc3339ToEpoch(ts->value, &e))
      out.push_back(e);
  }
  return out;
}

// The author recorded on |subject|'s earliest introducing triple (the minimum
// reifier timestamp among all triples with that subject), or nullopt when the
// subject has no author of record (§7.7) — including blank-node subjects, which
// cannot be targeted addressably.
inline std::optional<std::string> FirstIntroducingAuthor(
    Graph* W, const std::string& subject) {
  if (!W || subject.empty() || subject.rfind("_:", 0) == 0)
    return std::nullopt;
  std::string q = "SELECT ?author ?ts WHERE {\n";
  q += "?r <" + std::string(kRdfReifies) + "> <<( <" + subject +
       "> ?p ?o )>> .\n";
  q += "?r <" + std::string(kProvAuthor) + "> ?author .\n";
  q += "?r <" + std::string(kProvTimestamp) + "> ?ts .\n";
  q += "} ORDER BY ASC(?ts) LIMIT 1";
  SparqlResult r = W->QuerySparql(q, {});
  if (!r.ok)
    return std::nullopt;
  SparqlSelect sel;
  std::string err;
  if (!DecodeSparqlSelect(r.payload, &sel, &err) || sel.solutions.empty())
    return std::nullopt;
  const SparqlTerm* a = sel.solutions.front().Get("author");
  if (!a)
    return std::nullopt;
  return a->value;
}

// ---- §4.2 credential resolution + verification -----------------------------

// True iff the VC stored at content address |addr| in |W| verifies against the
// required type / issuer glob / freshness, its Ed25519 proof, and local-state
// revocation. A credential that fails any check simply does not count as a match
// (the constraint REJECTs later if *no* held credential matches).
inline bool VerifyHeldCredential(Graph* W, const std::string& addr,
                                 const std::string& required_type,
                                 const std::optional<std::string>& issuer_glob,
                                 const std::optional<int64_t>& min_age_hours,
                                 int64_t now_epoch) {
  // Resolve the inline JCS-canonical VC body at its own address (§4.1).
  std::optional<std::string> body =
      group_detail::FirstLiteralOf(W, addr, cv::kGovCredentialBody);
  if (!body)
    return false;
  // Content-address integrity: addr MUST equal sha256:hex(SHA-256(JCS(body))).
  std::optional<std::string> canonical = jcs::Canonicalize(*body);
  if (!canonical || Sha256HexAddr(*canonical) != addr)
    return false;
  cv::LivingWebVc vc;
  if (!cv::ParseLivingWebVc(*body, &vc) || !vc.valid)
    return false;
  // §4.2.2.3 type match.
  if (std::find(vc.types.begin(), vc.types.end(), required_type) ==
      vc.types.end())
    return false;
  // §4.2.2.4 issuer glob.
  if (issuer_glob && !cv::GlobMatch(*issuer_glob, vc.issuer))
    return false;
  // §4.2.2.5 freshness: issuanceDate at least min_age_hours in the past.
  if (min_age_hours) {
    int64_t issued = 0;
    if (!cv::ParseRfc3339ToEpoch(vc.issuance_date, &issued))
      return false;
    if (issued > now_epoch - *min_age_hours * 3600)
      return false;
  }
  // §4.2.2.6 signature: the living-web profile pins the issuer to a did:key; the
  // proof is an Ed25519 signature over SHA-256(BuildVcProofPreimage) by that key.
  std::optional<std::vector<uint8_t>> pubkey = ParseAnyDidEd25519(vc.issuer);
  if (!pubkey || pubkey->size() != 32)
    return false;
  std::string preimage = cv::BuildVcProofPreimage(vc);
  std::string hash = crypto::SHA256HashString(preimage);
  std::optional<std::vector<uint8_t>> sig =
      did_key::MultibaseDecode(vc.proof_value);
  if (!sig || sig->size() != 64)
    return false;
  if (ed25519_verify(sig->data(),
                     reinterpret_cast<const uint8_t*>(hash.data()), hash.size(),
                     pubkey->data()) != 1)
    return false;
  // §4.2.2.7 revocation (local-state): a status subject bearing
  // governance://revoked "true" revokes; absence means live.
  if (vc.has_status && !vc.status_id.empty()) {
    std::optional<std::string> revoked =
        group_detail::FirstLiteralOf(W, vc.status_id, cv::kGovRevoked);
    if (revoked && *revoked == cv::kRevokedTrue)
      return false;
  }
  return true;
}

// §4.2: does |author| hold at least one credential (via governance://has_credential)
// that satisfies the required type / issuer / freshness?
inline bool AuthorHasCredential(Graph* W, const std::string& author,
                                const std::string& required_type,
                                const std::optional<std::string>& issuer_glob,
                                const std::optional<int64_t>& min_age_hours,
                                const std::string& now_rfc3339) {
  int64_t now_epoch = 0;
  if (!cv::ParseRfc3339ToEpoch(now_rfc3339, &now_epoch))
    return false;  // no admissible clock → fail-closed
  for (const ObjectTerm& o :
       group_detail::QueryObjects(W, author, cv::kGovHasCredential)) {
    if (o.is_literal())
      continue;
    if (VerifyHeldCredential(W, o.iri_or_bnode, required_type, issuer_glob,
                             min_age_hours, now_epoch))
      return true;
  }
  return false;
}

// ---- constraint-kind handlers (§4–§6) --------------------------------------

// §4 credential constraint.
class CredentialConstraintHandler : public ConstraintKindHandler {
 public:
  std::string kind() const override { return cv::kKindCredential; }

  HandlerResult Validate(const std::optional<Triple>& /*triple*/,
                         const GraphConstraint& c,
                         const ValidationContext& ctx) override {
    std::optional<std::string> required =
        c.Property(cv::kGovRequiresCredentialType);
    if (!required || required->empty())
      return {true, ""};  // no required type declared → nothing to enforce
    std::optional<std::string> issuer =
        c.Property(cv::kGovCredentialIssuerPattern);
    std::optional<int64_t> min_age;
    if (std::optional<std::string> m =
            c.Property(cv::kGovCredentialMinAgeHours)) {
      int64_t v = 0;
      if (cv::ParseInt64(*m, &v))
        min_age = v;
    }
    if (AuthorHasCredential(ctx.graph, ctx.author_did, *required, issuer,
                            min_age, ctx.now))
      return {true, ""};
    return {false, "credential_required"};
  }
};

// §5 temporal constraint.
class TemporalConstraintHandler : public ConstraintKindHandler {
 public:
  std::string kind() const override { return cv::kKindTemporal; }

  HandlerResult Validate(const std::optional<Triple>& triple,
                         const GraphConstraint& c,
                         const ValidationContext& ctx) override {
    // A temporal constraint gates triple writes; non-triple operations carry no
    // predicate and are out of its scope.
    if (!triple)
      return {true, ""};

    std::optional<int64_t> min_interval, max_count, window;
    if (std::optional<std::string> v =
            c.Property(cv::kGovTemporalMinIntervalSeconds)) {
      int64_t n = 0;
      if (cv::ParseInt64(*v, &n))
        min_interval = n;
    }
    if (std::optional<std::string> v =
            c.Property(cv::kGovTemporalMaxCountPerWindow)) {
      int64_t n = 0;
      if (cv::ParseInt64(*v, &n))
        max_count = n;
    }
    if (std::optional<std::string> v =
            c.Property(cv::kGovTemporalWindowSeconds)) {
      int64_t n = 0;
      if (cv::ParseInt64(*v, &n))
        window = n;
    }
    if (!min_interval && !max_count)
      return {true, ""};  // §5.1 requires at least one; nothing to enforce

    std::vector<std::string> preds;
    if (std::optional<std::string> p =
            c.Property(cv::kGovTemporalAppliesToPredicates))
      preds = cv::SplitOnComma(*p);
    // §5.2.3.1 predicate match.
    if (!preds.empty() && std::find(preds.begin(), preds.end(),
                                    triple->predicate) == preds.end())
      return {true, ""};

    int64_t now_epoch = 0;
    if (!cv::ParseRfc3339ToEpoch(ctx.now, &now_epoch))
      return {false, "temporal_no_clock"};

    // §5.2.3.2 query the author's prior matching write events.
    std::vector<int64_t> epochs =
        cvp_detail_scope(ctx.graph, ctx.author_did, preds);

    // §5.2.3.3 interval check.
    if (min_interval) {
      int64_t most_recent = INT64_MIN;
      for (int64_t e : epochs)
        most_recent = std::max(most_recent, e);
      if (most_recent != INT64_MIN && now_epoch - most_recent < *min_interval)
        return {false, "temporal_interval"};
    }
    // §5.2.3.4 window count check.
    if (max_count) {
      int64_t low = now_epoch - window.value_or(cv::kDefaultTemporalWindowSeconds);
      int64_t count = 0;
      for (int64_t e : epochs)
        if (e >= low && e <= now_epoch)
          ++count;
      if (count >= *max_count)
        return {false, "temporal_window"};
    }
    return {true, ""};
  }

 private:
  // Indirection kept as a member so a subclass/test could override the source of
  // truth; defaults to the provenance query above.
  static std::vector<int64_t> cvp_detail_scope(
      Graph* W, const std::string& author,
      const std::vector<std::string>& preds) {
    return AuthorWriteEpochs(W, author, preds);
  }
};

// §6 content constraint.
class ContentConstraintHandler : public ConstraintKindHandler {
 public:
  explicit ContentConstraintHandler(cv::RegexMatcher matcher)
      : matcher_(std::move(matcher)) {}

  std::string kind() const override { return cv::kKindContent; }

  HandlerResult Validate(const std::optional<Triple>& triple,
                         const GraphConstraint& c,
                         const ValidationContext& /*ctx*/) override {
    if (!triple)
      return {true, ""};  // no object to inspect
    // §6.2.2.1 predicate match.
    if (std::optional<std::string> p =
            c.Property(cv::kGovContentAppliesToPredicates)) {
      std::vector<std::string> preds = cv::SplitOnComma(*p);
      if (!preds.empty() && std::find(preds.begin(), preds.end(),
                                      triple->predicate) == preds.end())
        return {true, ""};
    }
    // §6.2.2.2 resolve object text (literal lexical form / IRI string).
    std::string text = ObjectText(*triple);

    cv::ContentPolicy policy;
    if (std::optional<std::string> v = c.Property(cv::kGovContentMaxLength)) {
      int64_t n = 0;
      if (cv::ParseInt64(*v, &n))
        policy.max_length = n;
    }
    if (std::optional<std::string> v =
            c.Property(cv::kGovContentBlockedPatterns))
      policy.blocked_patterns = cv::SplitOnPipe(*v);
    if (std::optional<std::string> v = c.Property(cv::kGovContentAllowUrls)) {
      bool b = false;
      if (cv::ParseBoolString(*v, &b))
        policy.allow_urls = b;
    }
    if (std::optional<std::string> v =
            c.Property(cv::kGovContentAllowedDomains))
      policy.allowed_domains = cv::SplitOnComma(*v);
    if (std::optional<std::string> v =
            c.Property(cv::kGovContentAllowMediaTypes))
      policy.allow_media_types = cv::SplitOnComma(*v);

    cv::ContentResult r = cv::EvaluateContentText(policy, text, matcher_);
    if (r.allowed)
      return {true, ""};
    return {false, "content:" + r.reason};
  }

 private:
  cv::RegexMatcher matcher_;
};

// ---- caveat handlers (§7) --------------------------------------------------

// §7.2 predicate / §7.3 property share exact deny-wins membership on the
// triple's predicate (a plain triple's property path IS its predicate).
class PredicateLikeCaveatHandler : public CaveatHandler {
 public:
  explicit PredicateLikeCaveatHandler(std::string type) : type_(std::move(type)) {}
  std::string type() const override { return type_; }
  bool appliesToNonTripleOps() const override { return false; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& triple,
                         const std::string& /*action*/,
                         const ValidationContext& /*ctx*/) override {
    if (!triple)
      return {true, ""};
    std::vector<std::string> allowed =
        ValueStringArray(caveat.value_raw, "allowed");
    std::vector<std::string> denied =
        ValueStringArray(caveat.value_raw, "denied");
    if (cv::EvalAllowDeny(allowed, denied, triple->predicate) ==
        cv::AllowDeny::kAccept)
      return {true, ""};
    return {false, type_};
  }

 private:
  std::string type_;
};

// §7.4 subject / object glob on the subject IRI / object lexical form.
class GlobCaveatHandler : public CaveatHandler {
 public:
  enum class Target { kSubject, kObject };
  GlobCaveatHandler(std::string type, Target target)
      : type_(std::move(type)), target_(target) {}
  std::string type() const override { return type_; }
  bool appliesToNonTripleOps() const override { return false; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& triple,
                         const std::string& /*action*/,
                         const ValidationContext& /*ctx*/) override {
    if (!triple)
      return {true, ""};
    std::optional<std::string> pattern =
        ValueString(caveat.value_raw, "pattern");
    if (!pattern)
      return {false, type_ + "_malformed"};
    const std::string& value = target_ == Target::kSubject
                                   ? triple->subject
                                   : ObjectText(*triple);
    return cv::GlobMatch(*pattern, value) ? HandlerResult{true, ""}
                                          : HandlerResult{false, type_};
  }

 private:
  std::string type_;
  Target target_;
};

// §7.5 rateLimit — sliding window keyed (zcap.id, author).
class RateLimitCaveatHandler : public CaveatHandler {
 public:
  explicit RateLimitCaveatHandler(std::shared_ptr<UsageLedger> ledger)
      : ledger_(std::move(ledger)) {}
  std::string type() const override { return cv::kCaveatRateLimit; }
  bool appliesToNonTripleOps() const override { return true; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& /*triple*/,
                         const std::string& /*action*/,
                         const ValidationContext& ctx) override {
    std::optional<int64_t> max = ValueInt(caveat.value_raw, "maxPerWindow");
    std::optional<int64_t> window = ValueInt(caveat.value_raw, "windowSeconds");
    if (!max || !window)
      return {false, "rateLimit_malformed"};
    int64_t now_epoch = 0;
    if (!cv::ParseRfc3339ToEpoch(ctx.now, &now_epoch))
      return {false, "rateLimit_no_clock"};
    if (ledger_->CheckAndRecordRate(ctx.zcap_id, ctx.author_did, *max, *window,
                                    now_epoch))
      return {true, ""};
    return {false, "rateLimit"};
  }

 private:
  std::shared_ptr<UsageLedger> ledger_;
};

// §7.6 cardinality — lifetime cap keyed (zcap.id, author).
class CardinalityCaveatHandler : public CaveatHandler {
 public:
  explicit CardinalityCaveatHandler(std::shared_ptr<UsageLedger> ledger)
      : ledger_(std::move(ledger)) {}
  std::string type() const override { return cv::kCaveatCardinality; }
  bool appliesToNonTripleOps() const override { return true; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& /*triple*/,
                         const std::string& /*action*/,
                         const ValidationContext& ctx) override {
    std::optional<int64_t> max = ValueInt(caveat.value_raw, "max");
    if (!max)
      return {false, "cardinality_malformed"};
    if (ledger_->CheckAndRecordCardinality(ctx.zcap_id, ctx.author_did, *max))
      return {true, ""};
    return {false, "cardinality"};
  }

 private:
  std::shared_ptr<UsageLedger> ledger_;
};

// §7.7 authorOnly — the writer must be the subject's author of record.
class AuthorOnlyCaveatHandler : public CaveatHandler {
 public:
  std::string type() const override { return cv::kCaveatAuthorOnly; }
  bool appliesToNonTripleOps() const override { return true; }

  HandlerResult Evaluate(const Caveat& /*caveat*/,
                         const std::optional<Triple>& triple,
                         const std::string& /*action*/,
                         const ValidationContext& ctx) override {
    if (!triple)
      return {true, ""};  // non-triple op: no subject to compare against
    std::optional<std::string> first =
        FirstIntroducingAuthor(ctx.graph, triple->subject);
    if (!first)
      return {true, ""};  // §7.7 no prior author of record → ACCEPT
    return ctx.author_did == *first ? HandlerResult{true, ""}
                                    : HandlerResult{false, "authorOnly"};
  }
};

// §7.8 shape — the triple's subject must conform to a registered SHACL shape.
class ShapeCaveatHandler : public CaveatHandler {
 public:
  explicit ShapeCaveatHandler(ShapeConformsFn conforms)
      : conforms_(std::move(conforms)) {}
  std::string type() const override { return cv::kCaveatShape; }
  bool appliesToNonTripleOps() const override { return false; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& triple,
                         const std::string& /*action*/,
                         const ValidationContext& ctx) override {
    if (!triple)
      return {true, ""};
    std::optional<std::string> shape_iri =
        ValueString(caveat.value_raw, "shapeIri");
    if (!shape_iri)
      return {false, "shape_malformed"};
    // §9.6 fail-closed: an unwired or negative conformance result REJECTs.
    if (!conforms_ || !conforms_(ctx.graph, *shape_iri, *triple))
      return {false, "shape"};
    return {true, ""};
  }

 private:
  ShapeConformsFn conforms_;
};

// §7.9 content — a SPARQL ASK over an ephemeral model of the triple + reifier.
class ContentCaveatHandler : public CaveatHandler {
 public:
  std::string type() const override { return cv::kCaveatContent; }
  bool appliesToNonTripleOps() const override { return false; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& triple,
                         const std::string& /*action*/,
                         const ValidationContext& ctx) override {
    if (!triple)
      return {true, ""};
    std::optional<std::string> sparql = ValueString(caveat.value_raw, "sparql");
    if (!sparql)
      return {false, "content_malformed"};
    // Build the in-memory model: the data triple plus its reifier (a placeholder
    // method IRI keeps the N-Quads free of relative-IRI parse hazards).
    std::string nquads = BuildTripleWithReifierNquads(
        *triple, "_:r", ctx.author_did, ctx.now, "urn:living-web:ephemeral", "");
    OxigraphStore store;
    if (!store.ok() || !store.LoadNquads(nquads))
      return {false, "content_store"};  // §9.2 fail-closed
    // Substitute $this with the subject IRI.
    std::string q = ReplaceAll(*sparql, "$this", "<" + triple->subject + ">");
    SparqlResult r = store.Query(q, {});
    if (!r.ok)
      return {false, "content_query"};  // §9.4 cost/parse error → REJECT
    bool ask = false;
    std::string err;
    if (!DecodeSparqlBoolean(r.payload, &ask, &err))
      return {false, "content_decode"};
    return ask ? HandlerResult{true, ""} : HandlerResult{false, "content"};
  }
};

// §7.10 credential — the author must hold a VC for every `requires` entry.
class CredentialCaveatHandler : public CaveatHandler {
 public:
  std::string type() const override { return cv::kCaveatCredential; }
  bool appliesToNonTripleOps() const override { return true; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& /*triple*/,
                         const std::string& /*action*/,
                         const ValidationContext& ctx) override {
    JsonValue v;
    std::string err;
    if (!ParseJson(caveat.value_raw, &v, &err) || !v.is_object())
      return {false, "credential_malformed"};
    const JsonValue* requires_arr = v.Find("requires");
    if (!requires_arr || !requires_arr->is_array())
      return {false, "credential_malformed"};
    for (const JsonValue& entry : requires_arr->array_value) {
      if (!entry.is_object())
        return {false, "credential_malformed"};
      const JsonValue* type_v = entry.Find("type");
      if (!type_v || !type_v->is_string())
        return {false, "credential_malformed"};
      std::optional<std::string> issuer;
      if (const JsonValue* iss = entry.Find("issuerPattern"))
        if (iss->is_string())
          issuer = iss->string_value;
      if (!AuthorHasCredential(ctx.graph, ctx.author_did, type_v->string_value,
                               issuer, std::nullopt, ctx.now))
        return {false, "credential"};
    }
    return {true, ""};
  }
};

}  // namespace cvp_detail

// ---- §9.3 std::regex matcher (bounded) -------------------------------------

// The standalone RegexMatcher: evaluates |pattern| against |text| with std::regex
// on a detached worker thread, returning kTimeout if the match does not complete
// within |timeout_ms|. Detaching (rather than joining) is what actually bounds
// the caller — a std::async future's destructor would block on the runaway match,
// re-exposing the very ReDoS the timeout exists to stop. The worker owns copies of
// the pattern and text and fulfils a shared promise, so it is safe to outlive the
// call. A malformed pattern cannot match and is reported as kNoMatch (it blocks
// nothing), distinct from the fail-closed kTimeout. The browser backend uses RE2
// (linear-time) and needs no thread.
inline cv::RegexMatcher MakeStdRegexMatcher(
    int timeout_ms = cv::kDefaultRegexTimeoutMillis) {
  return [timeout_ms](const std::string& pattern,
                      const std::string& text) -> cv::RegexOutcome {
    auto prom = std::make_shared<std::promise<cv::RegexOutcome>>();
    std::future<cv::RegexOutcome> fut = prom->get_future();
    std::thread([prom, pattern, text]() {
      cv::RegexOutcome outcome = cv::RegexOutcome::kNoMatch;
      try {
        std::regex re(pattern, std::regex::ECMAScript);
        outcome = std::regex_search(text, re) ? cv::RegexOutcome::kMatch
                                              : cv::RegexOutcome::kNoMatch;
      } catch (const std::regex_error&) {
        outcome = cv::RegexOutcome::kNoMatch;
      }
      prom->set_value(outcome);
    }).detach();
    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) ==
        std::future_status::timeout)
      return cv::RegexOutcome::kTimeout;
    return fut.get();
  };
}

// ---- registration ----------------------------------------------------------

// Configuration for RegisterConstraintVocabulary. Every field is optional; the
// defaults give a fully-functional vocabulary (a fresh ledger, the std::regex
// matcher, and a fail-closed shape caveat).
struct ConstraintVocabOptions {
  // The §7.5/§7.6 counter store. Defaults to a fresh internal ledger; supply one
  // to share counters across engines or to inspect them from a test.
  std::shared_ptr<UsageLedger> ledger;
  // The §9.3 blocked-pattern matcher. Defaults to MakeStdRegexMatcher().
  cv::RegexMatcher regex_matcher;
  // The §7.8 shape-conformance seam (from the Spec 07 shape service). When unset
  // the shape caveat fails closed (§9.6).
  ShapeConformsFn shape_conforms;
};

// Registers the full Spec 08 vocabulary — the three constraint kinds and ten
// caveat types (§2) — against |engine| via the framework plug-in mechanism
// (§9.3). Unknown kinds/types the engine still fails closed on its own.
inline void RegisterConstraintVocabulary(
    GovernanceEngine* engine, const ConstraintVocabOptions& options = {}) {
  ConstraintVocabOptions opts = options;
  if (!opts.ledger)
    opts.ledger = std::make_shared<UsageLedger>();
  if (!opts.regex_matcher)
    opts.regex_matcher = MakeStdRegexMatcher();

  engine->RegisterConstraintKind(
      std::make_unique<cvp_detail::CredentialConstraintHandler>());
  engine->RegisterConstraintKind(
      std::make_unique<cvp_detail::TemporalConstraintHandler>());
  engine->RegisterConstraintKind(
      std::make_unique<cvp_detail::ContentConstraintHandler>(
          opts.regex_matcher));

  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::PredicateLikeCaveatHandler>(
          cv::kCaveatPredicate));
  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::PredicateLikeCaveatHandler>(
          cv::kCaveatProperty));
  engine->RegisterCaveatType(std::make_unique<cvp_detail::GlobCaveatHandler>(
      cv::kCaveatSubject, cvp_detail::GlobCaveatHandler::Target::kSubject));
  engine->RegisterCaveatType(std::make_unique<cvp_detail::GlobCaveatHandler>(
      cv::kCaveatObject, cvp_detail::GlobCaveatHandler::Target::kObject));
  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::RateLimitCaveatHandler>(opts.ledger));
  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::CardinalityCaveatHandler>(opts.ledger));
  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::AuthorOnlyCaveatHandler>());
  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::ShapeCaveatHandler>(opts.shape_conforms));
  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::ContentCaveatHandler>());
  engine->RegisterCaveatType(
      std::make_unique<cvp_detail::CredentialCaveatHandler>());
}

// ---- test / integration helpers --------------------------------------------

// Content address of the JCS-canonical form of |vc_json| (the address at which
// StoreCredential files it, and against which the credential handlers verify).
inline std::optional<std::string> CredentialAddress(const std::string& vc_json) {
  std::optional<std::string> canonical = jcs::Canonicalize(vc_json);
  if (!canonical)
    return std::nullopt;
  return cvp_detail::Sha256HexAddr(*canonical);
}

// Files |vc_json| into |W| under the §4.1 storage convention: the JCS-canonical
// VC body inline at its content address, linked from |author_did| via
// governance://has_credential. Writes are authored by W's active credential.
// Returns the content address on success.
inline bool StoreCredential(Graph* W, const std::string& author_did,
                            const std::string& vc_json, std::string* out_addr) {
  std::optional<std::string> canonical = jcs::Canonicalize(vc_json);
  if (!canonical)
    return false;
  std::string addr = cvp_detail::Sha256HexAddr(*canonical);
  std::vector<Triple> triples = {
      group_detail::T_lit(addr, cv::kGovCredentialBody, *canonical),
      group_detail::T_iri(author_did, cv::kGovHasCredential, addr),
  };
  if (!W->AddTriples(triples))
    return false;
  if (out_addr)
    *out_addr = addr;
  return true;
}

// Marks the credential-status subject |status_id| revoked in |W| (writes
// status_id governance://revoked "true"). Authored by W's active credential.
inline bool RevokeCredentialStatus(Graph* W, const std::string& status_id) {
  return W->AddTriple(
      group_detail::T_lit(status_id, cv::kGovRevoked, cv::kRevokedTrue));
}

// Builds a living-web-profile VC (§4 amendment) as a JSON document whose Ed25519
// proof over SHA-256(BuildVcProofPreimage) is produced with |issuer_cred_id|.
// |issuer_did| MUST be the did:key of that credential (the profile pins issuers
// to did:key for self-contained verification). |types| is written verbatim, so
// include every type the constraint may require. The returned JSON re-parses to
// exactly the fields the pre-image was built from, so it verifies round-trip.
inline std::string MakeSignedLivingWebVc(
    DIDKeyProvider* identity, const std::string& issuer_cred_id,
    const std::string& issuer_did, const std::vector<std::string>& types,
    const std::string& subject_did, const std::string& issuance_date,
    const std::optional<std::string>& status_id = std::nullopt) {
  cv::LivingWebVc vc;
  vc.types = types;
  vc.issuer = issuer_did;
  vc.issuance_date = issuance_date;
  vc.subject_id = subject_did;
  if (status_id) {
    vc.has_status = true;
    vc.status_id = *status_id;
  }
  vc.proof_purpose = "assertionMethod";
  vc.proof_created = issuance_date;
  vc.proof_method = issuer_did;

  std::string preimage = cv::BuildVcProofPreimage(vc);
  std::string hash = crypto::SHA256HashString(preimage);
  std::string proof_value;
  if (std::optional<std::vector<uint8_t>> sig = identity->SignRaw(
          issuer_cred_id, std::vector<uint8_t>(hash.begin(), hash.end())))
    proof_value = did_key::MultibaseEncode(*sig);

  auto esc = [](const std::string& s) {
    std::string out;
    for (char c : s) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += c;
      }
    }
    return out;
  };
  std::string json = "{\"type\":[";
  for (size_t i = 0; i < types.size(); ++i) {
    if (i)
      json += ",";
    json += "\"" + esc(types[i]) + "\"";
  }
  json += "],\"issuer\":\"" + esc(issuer_did) + "\"";
  json += ",\"issuanceDate\":\"" + esc(issuance_date) + "\"";
  json += ",\"credentialSubject\":{\"id\":\"" + esc(subject_did) + "\"}";
  if (status_id)
    json += ",\"credentialStatus\":{\"id\":\"" + esc(*status_id) + "\"}";
  json += ",\"proof\":{\"proofPurpose\":\"assertionMethod\",\"created\":\"" +
          esc(issuance_date) + "\",\"verificationMethod\":\"" + esc(issuer_did) +
          "\",\"proofValue\":\"" + esc(proof_value) + "\"}}";
  return json;
}

}  // namespace living_web

#endif  // LIVING_WEB_CONSTRAINT_VOCABULARY_PROVIDER_H_
