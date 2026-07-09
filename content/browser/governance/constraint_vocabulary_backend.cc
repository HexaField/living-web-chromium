// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/governance/constraint_vocabulary_backend.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/did/jcs.h"
#include "content/browser/graph/oxigraph_store.h"
#include "content/browser/graph/sparql_results.h"
#include "crypto/sha2.h"
#include "third_party/ed25519/ed25519.h"
#include "third_party/re2/src/re2/re2.h"

namespace content {

namespace {

using living_web::DecodeSparqlBoolean;
using living_web::DecodeSparqlSelect;
using living_web::JsonValue;
using living_web::ObjectTerm;
using living_web::OxigraphStore;
using living_web::ParseJson;
using living_web::SparqlResult;
using living_web::SparqlSelect;
using living_web::SparqlSolution;
using living_web::SparqlTerm;
using living_web::Triple;

namespace cvb_detail {

// ---- small shared helpers --------------------------------------------------

// Lowercase-hex of |bytes|.
std::string HexLower(const std::string& bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char c : bytes) {
    out.push_back(kHex[c >> 4]);
    out.push_back(kHex[c & 0x0F]);
  }
  return out;
}

// "sha256:" + lowercase-hex SHA-256 of |bytes|, the content-address form Spec 07
// and this spec's §4.1 credential-body convention share.
std::string Sha256HexAddr(const std::string& bytes) {
  return "sha256:" + HexLower(crypto::SHA256HashString(bytes));
}

// The object's compared text: a literal's lexical form, else the IRI / blank-node
// label. URL, domain, and pattern checks all run over this string.
std::string ObjectText(const Triple& t) {
  return t.object.is_literal() ? t.object.literal->lexical
                               : t.object.iri_or_bnode;
}

// Replaces every occurrence of |needle| in |s| with |repl| (single pass).
std::string ReplaceAll(const std::string& s, const std::string& needle,
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

std::optional<std::string> ValueString(const std::string& value_json,
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

std::optional<int64_t> ValueInt(const std::string& value_json,
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

std::vector<std::string> ValueStringArray(const std::string& value_json,
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
std::vector<int64_t> AuthorWriteEpochs(GraphBackend* W, const std::string& author,
                                       const std::vector<std::string>& preds) {
  std::vector<int64_t> out;
  if (!W || author.empty())
    return out;
  std::string q = "SELECT ?ts WHERE {\n";
  q += "?r <" + std::string(living_web::kRdfReifies) + "> <<( ?s ?p ?o )>> .\n";
  q += "?r <" + std::string(living_web::kProvAuthor) + "> <" + author + "> .\n";
  q += "?r <" + std::string(living_web::kProvTimestamp) + "> ?ts .\n";
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
std::optional<std::string> FirstIntroducingAuthor(GraphBackend* W,
                                                  const std::string& subject) {
  if (!W || subject.empty() || subject.rfind("_:", 0) == 0)
    return std::nullopt;
  std::string q = "SELECT ?author ?ts WHERE {\n";
  q += "?r <" + std::string(living_web::kRdfReifies) + "> <<( <" + subject +
       "> ?p ?o )>> .\n";
  q += "?r <" + std::string(living_web::kProvAuthor) + "> ?author .\n";
  q += "?r <" + std::string(living_web::kProvTimestamp) + "> ?ts .\n";
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
bool VerifyHeldCredential(GraphBackend* W, const std::string& addr,
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
  std::optional<std::string> canonical = living_web::jcs::Canonicalize(*body);
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
  std::optional<std::vector<uint8_t>> pubkey =
      living_web::ParseAnyDidEd25519(vc.issuer);
  if (!pubkey || pubkey->size() != 32)
    return false;
  std::string preimage = cv::BuildVcProofPreimage(vc);
  std::string hash = crypto::SHA256HashString(preimage);
  std::optional<std::vector<uint8_t>> sig =
      living_web::did_key::MultibaseDecode(vc.proof_value);
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

// §4.2: does |author| hold at least one credential (via
// governance://has_credential) that satisfies type / issuer / freshness?
bool AuthorHasCredential(GraphBackend* W, const std::string& author,
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

}  // namespace cvb_detail

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
    if (cvb_detail::AuthorHasCredential(ctx.graph, ctx.author_did, *required,
                                        issuer, min_age, ctx.now))
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
        cvb_detail::AuthorWriteEpochs(ctx.graph, ctx.author_did, preds);

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
      int64_t low =
          now_epoch - window.value_or(cv::kDefaultTemporalWindowSeconds);
      int64_t count = 0;
      for (int64_t e : epochs)
        if (e >= low && e <= now_epoch)
          ++count;
      if (count >= *max_count)
        return {false, "temporal_window"};
    }
    return {true, ""};
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
    std::string text = cvb_detail::ObjectText(*triple);

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
  explicit PredicateLikeCaveatHandler(std::string type)
      : type_(std::move(type)) {}
  std::string type() const override { return type_; }
  bool appliesToNonTripleOps() const override { return false; }

  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& triple,
                         const std::string& /*action*/,
                         const ValidationContext& /*ctx*/) override {
    if (!triple)
      return {true, ""};
    std::vector<std::string> allowed =
        cvb_detail::ValueStringArray(caveat.value_raw, "allowed");
    std::vector<std::string> denied =
        cvb_detail::ValueStringArray(caveat.value_raw, "denied");
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
        cvb_detail::ValueString(caveat.value_raw, "pattern");
    if (!pattern)
      return {false, type_ + "_malformed"};
    const std::string& value = target_ == Target::kSubject
                                   ? triple->subject
                                   : cvb_detail::ObjectText(*triple);
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
    std::optional<int64_t> max =
        cvb_detail::ValueInt(caveat.value_raw, "maxPerWindow");
    std::optional<int64_t> window =
        cvb_detail::ValueInt(caveat.value_raw, "windowSeconds");
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
    std::optional<int64_t> max = cvb_detail::ValueInt(caveat.value_raw, "max");
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
        cvb_detail::FirstIntroducingAuthor(ctx.graph, triple->subject);
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
        cvb_detail::ValueString(caveat.value_raw, "shapeIri");
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
    std::optional<std::string> sparql =
        cvb_detail::ValueString(caveat.value_raw, "sparql");
    if (!sparql)
      return {false, "content_malformed"};
    // Build the in-memory model: the data triple plus its reifier (a placeholder
    // method IRI keeps the N-Quads free of relative-IRI parse hazards).
    std::string nquads = living_web::BuildTripleWithReifierNquads(
        *triple, "_:r", ctx.author_did, ctx.now, "urn:living-web:ephemeral", "");
    OxigraphStore store;
    if (!store.ok() || !store.LoadNquads(nquads))
      return {false, "content_store"};  // §9.2 fail-closed
    // Substitute $this with the subject IRI.
    std::string q =
        cvb_detail::ReplaceAll(*sparql, "$this", "<" + triple->subject + ">");
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
      if (!cvb_detail::AuthorHasCredential(ctx.graph, ctx.author_did,
                                           type_v->string_value, issuer,
                                           std::nullopt, ctx.now))
        return {false, "credential"};
    }
    return {true, ""};
  }
};

}  // namespace

// ---- §9.3 RE2 matcher ------------------------------------------------------

cv::RegexMatcher MakeRe2Matcher(int /*timeout_ms*/) {
  return [](const std::string& pattern,
            const std::string& text) -> cv::RegexOutcome {
    RE2 re(pattern);
    // A malformed pattern cannot match and blocks nothing (§9.3), mirroring the
    // standalone std::regex path's kNoMatch-on-compile-error.
    if (!re.ok())
      return cv::RegexOutcome::kNoMatch;
    // RE2 is linear-time, so there is no runaway match to bound — kTimeout is
    // never produced. PartialMatch is an unanchored search (like regex_search).
    return RE2::PartialMatch(text, re) ? cv::RegexOutcome::kMatch
                                       : cv::RegexOutcome::kNoMatch;
  };
}

// ---- registration ----------------------------------------------------------

void RegisterConstraintVocabulary(GovernanceBackend* engine,
                                  const ConstraintVocabOptions& options) {
  ConstraintVocabOptions opts = options;
  if (!opts.ledger)
    opts.ledger = std::make_shared<UsageLedger>();
  if (!opts.regex_matcher)
    opts.regex_matcher = MakeRe2Matcher();

  engine->RegisterConstraintKind(
      std::make_unique<CredentialConstraintHandler>());
  engine->RegisterConstraintKind(std::make_unique<TemporalConstraintHandler>());
  engine->RegisterConstraintKind(
      std::make_unique<ContentConstraintHandler>(opts.regex_matcher));

  engine->RegisterCaveatType(
      std::make_unique<PredicateLikeCaveatHandler>(cv::kCaveatPredicate));
  engine->RegisterCaveatType(
      std::make_unique<PredicateLikeCaveatHandler>(cv::kCaveatProperty));
  engine->RegisterCaveatType(std::make_unique<GlobCaveatHandler>(
      cv::kCaveatSubject, GlobCaveatHandler::Target::kSubject));
  engine->RegisterCaveatType(std::make_unique<GlobCaveatHandler>(
      cv::kCaveatObject, GlobCaveatHandler::Target::kObject));
  engine->RegisterCaveatType(
      std::make_unique<RateLimitCaveatHandler>(opts.ledger));
  engine->RegisterCaveatType(
      std::make_unique<CardinalityCaveatHandler>(opts.ledger));
  engine->RegisterCaveatType(std::make_unique<AuthorOnlyCaveatHandler>());
  engine->RegisterCaveatType(
      std::make_unique<ShapeCaveatHandler>(opts.shape_conforms));
  engine->RegisterCaveatType(std::make_unique<ContentCaveatHandler>());
  engine->RegisterCaveatType(std::make_unique<CredentialCaveatHandler>());
}

// ---- credential storage / integration helpers (§4.1) -----------------------

std::optional<std::string> CredentialAddress(const std::string& vc_json) {
  std::optional<std::string> canonical = living_web::jcs::Canonicalize(vc_json);
  if (!canonical)
    return std::nullopt;
  return cvb_detail::Sha256HexAddr(*canonical);
}

bool StoreCredential(GraphBackend* W, const std::string& author_did,
                     const std::string& vc_json, std::string* out_addr) {
  std::optional<std::string> canonical = living_web::jcs::Canonicalize(vc_json);
  if (!canonical)
    return false;
  std::string addr = cvb_detail::Sha256HexAddr(*canonical);
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

bool RevokeCredentialStatus(GraphBackend* W, const std::string& status_id) {
  return W->AddTriple(
      group_detail::T_lit(status_id, cv::kGovRevoked, cv::kRevokedTrue));
}

std::string MakeSignedLivingWebVc(DIDKeyProvider* identity,
                                  const std::string& issuer_cred_id,
                                  const std::string& issuer_did,
                                  const std::vector<std::string>& types,
                                  const std::string& subject_did,
                                  const std::string& issuance_date,
                                  const std::optional<std::string>& status_id) {
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
    proof_value = living_web::did_key::MultibaseEncode(*sig);

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

}  // namespace content
