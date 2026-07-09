// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/governance/constraint_vocabulary.h"

#include <algorithm>
#include <cstddef>

#include "content/browser/graph/sparql_results.h"

namespace living_web {
namespace constraint_vocab {

namespace {

constexpr size_t kNpos = std::string::npos;

bool IsAsciiWs(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

std::string Trim(const std::string& s) {
  size_t a = 0;
  size_t b = s.size();
  while (a < b && IsAsciiWs(s[a]))
    ++a;
  while (b > a && IsAsciiWs(s[b - 1]))
    --b;
  return s.substr(a, b - a);
}

std::string ToLowerAscii(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

// Howard Hinnant's days-from-civil: days since 1970-01-01 for a proleptic
// Gregorian (y, m, d). Timezone-independent and free of the 2038 limit.
int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// A URL run ends at any control character, space, or a character that cannot
// appear unescaped in a URI (RFC 3986 excludes these from the URI grammar).
bool IsUrlTerminator(char c) {
  const unsigned char u = static_cast<unsigned char>(c);
  if (u <= 0x20)
    return true;
  switch (c) {
    case '<':
    case '>':
    case '"':
    case '{':
    case '}':
    case '|':
    case '\\':
    case '^':
    case '`':
      return true;
    default:
      return false;
  }
}

}  // namespace

// ---- string helpers --------------------------------------------------------

std::vector<std::string> SplitOnComma(const std::string& raw) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= raw.size()) {
    const size_t comma = raw.find(',', start);
    const std::string tok =
        raw.substr(start, comma == kNpos ? kNpos : comma - start);
    const std::string t = Trim(tok);
    if (!t.empty())
      out.push_back(t);
    if (comma == kNpos)
      break;
    start = comma + 1;
  }
  return out;
}

std::vector<std::string> SplitOnPipe(const std::string& raw) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= raw.size()) {
    const size_t bar = raw.find('|', start);
    std::string tok = raw.substr(start, bar == kNpos ? kNpos : bar - start);
    if (!tok.empty())
      out.push_back(std::move(tok));
    if (bar == kNpos)
      break;
    start = bar + 1;
  }
  return out;
}

bool ParseBoolString(const std::string& raw, bool* out) {
  const std::string low = ToLowerAscii(Trim(raw));
  if (low == "true") {
    *out = true;
    return true;
  }
  if (low == "false") {
    *out = false;
    return true;
  }
  return false;
}

bool ParseInt64(const std::string& raw, int64_t* out) {
  const std::string s = Trim(raw);
  if (s.empty())
    return false;
  size_t i = 0;
  bool neg = false;
  if (s[i] == '+' || s[i] == '-') {
    neg = (s[i] == '-');
    ++i;
  }
  if (i >= s.size())
    return false;
  int64_t val = 0;
  for (; i < s.size(); ++i) {
    if (s[i] < '0' || s[i] > '9')
      return false;
    const int digit = s[i] - '0';
    // Reject magnitudes past INT64_MAX; a min-age / count of that scale is
    // nonsensical, so the lost INT64_MIN edge is immaterial.
    if (val > (INT64_MAX - digit) / 10)
      return false;
    val = val * 10 + digit;
  }
  *out = neg ? -val : val;
  return true;
}

// ---- §7.4 glob matching ----------------------------------------------------

bool GlobMatch(const std::string& pattern, const std::string& text) {
  size_t p = 0;
  size_t t = 0;
  size_t star = kNpos;
  size_t match = 0;
  while (t < text.size()) {
    if (p < pattern.size() && pattern[p] == '*') {
      star = p++;
      match = t;
    } else if (p < pattern.size() && pattern[p] == text[t]) {
      ++p;
      ++t;
    } else if (star != kNpos) {
      p = star + 1;
      t = ++match;
    } else {
      return false;
    }
  }
  while (p < pattern.size() && pattern[p] == '*')
    ++p;
  return p == pattern.size();
}

// ---- §7.2 / §7.3 allow/deny (deny-wins) ------------------------------------

AllowDeny EvalAllowDeny(const std::vector<std::string>& allowed,
                        const std::vector<std::string>& denied,
                        const std::string& value) {
  if (std::find(denied.begin(), denied.end(), value) != denied.end())
    return AllowDeny::kDenied;
  if (!allowed.empty() &&
      std::find(allowed.begin(), allowed.end(), value) == allowed.end()) {
    return AllowDeny::kNotAllowed;
  }
  return AllowDeny::kAccept;
}

// ---- RFC 3339 → epoch ------------------------------------------------------

bool ParseRfc3339ToEpoch(const std::string& rfc3339,
                         int64_t* out_epoch_seconds) {
  const std::string s = Trim(rfc3339);
  size_t i = 0;
  auto take = [&](int n, int64_t* v) -> bool {
    if (i + static_cast<size_t>(n) > s.size())
      return false;
    int64_t acc = 0;
    for (int k = 0; k < n; ++k) {
      const char c = s[i + k];
      if (c < '0' || c > '9')
        return false;
      acc = acc * 10 + (c - '0');
    }
    i += n;
    *v = acc;
    return true;
  };
  auto expect = [&](char c) -> bool {
    if (i >= s.size() || s[i] != c)
      return false;
    ++i;
    return true;
  };

  int64_t year, mon, day, hh, mm, ss;
  if (!take(4, &year) || !expect('-') || !take(2, &mon) || !expect('-') ||
      !take(2, &day)) {
    return false;
  }
  // The date/time separator is 'T' (RFC 3339) or the lower-case / space
  // variants RFC 3339 permits by mutual agreement.
  if (i >= s.size() || (s[i] != 'T' && s[i] != 't' && s[i] != ' '))
    return false;
  ++i;
  if (!take(2, &hh) || !expect(':') || !take(2, &mm) || !expect(':') ||
      !take(2, &ss)) {
    return false;
  }
  // Optional fractional seconds (discarded — the profile works in whole
  // seconds), but at least one digit MUST follow the dot.
  if (i < s.size() && s[i] == '.') {
    ++i;
    const size_t frac_start = i;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9')
      ++i;
    if (i == frac_start)
      return false;
  }
  // A numeric offset or 'Z' is REQUIRED by RFC 3339.
  int64_t offset_seconds = 0;
  if (i < s.size() && (s[i] == 'Z' || s[i] == 'z')) {
    ++i;
  } else if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
    const int sign = (s[i] == '-') ? -1 : 1;
    ++i;
    int64_t oh, om;
    if (!take(2, &oh) || !expect(':') || !take(2, &om))
      return false;
    if (oh > 23 || om > 59)
      return false;
    offset_seconds = sign * (oh * 3600 + om * 60);
  } else {
    return false;
  }
  if (i != s.size())
    return false;  // trailing junk

  if (mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 ||
      ss > 60) {  // ss == 60 permits a leap second
    return false;
  }

  const int64_t days =
      DaysFromCivil(year, static_cast<unsigned>(mon), static_cast<unsigned>(day));
  *out_epoch_seconds =
      days * 86400 + hh * 3600 + mm * 60 + ss - offset_seconds;
  return true;
}

// ---- §5.3 timestamp plausibility -------------------------------------------

PlausibilityResult CheckTimestampPlausibility(const PlausibilityInput& in) {
  PlausibilityResult r;
  int64_t t = 0;
  int64_t now = 0;
  if (!ParseRfc3339ToEpoch(in.t, &t)) {
    r.ok = false;
    r.reason = "unparseable-timestamp";
    return r;
  }
  if (!ParseRfc3339ToEpoch(in.now, &now)) {
    r.ok = false;
    r.reason = "unparseable-now";
    return r;
  }
  // Check 1 — future bound.
  if (t - now > kFutureBoundSeconds) {
    r.ok = false;
    r.reason = "future-bound";
    return r;
  }
  // Check 2 — causal monotonicity over resolved parents.
  for (const std::string& parent : in.parent_timestamps) {
    int64_t pt = 0;
    if (!ParseRfc3339ToEpoch(parent, &pt))
      continue;  // resolved history, not attacker-controlled here
    if (t < pt) {
      r.ok = false;
      r.reason = "causal-monotonicity";
      return r;
    }
  }
  // Check 3 — per-author monotonicity along the causal chain.
  for (const std::string& prior : in.same_author_prior) {
    int64_t pt = 0;
    if (!ParseRfc3339ToEpoch(prior, &pt))
      continue;
    if (t < pt) {
      r.ok = false;
      r.reason = "author-monotonicity";
      return r;
    }
  }
  return r;
}

// ---- URL / domain extraction -----------------------------------------------

std::vector<std::string> ExtractHttpUrls(const std::string& text) {
  std::vector<std::string> urls;
  const std::string lower = ToLowerAscii(text);
  size_t i = 0;
  while (i < text.size()) {
    const size_t h = lower.find("http", i);
    if (h == kNpos)
      break;
    size_t scheme_end = kNpos;
    if (lower.compare(h, 7, "http://") == 0)
      scheme_end = h + 7;
    else if (lower.compare(h, 8, "https://") == 0)
      scheme_end = h + 8;
    if (scheme_end == kNpos) {
      i = h + 4;
      continue;
    }
    size_t j = scheme_end;
    while (j < text.size() && !IsUrlTerminator(text[j]))
      ++j;
    std::string url = text.substr(h, j - h);
    // Strip trailing sentence punctuation and a closing paren commonly written
    // right after a URL in prose (e.g. "see (http://x.example)").
    while (!url.empty()) {
      const char last = url.back();
      if (last == '.' || last == ',' || last == ';' || last == ':' ||
          last == '!' || last == '?' || last == ')') {
        url.pop_back();
      } else {
        break;
      }
    }
    if (url.size() > scheme_end - h)  // something beyond the bare scheme
      urls.push_back(std::move(url));
    i = j;
  }
  return urls;
}

std::string UrlHost(const std::string& url) {
  const std::string lower = ToLowerAscii(url);
  size_t start = kNpos;
  if (lower.compare(0, 7, "http://") == 0)
    start = 7;
  else if (lower.compare(0, 8, "https://") == 0)
    start = 8;
  else
    return "";
  size_t end = url.size();
  for (size_t k = start; k < url.size(); ++k) {
    const char c = url[k];
    if (c == '/' || c == '?' || c == '#') {
      end = k;
      break;
    }
  }
  std::string authority = url.substr(start, end - start);
  // Strip userinfo.
  const size_t at = authority.rfind('@');
  if (at != kNpos)
    authority = authority.substr(at + 1);
  // Bracketed IPv6 literal: host is up to and including ']'.
  if (!authority.empty() && authority[0] == '[') {
    const size_t close = authority.find(']');
    if (close != kNpos)
      return ToLowerAscii(authority.substr(0, close + 1));
    return ToLowerAscii(authority);
  }
  // Strip a numeric port.
  const size_t colon = authority.rfind(':');
  if (colon != kNpos) {
    bool is_port = true;
    for (size_t k = colon + 1; k < authority.size(); ++k) {
      if (authority[k] < '0' || authority[k] > '9') {
        is_port = false;
        break;
      }
    }
    if (is_port)
      authority = authority.substr(0, colon);
  }
  return ToLowerAscii(authority);
}

std::string DataUrlMediaType(const std::string& text) {
  const std::string s = Trim(text);
  const std::string lower = ToLowerAscii(s);
  if (lower.compare(0, 5, "data:") != 0)
    return "";
  const size_t comma = s.find(',');
  if (comma == kNpos)
    return "";  // malformed data: URL
  const std::string meta = s.substr(5, comma - 5);
  const size_t semi = meta.find(';');
  const std::string mt = (semi == kNpos) ? meta : meta.substr(0, semi);
  if (mt.empty())
    return "text/plain";  // RFC 2397 default when the mediatype is omitted
  return ToLowerAscii(mt);
}

// ---- §6.2 content policy ---------------------------------------------------

size_t Utf8Length(const std::string& s) {
  size_t n = 0;
  for (const char ch : s) {
    if ((static_cast<unsigned char>(ch) & 0xC0) != 0x80)
      ++n;  // not a UTF-8 continuation byte
  }
  return n;
}

ContentResult EvaluateContentText(const ContentPolicy& policy,
                                  const std::string& text,
                                  const RegexMatcher& matcher) {
  ContentResult r;

  // Step 3 — length.
  if (policy.max_length.has_value() &&
      static_cast<int64_t>(Utf8Length(text)) > *policy.max_length) {
    r.allowed = false;
    r.reason = "max-length";
    return r;
  }

  // Step 4 — blocked patterns (fail-closed on timeout, §9.3).
  for (const std::string& pattern : policy.blocked_patterns) {
    const RegexOutcome outcome =
        matcher ? matcher(pattern, text) : RegexOutcome::kTimeout;
    if (outcome == RegexOutcome::kMatch) {
      r.allowed = false;
      r.reason = "blocked-pattern";
      return r;
    }
    if (outcome == RegexOutcome::kTimeout) {
      r.allowed = false;
      r.reason = "regex-timeout";
      return r;
    }
  }

  const std::vector<std::string> urls = ExtractHttpUrls(text);

  // Step 5 — URL policy.
  if (policy.allow_urls.has_value() && !*policy.allow_urls && !urls.empty()) {
    r.allowed = false;
    r.reason = "urls-not-allowed";
    return r;
  }

  // Step 6 — domain whitelist (globs).
  if (!policy.allowed_domains.empty()) {
    for (const std::string& url : urls) {
      const std::string host = UrlHost(url);
      bool ok = false;
      for (const std::string& domain : policy.allowed_domains) {
        if (GlobMatch(ToLowerAscii(domain), host)) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        r.allowed = false;
        r.reason = "domain-not-allowed";
        return r;
      }
    }
  }

  // Step 7 — media type. Only a data: URL carries a locally-determinable media
  // type; other object forms have none and skip the check.
  if (!policy.allow_media_types.empty()) {
    const std::string media_type = DataUrlMediaType(text);
    if (!media_type.empty()) {
      bool ok = false;
      for (const std::string& glob : policy.allow_media_types) {
        if (GlobMatch(ToLowerAscii(glob), media_type)) {
          ok = true;
          break;
        }
      }
      if (!ok) {
        r.allowed = false;
        r.reason = "media-type-not-allowed";
        return r;
      }
    }
  }

  return r;
}

// ---- living-web Verifiable-Credential profile (§4 amendment) ---------------

bool ParseLivingWebVc(const std::string& json, LivingWebVc* out) {
  *out = LivingWebVc();
  JsonValue root;
  std::string error;
  if (!ParseJson(json, &root, &error) || !root.is_object())
    return false;

  // "type": a single string or an ordered array of strings.
  if (const JsonValue* type = root.Find("type")) {
    if (type->is_string()) {
      out->types.push_back(type->string_value);
    } else if (type->is_array()) {
      for (const JsonValue& entry : type->array_value) {
        if (entry.is_string())
          out->types.push_back(entry.string_value);
      }
    }
  }
  if (out->types.empty())
    return false;

  // "issuer": a string DID, or an object carrying its "id".
  if (const JsonValue* issuer = root.Find("issuer")) {
    if (issuer->is_string()) {
      out->issuer = issuer->string_value;
    } else if (issuer->is_object()) {
      if (const JsonValue* id = issuer->Find("id")) {
        if (id->is_string())
          out->issuer = id->string_value;
      }
    }
  }
  if (out->issuer.empty())
    return false;

  // "issuanceDate" (VC 1.1) or "validFrom" (VC 2.0).
  const JsonValue* issued = root.Find("issuanceDate");
  if (!issued)
    issued = root.Find("validFrom");
  if (issued && issued->is_string())
    out->issuance_date = issued->string_value;

  // "credentialSubject"."id" — the holder DID.
  if (const JsonValue* subject = root.Find("credentialSubject")) {
    if (subject->is_object()) {
      if (const JsonValue* id = subject->Find("id")) {
        if (id->is_string())
          out->subject_id = id->string_value;
      }
    }
  }
  if (out->subject_id.empty())
    return false;

  // "credentialStatus" is OPTIONAL; when present its "id" is the revocation
  // subject the handler resolves.
  if (const JsonValue* status = root.Find("credentialStatus")) {
    if (status->is_object()) {
      out->has_status = true;
      if (const JsonValue* id = status->Find("id")) {
        if (id->is_string())
          out->status_id = id->string_value;
      }
    }
  }

  // "proof" with a non-empty "proofValue" is REQUIRED.
  const JsonValue* proof = root.Find("proof");
  if (!proof || !proof->is_object())
    return false;
  const JsonValue* proof_value = proof->Find("proofValue");
  if (!proof_value || !proof_value->is_string() ||
      proof_value->string_value.empty()) {
    return false;
  }
  out->proof_value = proof_value->string_value;
  if (const JsonValue* v = proof->Find("proofPurpose")) {
    if (v->is_string())
      out->proof_purpose = v->string_value;
  }
  if (const JsonValue* v = proof->Find("created")) {
    if (v->is_string())
      out->proof_created = v->string_value;
  }
  if (const JsonValue* v = proof->Find("verificationMethod")) {
    if (v->is_string())
      out->proof_method = v->string_value;
  }

  out->valid = true;
  return true;
}

std::string BuildVcProofPreimage(const LivingWebVc& vc) {
  std::string p = "living-web/vc/credential/v1";
  p += '\n';
  for (size_t i = 0; i < vc.types.size(); ++i) {
    if (i)
      p += ',';
    p += vc.types[i];
  }
  p += '\n';
  p += vc.issuer;
  p += '\n';
  p += vc.issuance_date;
  p += '\n';
  p += vc.subject_id;
  p += '\n';
  p += vc.status_id;  // "" when no credentialStatus
  p += '\n';
  p += vc.proof_purpose;
  p += '\n';
  p += vc.proof_created;
  p += '\n';
  p += vc.proof_method;
  return p;
}

}  // namespace constraint_vocab
}  // namespace living_web
