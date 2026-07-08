// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/module_runtime/module_capabilities.h"

#include <cctype>

namespace living_web {

namespace {

// The parameterised capability prefixes (§8). A token beginning with one of
// these carries a `param` suffix; the remaining tokens are exact matches.
struct PrefixKind {
  const char* prefix;
  CapabilityKind kind;
};

constexpr PrefixKind kPrefixes[] = {
    {"network.relay.", CapabilityKind::kNetworkRelay},
    {"network.peer.", CapabilityKind::kNetworkPeer},
    {"network.fetch.", CapabilityKind::kNetworkFetch},
    {"storage.module.", CapabilityKind::kStorageModule},
};

struct ExactKind {
  const char* token;
  CapabilityKind kind;
};

constexpr ExactKind kExact[] = {
    {"graph.read", CapabilityKind::kGraphRead},
    {"graph.write", CapabilityKind::kGraphWrite},
    {"crypto.commit-sign", CapabilityKind::kCryptoCommitSign},
    {"crypto.signal-sign", CapabilityKind::kCryptoSignalSign},
    {"crypto.verify", CapabilityKind::kCryptoVerify},
    {"signal.send", CapabilityKind::kSignalSend},
    {"signal.receive", CapabilityKind::kSignalReceive},
    {"time.wallclock", CapabilityKind::kTimeWallclock},
    {"time.monotonic", CapabilityKind::kTimeMonotonic},
    {"random.csprng", CapabilityKind::kRandomCsprng},
};

bool StartsWith(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

std::string ToLowerAscii(const std::string& s) {
  std::string out = s;
  for (char& c : out)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

uint64_t ParseSizeBytes(const std::string& s) {
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9')
      return 0;
    v = v * 10 + static_cast<uint64_t>(c - '0');
  }
  return v;
}

}  // namespace

const char* HostErrorString(HostError e) {
  switch (e) {
    case HostError::kNone:
      return "none";
    case HostError::kNotAuthorised:
      return "not-authorised";
    case HostError::kUnknownScope:
      return "unknown-scope";
    case HostError::kQuotaExceeded:
      return "quota-exceeded";
    case HostError::kNetworkError:
      return "network-error";
    case HostError::kSigningRefused:
      return "signing-refused";
    case HostError::kInvalidArgument:
      return "invalid-argument";
    case HostError::kBudgetExceeded:
      return "budget-exceeded";
    case HostError::kInternal:
      return "internal";
  }
  return "internal";
}

Capability ParseCapability(const std::string& token) {
  Capability cap;
  for (const auto& e : kExact) {
    if (token == e.token) {
      cap.kind = e.kind;
      return cap;
    }
  }
  for (const auto& p : kPrefixes) {
    if (StartsWith(token, p.prefix)) {
      cap.kind = p.kind;
      cap.param = token.substr(std::string(p.prefix).size());
      if (p.kind == CapabilityKind::kStorageModule)
        cap.size_bytes = ParseSizeBytes(cap.param);
      return cap;
    }
  }
  cap.kind = CapabilityKind::kUnknown;
  cap.param = token;
  return cap;
}

std::string CapabilityOriginOf(const std::string& url) {
  const std::string lower = ToLowerAscii(url);
  const size_t scheme_end = lower.find("://");
  if (scheme_end == std::string::npos)
    return std::string();
  const size_t authority_start = scheme_end + 3;
  size_t authority_end = lower.find('/', authority_start);
  if (authority_end == std::string::npos)
    authority_end = lower.size();
  // scheme://host[:port]/  — trailing slash included so it matches a granted
  // origin written with the customary trailing slash (§8.2 example).
  return lower.substr(0, authority_end) + "/";
}

// static
CapabilitySet CapabilitySet::FromManifest(
    const std::vector<std::string>& required) {
  CapabilitySet set;
  for (const std::string& token : required)
    set.Add(token);
  return set;
}

void CapabilitySet::Add(const std::string& token) {
  caps_.push_back(ParseCapability(token));
}

bool CapabilitySet::HasKind(CapabilityKind kind) const {
  for (const Capability& c : caps_) {
    if (c.kind == kind)
      return true;
  }
  return false;
}

bool CapabilitySet::AllowsGraphRead() const {
  return HasKind(CapabilityKind::kGraphRead);
}
bool CapabilitySet::AllowsGraphWrite() const {
  return HasKind(CapabilityKind::kGraphWrite);
}
bool CapabilitySet::AllowsCommitSign() const {
  return HasKind(CapabilityKind::kCryptoCommitSign);
}
bool CapabilitySet::AllowsSignalSign() const {
  return HasKind(CapabilityKind::kCryptoSignalSign);
}
bool CapabilitySet::AllowsVerify() const {
  return HasKind(CapabilityKind::kCryptoVerify);
}

bool CapabilitySet::AllowsRelay(const std::string& endpoint) const {
  for (const Capability& c : caps_) {
    if (c.kind == CapabilityKind::kNetworkRelay && c.param == endpoint)
      return true;
  }
  return false;
}

bool CapabilitySet::AllowsPeer(const std::string& protocol) const {
  for (const Capability& c : caps_) {
    if (c.kind == CapabilityKind::kNetworkPeer && c.param == protocol)
      return true;
  }
  return false;
}

bool CapabilitySet::AllowsFetch(const std::string& url) const {
  const std::string origin = CapabilityOriginOf(url);
  if (origin.empty())
    return false;
  for (const Capability& c : caps_) {
    if (c.kind == CapabilityKind::kNetworkFetch &&
        ToLowerAscii(c.param) == origin) {
      return true;
    }
  }
  return false;
}

bool CapabilitySet::AllowsSignalSend() const {
  return HasKind(CapabilityKind::kSignalSend);
}
bool CapabilitySet::AllowsSignalReceive() const {
  return HasKind(CapabilityKind::kSignalReceive);
}
bool CapabilitySet::AllowsWallclock() const {
  return HasKind(CapabilityKind::kTimeWallclock);
}
bool CapabilitySet::AllowsMonotonic() const {
  return HasKind(CapabilityKind::kTimeMonotonic);
}
bool CapabilitySet::AllowsCsprng() const {
  return HasKind(CapabilityKind::kRandomCsprng);
}

bool CapabilitySet::HasStorage() const {
  return HasKind(CapabilityKind::kStorageModule);
}

uint64_t CapabilitySet::StorageQuotaBytes() const {
  uint64_t max = 0;
  for (const Capability& c : caps_) {
    if (c.kind == CapabilityKind::kStorageModule && c.size_bytes > max)
      max = c.size_bytes;
  }
  return max;
}

bool CapabilitySet::AllKnown() const {
  for (const Capability& c : caps_) {
    if (c.kind == CapabilityKind::kUnknown)
      return false;
  }
  return true;
}

}  // namespace living_web
