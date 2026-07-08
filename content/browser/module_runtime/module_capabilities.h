// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Sync Module Architecture (Spec 06) — capability vocabulary + host-error model.
//
// The Chromium-independent core (namespace `living_web`, pure-std, no Chromium
// and no standalone-shim dependencies) shared byte-for-byte by the browser
// module runtime (content/browser/module_runtime/module_runtime_host.*) and the
// standalone harness (standalone/module_runtime_provider.h). It defines:
//
//   * The §6.3 `host-error` variant every imported host function may raise, so
//     both worlds map capability/scope/quota failures to identical codes.
//   * The §8 capability vocabulary — the fixed set of capability tokens a module
//     declares in its manifest (§8.2) and the user consents to (§7.2) — parsed
//     into a structured `Capability`, and a `CapabilitySet` grant check that
//     gates every host surface (§8.3: the module cannot forge its way past a
//     `not-authorised`).
//
// Nothing here performs I/O, crypto, or JSON parsing; it is the pure grant
// algebra the runtime enforces behind the WIT host imports (§6.3).

#ifndef CONTENT_BROWSER_MODULE_RUNTIME_MODULE_CAPABILITIES_H_
#define CONTENT_BROWSER_MODULE_RUNTIME_MODULE_CAPABILITIES_H_

#include <cstdint>
#include <string>
#include <vector>

namespace living_web {

// §6.3 `host-error` — the error any imported host function raises. Capability,
// scope, and resource-limit failures are all reported here; the module cannot
// forge its way past a `kNotAuthorised` (§8.3, §9.3).
enum class HostError {
  kNone,
  kNotAuthorised,   // asked for a graph/endpoint/handle outside the grant set
  kUnknownScope,    // the graph-did (or space) is not in the authorised set
  kQuotaExceeded,   // a declared limit was exceeded (storage.module.<size>, §8.1)
  kNetworkError,    // transport/relay/fetch failure → [[CONTEXT-SYNC]] NetworkError
  kSigningRefused,  // the scoped signer refused the requested shape (§5.4, §9.7)
  kInvalidArgument, // malformed argument (bad IRI, bad SPARQL, non-UTF-8, …)
  kBudgetExceeded,  // exceeded execution-budget-ms and was terminated (§6.2)
  kInternal,        // catch-all internal host failure
};

// Stable lowercase token for a host error (matches the WIT variant case names).
const char* HostErrorString(HostError e);

// §8 capability kinds — the fixed vocabulary. `kUnknown` is any token outside
// the vocabulary; a manifest requiring one is rejected at install (§7.1).
enum class CapabilityKind {
  kGraphRead,         // graph.read
  kGraphWrite,        // graph.write
  kCryptoCommitSign,  // crypto.commit-sign
  kCryptoSignalSign,  // crypto.signal-sign
  kCryptoVerify,      // crypto.verify
  kNetworkRelay,      // network.relay.<endpoint>
  kNetworkPeer,       // network.peer.<protocol>
  kNetworkFetch,      // network.fetch.<origin>
  kStorageModule,     // storage.module.<size>
  kSignalSend,        // signal.send
  kSignalReceive,     // signal.receive
  kTimeWallclock,     // time.wallclock
  kTimeMonotonic,     // time.monotonic
  kRandomCsprng,      // random.csprng
  kUnknown,
};

// A single parsed capability token. `param` is the raw suffix for the
// parameterised kinds (endpoint / protocol / origin / size); empty otherwise.
// `size_bytes` is the parsed byte cap for `storage.module.<size>`.
struct Capability {
  CapabilityKind kind = CapabilityKind::kUnknown;
  std::string param;
  uint64_t size_bytes = 0;
};

// Parse one §8 capability token. An unrecognised token yields kind kUnknown with
// the original text preserved in `param` (so the consent prompt can show it).
Capability ParseCapability(const std::string& token);

// The scheme://host[:port] origin of a URL, lowercased, with no trailing path —
// used to match `network.fetch.<origin>` / `network.relay.<endpoint>` grants.
// Returns the empty string for a URL with no `://`.
std::string CapabilityOriginOf(const std::string& url);

// The consented grant set a module holds (§7.2). Every host surface consults it
// (§8.3); an operation outside the set is denied rather than performed.
class CapabilitySet {
 public:
  CapabilitySet() = default;

  // Build from a manifest's `capabilitiesRequired` (§8.2). Unknown tokens are
  // retained as kUnknown so callers can reject the manifest at install time.
  static CapabilitySet FromManifest(const std::vector<std::string>& required);

  void Add(const std::string& token);

  bool AllowsGraphRead() const;
  bool AllowsGraphWrite() const;
  bool AllowsCommitSign() const;
  bool AllowsSignalSign() const;
  bool AllowsVerify() const;
  // Exact-endpoint match against a granted `network.relay.<endpoint>` (§8).
  bool AllowsRelay(const std::string& endpoint) const;
  bool AllowsPeer(const std::string& protocol) const;
  // Origin match: `url`'s origin must equal a granted `network.fetch.<origin>`.
  bool AllowsFetch(const std::string& url) const;
  bool AllowsSignalSend() const;
  bool AllowsSignalReceive() const;
  bool AllowsWallclock() const;
  bool AllowsMonotonic() const;
  bool AllowsCsprng() const;

  bool HasStorage() const;
  // The declared `storage.module.<size>` byte cap; 0 when no storage grant.
  uint64_t StorageQuotaBytes() const;

  // True iff every token parsed to a known capability kind (§7.1 step 3).
  bool AllKnown() const;

  const std::vector<Capability>& all() const { return caps_; }

 private:
  bool HasKind(CapabilityKind kind) const;
  std::vector<Capability> caps_;
};

}  // namespace living_web

#endif  // CONTENT_BROWSER_MODULE_RUNTIME_MODULE_CAPABILITIES_H_
