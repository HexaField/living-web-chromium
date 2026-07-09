// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/did_graph.h"

#include <algorithm>
#include <set>

#include "content/browser/did/did_key_codec.h"

namespace living_web {

namespace {

// Minimal RFC 8259 string escaping for the JSON-LD projection. DID and
// multibase values contain no metacharacters, but the projection is a public
// output surface so it escapes defensively rather than trusting its inputs.
std::string JsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          static const char kHex[] = "0123456789abcdef";
          out += "\\u00";
          out += kHex[(c >> 4) & 0xf];
          out += kHex[c & 0xf];
        } else {
          out += c;
        }
    }
  }
  return out;
}

// Renders a capability-section membership list as a JSON array of DID-URL
// strings, e.g. ["did:graph:z...#z...", ...].
std::string JsonStringArray(const std::vector<std::string>& items) {
  std::string out = "[";
  for (size_t i = 0; i < items.size(); ++i) {
    if (i)
      out += ", ";
    out += "\"" + JsonEscape(items[i]) + "\"";
  }
  out += "]";
  return out;
}

}  // namespace

const char* SectionPredicate(DIDCapabilitySection section) {
  switch (section) {
    case DIDCapabilitySection::kCapabilityInvocation:
      return kDidCapabilityInvocation;
    case DIDCapabilitySection::kCapabilityDelegation:
      return kDidCapabilityDelegation;
    case DIDCapabilitySection::kAssertionMethod:
      return kDidAssertionMethod;
    case DIDCapabilitySection::kAuthentication:
      return kDidAuthentication;
  }
  return "";  // All enumerators handled above; unreachable.
}

const char* SectionToken(DIDCapabilitySection section) {
  switch (section) {
    case DIDCapabilitySection::kCapabilityInvocation:
      return "capabilityInvocation";
    case DIDCapabilitySection::kCapabilityDelegation:
      return "capabilityDelegation";
    case DIDCapabilitySection::kAssertionMethod:
      return "assertionMethod";
    case DIDCapabilitySection::kAuthentication:
      return "authentication";
  }
  return "";  // All enumerators handled above; unreachable.
}

std::optional<DIDCapabilitySection> SectionFromToken(const std::string& token) {
  if (token == "capabilityInvocation")
    return DIDCapabilitySection::kCapabilityInvocation;
  if (token == "capabilityDelegation")
    return DIDCapabilitySection::kCapabilityDelegation;
  if (token == "assertionMethod")
    return DIDCapabilitySection::kAssertionMethod;
  if (token == "authentication")
    return DIDCapabilitySection::kAuthentication;
  return std::nullopt;
}

namespace did_graph {

std::optional<std::string> DeriveDidGraphEd25519(
    const std::vector<uint8_t>& public_key) {
  if (public_key.size() != 32)
    return std::nullopt;
  std::vector<uint8_t> prefixed;
  prefixed.reserve(2 + 32);
  prefixed.push_back(did_key::kEd25519PubMulticodec[0]);
  prefixed.push_back(did_key::kEd25519PubMulticodec[1]);
  prefixed.insert(prefixed.end(), public_key.begin(), public_key.end());
  return std::string(kMethodPrefix) + "z" + did_key::Base58BtcEncode(prefixed);
}

std::optional<std::vector<uint8_t>> ParseDidGraphEd25519(
    const std::string& did) {
  constexpr char kPrefix[] = "did:graph:z";
  constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
  if (did.compare(0, kPrefixLen, kPrefix) != 0)
    return std::nullopt;

  // The method-specific identifier ends at the first fragment/query/path
  // delimiter (a verification-method reference arrives as did:graph:z...#z...).
  std::string mb = did.substr(kPrefixLen - 1);  // keep the leading 'z'
  const size_t delim = mb.find_first_of("#?/");
  if (delim != std::string::npos)
    mb = mb.substr(0, delim);

  auto decoded = did_key::MultibaseDecode(mb);
  if (!decoded)
    return std::nullopt;
  if (decoded->size() != 2 + 32)
    return std::nullopt;
  if ((*decoded)[0] != did_key::kEd25519PubMulticodec[0] ||
      (*decoded)[1] != did_key::kEd25519PubMulticodec[1]) {
    return std::nullopt;  // Not an Ed25519 multicodec.
  }
  return std::vector<uint8_t>(decoded->begin() + 2, decoded->end());
}

bool IsDidGraph(const std::string& did) {
  return did.rfind(kMethodPrefix, 0) == 0;
}

}  // namespace did_graph

std::optional<std::vector<uint8_t>> ParseAnyDidEd25519(const std::string& did) {
  if (did_graph::IsDidGraph(did))
    return did_graph::ParseDidGraphEd25519(did);
  return did_key::ParseDidKeyEd25519(did);
}

std::optional<std::vector<uint8_t>> DecodePublicKeyMultibase(
    const std::string& multibase) {
  auto decoded = did_key::MultibaseDecode(multibase);
  if (!decoded)
    return std::nullopt;
  if (decoded->size() != 2 + 32)
    return std::nullopt;
  if ((*decoded)[0] != did_key::kEd25519PubMulticodec[0] ||
      (*decoded)[1] != did_key::kEd25519PubMulticodec[1]) {
    return std::nullopt;
  }
  return std::vector<uint8_t>(decoded->begin() + 2, decoded->end());
}

std::string BareDid(const std::string& did_url) {
  const size_t delim = did_url.find_first_of("#?/");
  if (delim == std::string::npos)
    return did_url;
  return did_url.substr(0, delim);
}

// ---- DidDocument -----------------------------------------------------------

const std::vector<std::string>& DidDocument::Section(
    DIDCapabilitySection section) const {
  switch (section) {
    case DIDCapabilitySection::kCapabilityInvocation:
      return capability_invocation;
    case DIDCapabilitySection::kCapabilityDelegation:
      return capability_delegation;
    case DIDCapabilitySection::kAssertionMethod:
      return assertion_method;
    case DIDCapabilitySection::kAuthentication:
      return authentication;
  }
  return authentication;  // All enumerators handled above; unreachable.
}

std::vector<std::string>& DidDocument::Section(DIDCapabilitySection section) {
  return const_cast<std::vector<std::string>&>(
      static_cast<const DidDocument*>(this)->Section(section));
}

bool DidDocument::InSection(DIDCapabilitySection section,
                            const std::string& method_id) const {
  const auto& ids = Section(section);
  return std::find(ids.begin(), ids.end(), method_id) != ids.end();
}

const VerificationMethod* DidDocument::FindMethod(
    const std::string& method_id) const {
  for (const auto& vm : verification_method) {
    if (vm.id == method_id)
      return &vm;
  }
  return nullptr;
}

size_t DidDocument::SectionSize(DIDCapabilitySection section) const {
  // Count distinct method ids: a well-formed projection never duplicates, but
  // the §5.4 brick-state guard must not be fooled into reading a phantom second
  // delegate from an accidental duplicate triple.
  const auto& ids = Section(section);
  std::set<std::string> distinct(ids.begin(), ids.end());
  return distinct.size();
}

std::string DidDocument::ToJsonLd() const {
  std::string vms = "[";
  for (size_t i = 0; i < verification_method.size(); ++i) {
    const auto& vm = verification_method[i];
    if (i)
      vms += ",";
    vms += R"(
    {
      "id": ")" + JsonEscape(vm.id) + R"(",
      "type": ")" + JsonEscape(vm.type) + R"(",
      "controller": ")" + JsonEscape(vm.controller) + R"(",
      "publicKeyMultibase": ")" +
           JsonEscape(vm.public_key_multibase) + R"("
    })";
  }
  vms += "\n  ]";

  std::string doc = R"({
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": ")" + JsonEscape(id) +
                    R"(",
  "verificationMethod": )" +
                    vms + R"(,
  "authentication": )" +
                    JsonStringArray(authentication) + R"(,
  "assertionMethod": )" +
                    JsonStringArray(assertion_method) + R"(,
  "capabilityDelegation": )" +
                    JsonStringArray(capability_delegation) + R"(,
  "capabilityInvocation": )" +
                    JsonStringArray(capability_invocation);
  if (deactivated) {
    doc += R"(,
  "deactivated": true)";
  }
  doc += R"(,
  "trustLevel": ")" + JsonEscape(trust_level) +
         R"("
})";
  return doc;
}

}  // namespace living_web
