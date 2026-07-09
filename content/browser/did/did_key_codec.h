// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// did:key codec for the Ed25519 verification method, implementing the
// encoding mandated by the Decentralised Identity Web Platform specification
// (§4.1) and [[DID-KEY]]:
//
//     did:key:z || base58btc( 0xed01 || raw-32-byte-Ed25519-public-key )
//
// This translation unit has NO Chromium dependencies (only the C++ standard
// library) so that it can be shared verbatim between the browser-process
// backend (content/browser/did/did_key_provider.cc) and the standalone
// conformance harness. There is exactly one implementation of the encoding;
// the two callers never diverge.

#ifndef CONTENT_BROWSER_DID_DID_KEY_CODEC_H_
#define CONTENT_BROWSER_DID_DID_KEY_CODEC_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace living_web {
namespace did_key {

// Multicodec unsigned-varint prefix for an Ed25519 public key: 0xed -> {0xed,
// 0x01} as a LEB128 varint. Every Ed25519 did:key therefore begins "did:key:z6Mk".
inline constexpr uint8_t kEd25519PubMulticodec[2] = {0xed, 0x01};

// Raw base58btc (Bitcoin alphabet), the codec behind multibase 'z'.
std::string Base58BtcEncode(const std::vector<uint8_t>& bytes);
std::optional<std::vector<uint8_t>> Base58BtcDecode(const std::string& input);

// Multibase. Encoding always emits base58btc ('z'). Decoding accepts the
// bases this platform emits or is likely to ingest: 'z' base58btc, 'f'/'F'
// base16, 'u'/'U' base64url (unpadded). Any other prefix yields nullopt.
std::string MultibaseEncode(const std::vector<uint8_t>& bytes);
std::optional<std::vector<uint8_t>> MultibaseDecode(const std::string& input);

// did:key derivation and parsing for Ed25519. |public_key| MUST be 32 bytes.
std::optional<std::string> DeriveDidKeyEd25519(
    const std::vector<uint8_t>& public_key);

// Parses a "did:key:z..." URI (optionally carrying a #fragment or path/query,
// which are ignored for key extraction), validates the Ed25519 multicodec
// prefix, and returns the raw 32-byte public key. nullopt on any malformation.
std::optional<std::vector<uint8_t>> ParseDidKeyEd25519(const std::string& did);

// The multibase value placed in a DID document verificationMethod's
// publicKeyMultibase: multibase(base58btc, 0xed01 || public_key). This is
// identical to the DID's own z-suffix. |public_key| MUST be 32 bytes.
std::optional<std::string> Ed25519PublicKeyMultibase(
    const std::vector<uint8_t>& public_key);

}  // namespace did_key
}  // namespace living_web

#endif  // CONTENT_BROWSER_DID_DID_KEY_CODEC_H_
