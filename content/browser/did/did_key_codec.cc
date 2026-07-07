// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/did_key_codec.h"

#include <array>

namespace living_web {
namespace did_key {

namespace {

constexpr char kBase58Alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Reverse lookup table for base58 decoding: ASCII byte -> value in [0,57], or
// -1 if the byte is not part of the alphabet.
const std::array<int8_t, 256>& Base58DecodeMap() {
  static const std::array<int8_t, 256> map = [] {
    std::array<int8_t, 256> m;
    m.fill(-1);
    for (int8_t i = 0; i < 58; ++i)
      m[static_cast<uint8_t>(kBase58Alphabet[i])] = i;
    return m;
  }();
  return map;
}

int HexVal(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  return -1;
}

std::optional<std::vector<uint8_t>> Base16Decode(const std::string& s) {
  if (s.size() % 2 != 0)
    return std::nullopt;
  std::vector<uint8_t> out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    int hi = HexVal(s[i]);
    int lo = HexVal(s[i + 1]);
    if (hi < 0 || lo < 0)
      return std::nullopt;
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::optional<std::vector<uint8_t>> Base64UrlDecode(const std::string& s) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z')
      return c - 'A';
    if (c >= 'a' && c <= 'z')
      return c - 'a' + 26;
    if (c >= '0' && c <= '9')
      return c - '0' + 52;
    if (c == '-')
      return 62;
    if (c == '_')
      return 63;
    return -1;
  };
  std::vector<uint8_t> out;
  uint32_t buffer = 0;
  int bits = 0;
  for (char c : s) {
    int v = val(c);
    if (v < 0)
      return std::nullopt;
    buffer = (buffer << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
    }
  }
  // Any leftover bits MUST be zero padding; reject non-canonical trailing bits.
  if (bits > 0 && (buffer & ((1u << bits) - 1)) != 0)
    return std::nullopt;
  return out;
}

}  // namespace

std::string Base58BtcEncode(const std::vector<uint8_t>& bytes) {
  size_t zeros = 0;
  while (zeros < bytes.size() && bytes[zeros] == 0)
    ++zeros;

  // Upper bound on the base58 size: ceil(log(256)/log(58) * n) = 138/100 * n.
  std::vector<uint8_t> b58((bytes.size() - zeros) * 138 / 100 + 1, 0);
  for (size_t i = zeros; i < bytes.size(); ++i) {
    int carry = bytes[i];
    for (size_t j = b58.size(); j-- > 0;) {
      carry += 256 * b58[j];
      b58[j] = static_cast<uint8_t>(carry % 58);
      carry /= 58;
    }
  }

  size_t it = 0;
  while (it < b58.size() && b58[it] == 0)
    ++it;

  std::string result;
  result.reserve(zeros + (b58.size() - it));
  result.assign(zeros, '1');
  for (; it < b58.size(); ++it)
    result += kBase58Alphabet[b58[it]];
  return result;
}

std::optional<std::vector<uint8_t>> Base58BtcDecode(const std::string& input) {
  const auto& map = Base58DecodeMap();

  size_t zeros = 0;
  while (zeros < input.size() && input[zeros] == '1')
    ++zeros;

  // Upper bound on the byte size: ceil(log(58)/log(256) * n) = 733/1000 * n.
  std::vector<uint8_t> b256((input.size() - zeros) * 733 / 1000 + 1, 0);
  for (size_t i = zeros; i < input.size(); ++i) {
    int8_t c = map[static_cast<uint8_t>(input[i])];
    if (c < 0)
      return std::nullopt;  // Character outside the base58 alphabet.
    int carry = c;
    for (size_t j = b256.size(); j-- > 0;) {
      carry += 58 * b256[j];
      b256[j] = static_cast<uint8_t>(carry & 0xff);
      carry >>= 8;
    }
    if (carry != 0)
      return std::nullopt;  // Overflow: sizing invariant violated.
  }

  size_t it = 0;
  while (it < b256.size() && b256[it] == 0)
    ++it;

  std::vector<uint8_t> result;
  result.reserve(zeros + (b256.size() - it));
  result.assign(zeros, 0);
  for (; it < b256.size(); ++it)
    result.push_back(b256[it]);
  return result;
}

std::string MultibaseEncode(const std::vector<uint8_t>& bytes) {
  return "z" + Base58BtcEncode(bytes);
}

std::optional<std::vector<uint8_t>> MultibaseDecode(const std::string& input) {
  if (input.empty())
    return std::nullopt;
  const std::string body = input.substr(1);
  switch (input[0]) {
    case 'z':
      return Base58BtcDecode(body);
    case 'f':
    case 'F':
      return Base16Decode(body);
    case 'u':
    case 'U':
      return Base64UrlDecode(body);
    default:
      return std::nullopt;
  }
}

std::optional<std::string> DeriveDidKeyEd25519(
    const std::vector<uint8_t>& public_key) {
  if (public_key.size() != 32)
    return std::nullopt;
  std::vector<uint8_t> prefixed;
  prefixed.reserve(2 + 32);
  prefixed.push_back(kEd25519PubMulticodec[0]);
  prefixed.push_back(kEd25519PubMulticodec[1]);
  prefixed.insert(prefixed.end(), public_key.begin(), public_key.end());
  return "did:key:z" + Base58BtcEncode(prefixed);
}

std::optional<std::vector<uint8_t>> ParseDidKeyEd25519(const std::string& did) {
  constexpr char kPrefix[] = "did:key:z";
  constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
  if (did.compare(0, kPrefixLen, kPrefix) != 0)
    return std::nullopt;

  // The method-specific identifier ends at the first fragment/query/path
  // delimiter. did:key has no path, but a verification-method reference may be
  // supplied as did:key:z...#z... — strip anything from the delimiter onward.
  std::string mb = did.substr(kPrefixLen - 1);  // keep the leading 'z'
  const size_t delim = mb.find_first_of("#?/");
  if (delim != std::string::npos)
    mb = mb.substr(0, delim);

  auto decoded = MultibaseDecode(mb);
  if (!decoded)
    return std::nullopt;
  if (decoded->size() != 2 + 32)
    return std::nullopt;
  if ((*decoded)[0] != kEd25519PubMulticodec[0] ||
      (*decoded)[1] != kEd25519PubMulticodec[1]) {
    return std::nullopt;  // Not an Ed25519 multicodec.
  }
  return std::vector<uint8_t>(decoded->begin() + 2, decoded->end());
}

std::optional<std::string> Ed25519PublicKeyMultibase(
    const std::vector<uint8_t>& public_key) {
  if (public_key.size() != 32)
    return std::nullopt;
  std::vector<uint8_t> prefixed;
  prefixed.reserve(2 + 32);
  prefixed.push_back(kEd25519PubMulticodec[0]);
  prefixed.push_back(kEd25519PubMulticodec[1]);
  prefixed.insert(prefixed.end(), public_key.begin(), public_key.end());
  return MultibaseEncode(prefixed);
}

}  // namespace did_key
}  // namespace living_web
