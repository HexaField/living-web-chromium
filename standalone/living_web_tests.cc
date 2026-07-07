// Living Web — Test Suite
//
// A minimal, self-registering test framework (no gtest dependency). The base
// ships the framework and the runner only. Each per-spec branch adds the
// includes, helpers, and TEST() blocks it needs — so the suite grows one spec
// at a time and every test is introduced by the PR that implements its spec.

#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Spec 01 — Decentralised Identity.
#include "did_key_provider.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/jcs.h"
#include "third_party/ed25519/ed25519.h"

using namespace living_web;

// ============================================================
// Minimal test framework
// ============================================================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static std::vector<std::string> failures;

#define TEST(name) \
  static void test_##name(); \
  static bool test_##name##_registered = (register_test(#name, test_##name), true); \
  static void test_##name()

#define EXPECT_TRUE(expr) do { \
  if (!(expr)) { \
    std::cerr << "  FAIL: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_FALSE(expr) EXPECT_TRUE(!(expr))
#define EXPECT_EQ(a, b) do { \
  auto _a = (a); auto _b = (b); \
  if (_a != _b) { \
    std::cerr << "  FAIL: " << #a << " == " << #b << " (" << _a << " != " << _b << ") at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_NE(a, b) do { \
  if ((a) == (b)) { \
    std::cerr << "  FAIL: " << #a << " != " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

#define EXPECT_GT(a, b) do { \
  if (!((a) > (b))) { \
    std::cerr << "  FAIL: " << #a << " > " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; \
    throw std::runtime_error("assertion failed"); \
  } \
} while(0)

struct TestEntry {
  std::string name;
  std::function<void()> fn;
};
static std::vector<TestEntry>& test_registry() {
  static std::vector<TestEntry> r;
  return r;
}
static void register_test(const std::string& name, std::function<void()> fn) {
  test_registry().push_back({name, fn});
}

// ============================================================
// Test cases
// ============================================================
//
// Populated per spec. Each per-spec branch inserts its includes above, its
// helpers here, and its TEST() blocks below this banner.

// ============================================================
// Spec 01 — DID key management
// ============================================================

TEST(DID_CreateKey) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Test Identity");
  EXPECT_TRUE(key != nullptr);
  EXPECT_FALSE(key->did.empty());
  EXPECT_EQ(key->algorithm, "Ed25519");
  EXPECT_EQ(key->display_name, "Test Identity");
  EXPECT_FALSE(key->is_locked);
  EXPECT_EQ(key->public_key.size(), 32u);
  EXPECT_EQ(key->private_key.size(), 64u);
  EXPECT_EQ(key->did.substr(0, 12), "did:key:z6Mk");
}

TEST(DID_ListCredentials) {
  DIDKeyProvider provider;
  provider.CreateKey("First");
  provider.CreateKey("Second");
  EXPECT_EQ(provider.ListCredentials().size(), 2u);
}

TEST(DID_ActiveCredential) {
  DIDKeyProvider provider;
  auto first = provider.CreateKey("First");
  auto second = provider.CreateKey("Second");
  auto active = provider.GetActiveCredential();
  EXPECT_TRUE(active != nullptr);
  EXPECT_EQ(active->id, first->id);
  EXPECT_TRUE(provider.SetActiveCredential(second->id));
  active = provider.GetActiveCredential();
  EXPECT_EQ(active->id, second->id);
}

TEST(DID_DeleteCredential) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("ToDelete");
  EXPECT_TRUE(provider.DeleteCredential(key->id));
  EXPECT_EQ(provider.ListCredentials().size(), 0u);
  EXPECT_FALSE(provider.DeleteCredential("nonexistent"));
}

TEST(DID_SignAndVerify) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Signer");
  auto result = provider.Sign(key->id, R"({"message":"hello"})");
  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(result->author, key->did);
  EXPECT_FALSE(result->proof_sig.empty());
  EXPECT_FALSE(result->timestamp.empty());
  // §6.4 step 5: proof carries the verification method id (DID + multibase
  // fragment) and the Ed25519Signature2020 type.
  EXPECT_EQ(result->proof_method, key->did + "#" + key->did.substr(8));
  EXPECT_EQ(result->proof_type, "Ed25519Signature2020");
  EXPECT_TRUE(provider.Verify(result->author, result->data_json,
                                result->timestamp, result->proof_sig));
  EXPECT_FALSE(provider.Verify(result->author, R"({"message":"tampered"})",
                                 result->timestamp, result->proof_sig));
}

TEST(DID_SignLockedKey) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Lockable");
  EXPECT_TRUE(provider.Lock(key->id));
  EXPECT_FALSE(provider.Sign(key->id, R"({"k":"v"})").has_value());
  EXPECT_TRUE(provider.Unlock(key->id));
  EXPECT_TRUE(provider.Sign(key->id, R"({"k":"v"})").has_value());
}

TEST(DID_ResolveDID) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Resolvable");
  auto doc = provider.ResolveDID(key->did);
  EXPECT_FALSE(doc.empty());
  EXPECT_NE(doc.find(key->did), std::string::npos);
  EXPECT_NE(doc.find("Ed25519VerificationKey2020"), std::string::npos);
  EXPECT_NE(doc.find("authentication"), std::string::npos);
  EXPECT_NE(doc.find("assertionMethod"), std::string::npos);
  EXPECT_NE(doc.find("capabilityDelegation"), std::string::npos);
  EXPECT_NE(doc.find("capabilityInvocation"), std::string::npos);
}

TEST(DID_ResolveInvalidDID) {
  DIDKeyProvider provider;
  EXPECT_TRUE(provider.ResolveDID("did:web:example.com").empty());
}

TEST(DID_MultipleKeys_UniqueDIDs) {
  DIDKeyProvider provider;
  auto k1 = provider.CreateKey("Key1");
  auto k2 = provider.CreateKey("Key2");
  EXPECT_NE(k1->did, k2->did);
  EXPECT_NE(k1->id, k2->id);
}

TEST(DID_CrossKeyVerification) {
  DIDKeyProvider provider;
  auto k1 = provider.CreateKey("Key1");
  auto k2 = provider.CreateKey("Key2");

  auto signed1 = provider.Sign(k1->id, R"({"k":"v"})");
  EXPECT_TRUE(signed1.has_value());

  // Verify with k1's DID should work
  EXPECT_TRUE(provider.Verify(signed1->author, signed1->data_json,
                                signed1->timestamp, signed1->proof_sig));

  // Cannot verify with k2's DID
  EXPECT_FALSE(provider.Verify(k2->did, signed1->data_json,
                                 signed1->timestamp, signed1->proof_sig));
}

TEST(DID_InvalidSignatureRejection) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Test");
  auto result = provider.Sign(key->id, R"({"k":"v"})");
  EXPECT_TRUE(result.has_value());

  // Corrupt a signature byte while keeping the multibase 'z' prefix and a
  // decodable base58 body, so this exercises Ed25519 rejection (not a decode
  // failure). Flip a character in the middle to a different alphabet member.
  std::string bad_sig = result->proof_sig;
  size_t mid = bad_sig.size() / 2;
  bad_sig[mid] = (bad_sig[mid] == 'A') ? 'B' : 'A';
  EXPECT_FALSE(provider.Verify(result->author, result->data_json,
                                 result->timestamp, bad_sig));

  // Wrong timestamp
  EXPECT_FALSE(provider.Verify(result->author, result->data_json,
                                 "1999-01-01T00:00:00Z", result->proof_sig));
}

// ============================================================
// Spec 01 — did:key codec, JCS canonicalisation, signing primitives
// ============================================================

// RFC 8032 §7.1 TEST 1 Ed25519 public key and its canonical did:key,
// computed independently (multicodec 0xed01 + base58btc).
static const char* kRFC8032Test1PubHex =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static const char* kRFC8032Test1Did =
    "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

TEST(Codec_Base58KnownVectors) {
  auto enc = [](std::vector<uint8_t> b) { return did_key::Base58BtcEncode(b); };
  EXPECT_EQ(enc(std::vector<uint8_t>{'H','e','l','l','o',' ','W','o','r','l','d','!'}),
            std::string("2NEpo7TZRRrLZSi2U"));
  EXPECT_EQ(enc(std::vector<uint8_t>{0x00, 0x00, 0x61}), std::string("112g"));
  EXPECT_EQ(enc(DIDKeyProvider::HexDecode("deadbeef")), std::string("6h8cQN"));
  EXPECT_EQ(enc(std::vector<uint8_t>{}), std::string(""));
}

TEST(Codec_Base58RoundTrip) {
  std::vector<std::vector<uint8_t>> cases = {
      {}, {0x00}, {0x00, 0x00, 0xff}, {0x01, 0x02, 0x03},
      DIDKeyProvider::HexDecode(kRFC8032Test1PubHex)};
  for (const auto& c : cases) {
    auto dec = did_key::Base58BtcDecode(did_key::Base58BtcEncode(c));
    EXPECT_TRUE(dec.has_value());
    EXPECT_TRUE(*dec == c);
  }
  // Invalid alphabet character (0, O, I, l are excluded).
  EXPECT_FALSE(did_key::Base58BtcDecode("0OIl").has_value());
}

TEST(Codec_DidKeyRFC8032Vector) {
  auto pub = DIDKeyProvider::HexDecode(kRFC8032Test1PubHex);
  EXPECT_EQ(pub.size(), 32u);
  auto did = did_key::DeriveDidKeyEd25519(pub);
  EXPECT_TRUE(did.has_value());
  EXPECT_EQ(*did, std::string(kRFC8032Test1Did));
  // Parse back to the exact public key.
  auto parsed = did_key::ParseDidKeyEd25519(*did);
  EXPECT_TRUE(parsed.has_value());
  EXPECT_TRUE(*parsed == pub);
}

TEST(Codec_DidKeyPrefixInvariant) {
  // Every Ed25519 did:key begins "did:key:z6Mk" (the 0xed01 multicodec).
  DIDKeyProvider provider;
  for (int i = 0; i < 8; ++i) {
    auto key = provider.CreateKey("k");
    EXPECT_EQ(key->did.substr(0, 12), "did:key:z6Mk");
    auto parsed = did_key::ParseDidKeyEd25519(key->did);
    EXPECT_TRUE(parsed.has_value());
    EXPECT_TRUE(*parsed == key->public_key);
  }
}

TEST(Codec_DidKeyRejectsMalformed) {
  EXPECT_FALSE(did_key::ParseDidKeyEd25519("did:web:example.com").has_value());
  EXPECT_FALSE(did_key::ParseDidKeyEd25519("did:key:zzzz").has_value());
  EXPECT_FALSE(did_key::ParseDidKeyEd25519("").has_value());
  // Wrong multicodec: base58btc of 0x00 0x01 || 32 zero bytes is NOT Ed25519.
  std::vector<uint8_t> wrong(2 + 32, 0);
  wrong[0] = 0x12;  // e.g. secp/other codec low byte
  wrong[1] = 0x00;
  std::string bad = "did:key:z" + did_key::Base58BtcEncode(wrong);
  EXPECT_FALSE(did_key::ParseDidKeyEd25519(bad).has_value());
  // Wrong length payload (33 bytes after prefix).
  std::vector<uint8_t> short_pl = {0xed, 0x01, 0x00};
  std::string short_did = "did:key:z" + did_key::Base58BtcEncode(short_pl);
  EXPECT_FALSE(did_key::ParseDidKeyEd25519(short_did).has_value());
}

TEST(Codec_DidKeyParsesFragment) {
  auto pub = DIDKeyProvider::HexDecode(kRFC8032Test1PubHex);
  std::string mb = *did_key::Ed25519PublicKeyMultibase(pub);
  std::string vm = std::string(kRFC8032Test1Did) + "#" + mb;
  auto parsed = did_key::ParseDidKeyEd25519(vm);
  EXPECT_TRUE(parsed.has_value());
  EXPECT_TRUE(*parsed == pub);
}

TEST(Codec_MultibaseDecode) {
  std::vector<uint8_t> data = DIDKeyProvider::HexDecode("00deadbeef");
  // base58btc round-trip through multibase.
  auto z = did_key::MultibaseEncode(data);
  EXPECT_EQ(z[0], 'z');
  auto back = did_key::MultibaseDecode(z);
  EXPECT_TRUE(back.has_value());
  EXPECT_TRUE(*back == data);
  // base16 'f' and base64url 'u' forms of 0xdeadbeef.
  auto f = did_key::MultibaseDecode("fdeadbeef");
  EXPECT_TRUE(f.has_value());
  EXPECT_TRUE((*f == std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}));
  auto u = did_key::MultibaseDecode("u3q2-7w");  // base64url of deadbeef
  EXPECT_TRUE(u.has_value());
  EXPECT_TRUE((*u == std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}));
  // Unknown multibase prefix rejected.
  EXPECT_FALSE(did_key::MultibaseDecode("Xabc").has_value());
}

TEST(JCS_Number_ECMAScript) {
  auto n = [](double d) { return jcs::SerializeNumber(d); };
  EXPECT_EQ(n(0.0), std::string("0"));
  EXPECT_EQ(n(-0.0), std::string("0"));
  EXPECT_EQ(n(1.0), std::string("1"));
  EXPECT_EQ(n(-1.0), std::string("-1"));
  EXPECT_EQ(n(2.0), std::string("2"));
  EXPECT_EQ(n(100.0), std::string("100"));
  EXPECT_EQ(n(0.5), std::string("0.5"));
  EXPECT_EQ(n(1.5), std::string("1.5"));
  EXPECT_EQ(n(-1.5), std::string("-1.5"));
  EXPECT_EQ(n(0.001), std::string("0.001"));
  EXPECT_EQ(n(1e-6), std::string("0.000001"));
  EXPECT_EQ(n(1e-7), std::string("1e-7"));
  EXPECT_EQ(n(1e21), std::string("1e+21"));
  EXPECT_EQ(n(1e20), std::string("100000000000000000000"));
  EXPECT_EQ(n(333333333.33333329), std::string("333333333.3333333"));
}

TEST(JCS_SortsKeysAndStripsWhitespace) {
  auto c = jcs::Canonicalize(R"(  { "b" : 1 , "a" : 2 } )");
  EXPECT_TRUE(c.has_value());
  EXPECT_EQ(*c, std::string(R"({"a":2,"b":1})"));
}

TEST(JCS_NestedAndArrays) {
  auto c = jcs::Canonicalize(R"({"z":[3,2,1],"a":{"y":1,"x":2}})");
  EXPECT_TRUE(c.has_value());
  // Object keys sort; array order preserved.
  EXPECT_EQ(*c, std::string(R"({"a":{"x":2,"y":1},"z":[3,2,1]})"));
}

TEST(JCS_NumbersNormalised) {
  auto c = jcs::Canonicalize(R"({"a":1.0,"b":1.5e3,"c":1e-7})");
  EXPECT_TRUE(c.has_value());
  EXPECT_EQ(*c, std::string(R"({"a":1,"b":1500,"c":1e-7})"));
}

TEST(JCS_StringEscaping) {
  // Control chars use short escapes / \u00XX; quote and backslash escaped;
  // forward slash NOT escaped; UTF-8 passed through unescaped.
  auto c = jcs::Canonicalize("{\"s\":\"a\\\"b\\\\c\\n\\t/\\u0001\"}");
  EXPECT_TRUE(c.has_value());
  EXPECT_EQ(*c, std::string("{\"s\":\"a\\\"b\\\\c\\n\\t/\\u0001\"}"));
}

TEST(JCS_UnicodePassthroughAndKeyOrder) {
  // Non-ASCII characters are emitted as UTF-8, not \u-escaped.
  auto c = jcs::Canonicalize("{\"\xC3\xA9\":1,\"a\":2}");
  EXPECT_TRUE(c.has_value());
  // 'a' (U+0061) sorts before 'é' (U+00E9) by UTF-16 code unit.
  EXPECT_EQ(*c, std::string("{\"a\":2,\"\xC3\xA9\":1}"));
}

TEST(JCS_RejectsInvalid) {
  EXPECT_FALSE(jcs::Canonicalize("not json").has_value());
  EXPECT_FALSE(jcs::Canonicalize("{\"a\":}").has_value());
  EXPECT_FALSE(jcs::Canonicalize("{\"a\":1,}").has_value());
  EXPECT_FALSE(jcs::Canonicalize("{\"a\":1} trailing").has_value());
  EXPECT_FALSE(jcs::Canonicalize("{\"a\":01}").has_value());  // leading zero
  EXPECT_FALSE(jcs::Canonicalize("").has_value());
}

TEST(DID_SignUsesJCS_OrderIndependent) {
  // Two JSON encodings of the same logical object must verify against either
  // encoding, because sign()/verify() canonicalise with JCS first.
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Signer");
  auto result = provider.Sign(key->id, R"({"b":2,"a":1})");
  EXPECT_TRUE(result.has_value());
  // Verify with a differently-ordered but equivalent encoding.
  EXPECT_TRUE(provider.Verify(result->author, R"({"a":1,"b":2})",
                              result->timestamp, result->proof_sig));
  // Signature is multibase base58btc ('z' prefix).
  EXPECT_EQ(result->proof_sig[0], 'z');
}

TEST(DID_ResolveDID_ContentsAndTrustLevel) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Resolvable");
  auto doc = provider.ResolveDID(key->did);
  EXPECT_NE(doc.find("\"trustLevel\": \"local\""), std::string::npos);
  EXPECT_NE(doc.find("publicKeyMultibase"), std::string::npos);
  // publicKeyMultibase equals the DID's own z-suffix.
  EXPECT_NE(doc.find(key->did.substr(8)), std::string::npos);
}

TEST(DID_SignRaw_VerbatimBytes) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("RawSigner");
  std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F};
  auto sig = provider.SignRaw(key->id, payload);
  EXPECT_TRUE(sig.has_value());
  EXPECT_EQ(sig->size(), 64u);
  // Signature is over the raw bytes (no hashing/framing): verify directly.
  EXPECT_EQ(ed25519_verify(sig->data(), payload.data(), payload.size(),
                           key->public_key.data()),
            1);
  // A different payload must not verify against this signature.
  std::vector<uint8_t> other = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7E};
  EXPECT_EQ(ed25519_verify(sig->data(), other.data(), other.size(),
                           key->public_key.data()),
            0);
}

TEST(DID_SignRaw_LockedRejected) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("RawSigner");
  EXPECT_TRUE(provider.Lock(key->id));
  EXPECT_FALSE(provider.SignRaw(key->id, {0x01}).has_value());
  EXPECT_TRUE(provider.Unlock(key->id));
  EXPECT_TRUE(provider.SignRaw(key->id, {0x01}).has_value());
}

TEST(DID_SignCapability) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Delegator");
  auto zcap = provider.SignCapability(
      key->id,
      R"({"parentCapability":"urn:root","delegatee":"did:key:z6MkX","actions":["createLink"]})");
  EXPECT_TRUE(zcap.has_value());
  EXPECT_EQ(zcap->author, key->did);
  EXPECT_TRUE(provider.Verify(zcap->author, zcap->data_json, zcap->timestamp,
                              zcap->proof_sig));
  // Non-object JSON is rejected at the identity layer.
  EXPECT_FALSE(provider.SignCapability(key->id, "[1,2,3]").has_value());
  EXPECT_FALSE(provider.SignCapability(key->id, "5").has_value());
}

// ============================================================
// Main
// ============================================================

int main(int argc, char** argv) {
  std::cout << "Living Web — Test Suite\n";
  std::cout << "=======================\n\n";

  for (auto& entry : test_registry()) {
    tests_run++;
    std::cout << "  [RUN ] " << entry.name << std::flush;
    try {
      entry.fn();
      tests_passed++;
      std::cout << " [PASS]\n";
    } catch (const std::exception& e) {
      tests_failed++;
      failures.push_back(entry.name);
      std::cout << " [FAIL]\n";
    }
  }

  std::cout << "\n=======================\n";
  std::cout << "Tests run: " << tests_run
            << " | Passed: " << tests_passed
            << " | Failed: " << tests_failed << "\n";

  if (!failures.empty()) {
    std::cout << "\nFailed tests:\n";
    for (const auto& f : failures)
      std::cout << "  - " << f << "\n";
  }

  return tests_failed > 0 ? 1 : 0;
}
