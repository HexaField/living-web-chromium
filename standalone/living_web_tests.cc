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

// Spec 02 — Personal Linked Data Graphs.
#include "graph_provider.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph/oxigraph_store.h"
#include "content/browser/graph/sparql_results.h"

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
// Spec 02 — Personal Linked Data Graphs
// ============================================================

namespace {

// The IRI of the canonicalised empty triple set: graph:// + SHA-256("").
constexpr char kEmptyGraphIri[] =
    "graph://e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

Triple MakeLit(const std::string& s,
               const std::string& p,
               const std::string& lex) {
  Triple t;
  t.subject = s;
  t.predicate = p;
  LiteralValue lv;
  lv.lexical = lex;
  t.object = ObjectTerm::Literal(lv);
  return t;
}

Triple MakeIri(const std::string& s,
               const std::string& p,
               const std::string& iri) {
  Triple t;
  t.subject = s;
  t.predicate = p;
  t.object = ObjectTerm::Iri(iri);
  return t;
}

std::string HexOf(const std::string& raw) {
  return DIDKeyProvider::HexEncode(
      std::vector<uint8_t>(raw.begin(), raw.end()));
}

}  // namespace

// ---- content hash foundation (§5.2) ----

TEST(Graph_EmptyIriIsWellKnown) {
  std::string iri, err;
  EXPECT_TRUE(OxigraphStore::GraphIri("", &iri, &err));
  EXPECT_EQ(iri, kEmptyGraphIri);
}

TEST(Graph_ContentHashIsDeterministic) {
  const std::string doc = "<urn:s> <urn:p> \"v\" .\n";
  std::string a, b, err;
  EXPECT_TRUE(OxigraphStore::GraphIri(doc, &a, &err));
  EXPECT_TRUE(OxigraphStore::GraphIri(doc, &b, &err));
  EXPECT_EQ(a, b);
  EXPECT_NE(a, std::string(kEmptyGraphIri));
}

// ---- create (§4.1) ----

TEST(Graph_CreateIsEmptyLocalNoDid) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create("My Calendar");
  EXPECT_EQ(g->id().substr(0, 10), "urn:graph:");
  EXPECT_FALSE(g->did().has_value());
  EXPECT_TRUE(g->trust_level() == GraphTrustLevel::kLocal);
  EXPECT_TRUE(g->display_name().has_value());
  EXPECT_EQ(*g->display_name(), "My Calendar");
  std::string iri;
  EXPECT_TRUE(g->GetIri(&iri));
  EXPECT_EQ(iri, kEmptyGraphIri);
}

// ---- addTriple (§4.2) ----

TEST(Graph_AddTripleAdvancesIriAndFires) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  std::string iri0;
  EXPECT_TRUE(g->GetIri(&iri0));

  int fired = 0;
  g->set_on_triple_added([&](const Triple&) { fired++; });

  Triple out;
  EXPECT_TRUE(g->AddTriple(
      MakeLit("urn:event:1", "https://schema.org/name", "Coffee with Alice"),
      &out));
  EXPECT_EQ(fired, 1);
  EXPECT_EQ(out.subject, "urn:event:1");

  std::string iri1;
  EXPECT_TRUE(g->GetIri(&iri1));
  EXPECT_NE(iri0, iri1);
}

TEST(Graph_AddTripleRequiresActiveCredential) {
  DIDKeyProvider provider;  // no key created -> no active credential
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_FALSE(g->AddTriple(MakeLit("urn:s", "urn:p", "v")));
  EXPECT_EQ(g->last_error(), "InvalidStateError");
}

TEST(Graph_QueryTriplesReturnsDataNotReifiers) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:event:1", "urn:p:name", "Alice")));

  std::vector<Triple> got;
  TripleQuery q;
  q.subject = std::string("urn:event:1");
  EXPECT_TRUE(g->QueryTriples(q, &got));
  EXPECT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0].subject, "urn:event:1");
  EXPECT_EQ(got[0].predicate, "urn:p:name");
  EXPECT_TRUE(got[0].object.is_literal());
  EXPECT_EQ(got[0].object.literal->lexical, "Alice");
}

TEST(Graph_QueryTriplesOrderingAndFilters) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  // Equal timestamps -> tie broken by subject ascending.
  EXPECT_TRUE(g->AddTriples({MakeLit("urn:c", "urn:p", "3"),
                             MakeLit("urn:a", "urn:p", "1"),
                             MakeLit("urn:b", "urn:p", "2")}));

  std::vector<Triple> got;
  EXPECT_TRUE(g->QueryTriples(TripleQuery{}, &got));
  EXPECT_EQ(got.size(), 3u);
  EXPECT_EQ(got[0].subject, "urn:a");
  EXPECT_EQ(got[1].subject, "urn:b");
  EXPECT_EQ(got[2].subject, "urn:c");

  // author filter: our key matches all; a foreign DID matches none.
  TripleQuery qa;
  qa.author = key->did;
  EXPECT_TRUE(g->QueryTriples(qa, &got));
  EXPECT_EQ(got.size(), 3u);
  TripleQuery qf;
  qf.author = std::string("did:key:z6MkFOREIGN");
  EXPECT_TRUE(g->QueryTriples(qf, &got));
  EXPECT_EQ(got.size(), 0u);

  // date window.
  TripleQuery qfrom;
  qfrom.from_date = std::string("2000-01-01T00:00:00Z");
  EXPECT_TRUE(g->QueryTriples(qfrom, &got));
  EXPECT_EQ(got.size(), 3u);
  TripleQuery quntil;
  quntil.until_date = std::string("2000-01-01T00:00:00Z");
  EXPECT_TRUE(g->QueryTriples(quntil, &got));
  EXPECT_EQ(got.size(), 0u);

  // limit / offset.
  TripleQuery qlim;
  qlim.limit = 2u;
  EXPECT_TRUE(g->QueryTriples(qlim, &got));
  EXPECT_EQ(got.size(), 2u);
  TripleQuery qoff;
  qoff.offset = 1u;
  qoff.limit = 2u;
  EXPECT_TRUE(g->QueryTriples(qoff, &got));
  EXPECT_EQ(got.size(), 2u);
  EXPECT_EQ(got[0].subject, "urn:b");
}

// ---- provenance (§4.2, §3.2.1) ----

TEST(Graph_ProvenanceSignatureVerifies) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  Triple t = MakeLit("urn:event:1", "urn:p:name", "Alice");
  EXPECT_TRUE(g->AddTriple(t));

  std::vector<Reifier> reifiers;
  EXPECT_TRUE(g->Provenance(t, &reifiers));
  EXPECT_EQ(reifiers.size(), 1u);
  const Reifier& r = reifiers[0];
  EXPECT_EQ(r.author, key->did);
  EXPECT_EQ(r.method, key->did + "#" +
                          *did_key::Ed25519PublicKeyMultibase(key->public_key));

  // Recompute the §3.2.1 payload and verify the stored signature end-to-end.
  // graphIdentifier is the graph id (no DID attached).
  std::string preimage = BuildSignaturePreimage(t, r.timestamp, g->id());
  std::string payload = crypto::SHA256HashString(preimage);
  auto pub = did_key::ParseDidKeyEd25519(r.author);
  auto sig = did_key::MultibaseDecode(r.signature);
  EXPECT_TRUE(pub.has_value());
  EXPECT_TRUE(sig.has_value());
  EXPECT_EQ(sig->size(), 64u);
  EXPECT_EQ(ed25519_verify(sig->data(),
                           reinterpret_cast<const uint8_t*>(payload.data()),
                           payload.size(), pub->data()),
            1);
}

// ---- addTriples batch (§4.2) ----

TEST(Graph_AddTriplesBatchAtomicOneIriAdvanceEventsPerTriple) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  std::string iri0;
  EXPECT_TRUE(g->GetIri(&iri0));

  int fired = 0;
  g->set_on_triple_added([&](const Triple&) { fired++; });
  EXPECT_TRUE(g->AddTriples({MakeLit("urn:a", "urn:p", "1"),
                             MakeLit("urn:b", "urn:p", "2")}));
  EXPECT_EQ(fired, 2);

  std::vector<Triple> got;
  EXPECT_TRUE(g->QueryTriples(TripleQuery{}, &got));
  EXPECT_EQ(got.size(), 2u);
  std::string iri1;
  EXPECT_TRUE(g->GetIri(&iri1));
  EXPECT_NE(iri0, iri1);
}

// ---- removeTriple (§4.2) ----

TEST(Graph_RemoveTripleDropsDataAndReifiers) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  Triple t = MakeLit("urn:event:1", "urn:p:name", "Alice");
  EXPECT_TRUE(g->AddTriple(t));

  int removed_events = 0;
  g->set_on_triple_removed([&](const Triple&) { removed_events++; });

  bool removed = false;
  EXPECT_TRUE(g->RemoveTriple(t, &removed));
  EXPECT_TRUE(removed);
  EXPECT_EQ(removed_events, 1);

  std::vector<Triple> got;
  EXPECT_TRUE(g->QueryTriples(TripleQuery{}, &got));
  EXPECT_EQ(got.size(), 0u);
  // All triples gone -> IRI returns to the empty-graph IRI.
  std::string iri;
  EXPECT_TRUE(g->GetIri(&iri));
  EXPECT_EQ(iri, kEmptyGraphIri);

  // Removing again matches nothing.
  removed = true;
  EXPECT_TRUE(g->RemoveTriple(t, &removed));
  EXPECT_FALSE(removed);
}

// ---- snapshot ordering (§4.2) ----

TEST(Graph_SnapshotOrdersByTimestampAscending) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriples({MakeLit("urn:b", "urn:p", "2"),
                             MakeLit("urn:a", "urn:p", "1")}));
  std::vector<Triple> got;
  EXPECT_TRUE(g->Snapshot(&got));
  EXPECT_EQ(got.size(), 2u);
  // Equal ts -> subject ascending.
  EXPECT_EQ(got[0].subject, "urn:a");
  EXPECT_EQ(got[1].subject, "urn:b");
}

// ---- getAsSnapshot (§5.4) ----

TEST(Graph_SnapshotCanonicalInvariantHolds) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:event:1", "urn:p:name", "Alice")));

  GraphSnapshot snap;
  EXPECT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));
  // §5.3.1 invariant: graphIri == "graph://" + hex(SHA-256(data)).
  EXPECT_EQ(snap.graph_iri,
            "graph://" + HexOf(crypto::SHA256HashString(snap.data)));
  EXPECT_EQ(snap.proofs.size(), 1u);
  EXPECT_EQ(snap.proofs[0].role, "agent");
  std::string iri;
  EXPECT_TRUE(g->GetIri(&iri));
  EXPECT_EQ(snap.graph_iri, iri);
}

TEST(Graph_SnapshotSignByGraphRequiresMatchingDid) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:s", "urn:p", "v")));

  GraphSnapshot snap;
  // No DID attached -> signBy "graph" is NotAllowedError.
  EXPECT_FALSE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                                GraphSignBy::kGraph, &snap));
  EXPECT_EQ(g->last_error(), "NotAllowedError");
  EXPECT_FALSE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                                GraphSignBy::kBoth, &snap));
  EXPECT_EQ(g->last_error(), "NotAllowedError");
}

TEST(Graph_SnapshotJsonLdIsNotSupported) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  GraphSnapshot snap;
  EXPECT_FALSE(g->GetAsSnapshot(SnapshotFormat::kJsonLd, GraphSignBy::kAgent,
                                &snap));
  EXPECT_EQ(g->last_error(), "NotSupportedError");
}

// §5.3.4: the advertised-format set is discoverable and drives NotSupportedError
// on both producer and consumer. nquads-canonical / nquads / turtle REQUIRED;
// jsonld OPTIONAL and not advertised here.
TEST(Graph_SupportedSnapshotFormatsAdvertised) {
  auto formats = SupportedSnapshotFormats();
  EXPECT_EQ(formats.size(), 3u);
  EXPECT_EQ(static_cast<int>(formats[0]),
            static_cast<int>(SnapshotFormat::kNQuadsCanonical));
  EXPECT_EQ(static_cast<int>(formats[1]),
            static_cast<int>(SnapshotFormat::kNQuads));
  EXPECT_EQ(static_cast<int>(formats[2]),
            static_cast<int>(SnapshotFormat::kTurtle));
  // Tokens match the IDL enum values.
  EXPECT_EQ(std::string(SnapshotFormatToken(formats[0])), "nquads-canonical");
  EXPECT_EQ(std::string(SnapshotFormatToken(formats[1])), "nquads");
  EXPECT_EQ(std::string(SnapshotFormatToken(formats[2])), "turtle");
  // Membership predicate.
  EXPECT_TRUE(IsSnapshotFormatSupported(SnapshotFormat::kNQuadsCanonical));
  EXPECT_TRUE(IsSnapshotFormatSupported(SnapshotFormat::kNQuads));
  EXPECT_TRUE(IsSnapshotFormatSupported(SnapshotFormat::kTurtle));
  EXPECT_FALSE(IsSnapshotFormatSupported(SnapshotFormat::kJsonLd));
  // The GraphManager static mirror agrees with the free function.
  EXPECT_EQ(GraphManager::supportedSnapshotFormats().size(), formats.size());

  // Consumer side: a snapshot tagged jsonld is rejected before proof/parse.
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:event:1", "urn:p:name", "Alice")));
  GraphSnapshot snap;
  EXPECT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));
  snap.format = SnapshotFormat::kJsonLd;  // tag an otherwise-valid snapshot
  std::string err;
  auto m = mgr.FromSnapshot(snap, &err);
  EXPECT_TRUE(m == nullptr);
  EXPECT_EQ(err, "NotSupportedError");
}

// ---- fromSnapshot (§5.5) ----

TEST(Graph_FromSnapshotRoundTripsCanonical) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:event:1", "urn:p:name", "Alice")));
  std::string src_iri;
  EXPECT_TRUE(g->GetIri(&src_iri));

  GraphSnapshot snap;
  EXPECT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));

  std::string err;
  auto m = mgr.FromSnapshot(snap, &err);
  EXPECT_TRUE(m != nullptr);
  EXPECT_TRUE(m->trust_level() == GraphTrustLevel::kExternal);
  std::string m_iri;
  EXPECT_TRUE(m->GetIri(&m_iri));
  EXPECT_EQ(m_iri, src_iri);

  // The materialised graph exposes the same data triple.
  std::vector<Triple> got;
  EXPECT_TRUE(m->QueryTriples(TripleQuery{}, &got));
  EXPECT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0].object.literal->lexical, "Alice");
}

TEST(Graph_FromSnapshotTurtleRoundTrips) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:event:1", "urn:p:name", "Alice")));
  std::string src_iri;
  EXPECT_TRUE(g->GetIri(&src_iri));

  GraphSnapshot snap;
  EXPECT_TRUE(g->GetAsSnapshot(SnapshotFormat::kTurtle, GraphSignBy::kAgent,
                               &snap));
  EXPECT_EQ(static_cast<int>(snap.format),
            static_cast<int>(SnapshotFormat::kTurtle));

  std::string err;
  auto m = mgr.FromSnapshot(snap, &err);
  EXPECT_TRUE(m != nullptr);
  std::string m_iri;
  EXPECT_TRUE(m->GetIri(&m_iri));
  EXPECT_EQ(m_iri, src_iri);
}

TEST(Graph_FromSnapshotRejectsEmptyProofs) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:s", "urn:p", "v")));
  GraphSnapshot snap;
  EXPECT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));
  snap.proofs.clear();
  std::string err;
  EXPECT_TRUE(mgr.FromSnapshot(snap, &err) == nullptr);
  EXPECT_EQ(err, "DataError");
}

TEST(Graph_FromSnapshotRejectsTamperedData) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:s", "urn:p", "v")));
  GraphSnapshot snap;
  EXPECT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));
  // Add a triple the claimed IRI does not cover -> hash check fails.
  snap.data += "<urn:x> <urn:y> <urn:z> .\n";
  std::string err;
  EXPECT_TRUE(mgr.FromSnapshot(snap, &err) == nullptr);
  EXPECT_EQ(err, "DataError");
}

TEST(Graph_FromSnapshotAttachesDidAndEnablesGraphSigning) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:s", "urn:p", "v")));
  GraphSnapshot snap;
  EXPECT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));
  // Attach a graph DID (normally populated by another specification). The proof
  // covers graphIri||timestamp, not graphDid, so it still verifies.
  snap.graph_did = key->did;

  std::string err;
  auto m = mgr.FromSnapshot(snap, &err);
  EXPECT_TRUE(m != nullptr);
  EXPECT_TRUE(m->did().has_value());
  EXPECT_EQ(*m->did(), key->did);

  // With graph.did == active.did, signBy "graph" now succeeds.
  GraphSnapshot gsnap;
  EXPECT_TRUE(m->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                              GraphSignBy::kGraph, &gsnap));
  EXPECT_EQ(gsnap.proofs.size(), 1u);
  EXPECT_EQ(gsnap.proofs[0].role, "graph");
  EXPECT_TRUE(gsnap.graph_did.has_value());
}

// ---- dissolve (§4.3) ----

TEST(Graph_DissolveIsTerminalAndIdempotent) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto g = mgr.Create();
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:s", "urn:p", "v")));
  EXPECT_TRUE(g->Dissolve());
  EXPECT_TRUE(g->dissolved());

  // Every other operation now rejects with InvalidStateError.
  EXPECT_FALSE(g->AddTriple(MakeLit("urn:s2", "urn:p", "v")));
  EXPECT_EQ(g->last_error(), "InvalidStateError");
  std::vector<Triple> got;
  EXPECT_FALSE(g->QueryTriples(TripleQuery{}, &got));
  EXPECT_EQ(g->last_error(), "InvalidStateError");
  std::string iri;
  EXPECT_FALSE(g->GetIri(&iri));

  // dissolve() itself is idempotent.
  EXPECT_TRUE(g->Dissolve());
}

// ---- holonic SPARQL (§7) ----

TEST(Graph_HolonicSparqlAcrossTwoGraphs) {
  DIDKeyProvider provider;
  provider.CreateKey("A");
  GraphManager mgr(&provider);
  auto community = mgr.Create("Acme");
  auto channel = mgr.Create("#general");

  // Populate the channel first, then reference its *current* IRI so the named
  // graph key matches at query time.
  EXPECT_TRUE(channel->AddTriple(MakeLit("urn:msg:1", "urn:p:body", "hello")));
  std::string ch_iri;
  EXPECT_TRUE(channel->GetIri(&ch_iri));
  EXPECT_TRUE(community->AddTriple(
      MakeIri("urn:community:acme", "urn:p:hasChannel", ch_iri)));

  std::vector<Graph*> named{channel.get()};
  SparqlResult res = community->QuerySparql(
      "SELECT ?msg ?body WHERE {\n"
      "  <urn:community:acme> <urn:p:hasChannel> ?ch .\n"
      "  GRAPH ?ch { ?msg <urn:p:body> ?body . }\n"
      "}",
      named);
  EXPECT_TRUE(res.ok);
  SparqlSelect sel;
  std::string err;
  EXPECT_TRUE(DecodeSparqlSelect(res.payload, &sel, &err));
  EXPECT_EQ(sel.solutions.size(), 1u);
  const SparqlTerm* body = sel.solutions[0].Get("body");
  EXPECT_TRUE(body != nullptr);
  EXPECT_EQ(body->value, "hello");
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
