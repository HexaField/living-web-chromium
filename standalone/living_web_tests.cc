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

// Spec 03 — Decentralised Group Identity.
#include "group_provider.h"
#include "content/browser/did/did_graph.h"

// Spec 04 — Graph Capability Framework.
#include "capability_provider.h"
#include "content/browser/governance/zcap.h"

// Spec 05 — Graph Synchronisation Protocol.
#include "sync_provider.h"
#include "content/browser/graph_sync/graph_diff.h"

// Spec 06 — Sync Module Architecture.
#include "module_runtime_provider.h"
#include "content/browser/module_runtime/module_capabilities.h"
#include "content/browser/module_runtime/module_manifest.h"

// Spec 07 — Dynamic Graph Shape Validation.
#include "shape_provider.h"
#include "content/browser/shapes/shape_definition.h"

// Spec 08 — Governance Constraint Vocabulary.
#include "constraint_vocabulary_provider.h"
#include "content/browser/governance/constraint_vocabulary.h"

#include <chrono>
#include <openssl/rand.h>

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
// Spec 03 — Decentralised Group Identity
// ============================================================

namespace {

// Create a provider with one human did:key active, plus a graph + group manager.
struct GroupFixture {
  DIDKeyProvider provider;
  GraphManager graphs{&provider};
  GroupManager groups{&provider, &graphs};
  GroupFixture() { provider.CreateKey("Human"); }
};

GroupCreationOptions DefaultGroupOptions() {
  GroupCreationOptions o;
  o.sync_module = "urn:sync:module:default";
  return o;
}

}  // namespace

// ---- did:graph codec (§4.1) ----

TEST(Group_DidGraphCodecRoundTrip) {
  std::vector<uint8_t> pk(32, 0x11);
  auto did = did_graph::DeriveDidGraphEd25519(pk);
  EXPECT_TRUE(did.has_value());
  EXPECT_EQ(did->substr(0, 12), "did:graph:z6");
  EXPECT_TRUE(did_graph::IsDidGraph(*did));
  EXPECT_FALSE(did_graph::IsDidGraph("did:key:z6MkFoo"));
  auto pk2 = did_graph::ParseDidGraphEd25519(*did);
  EXPECT_TRUE(pk2.has_value());
  EXPECT_TRUE(*pk2 == pk);
}

// ---- createGroup: binding + seed + resolution (§4.2, §4.7) ----

TEST(Group_CreateBindsDidGraphAndSeed) {
  GroupFixture f;
  auto opts = DefaultGroupOptions();
  opts.display_name = "Book Club";
  opts.description = "We read books";
  auto group = f.groups.CreateGroup(opts);
  EXPECT_TRUE(group != nullptr);
  EXPECT_EQ(group->did().substr(0, 10), "did:graph:");
  EXPECT_TRUE(group->name().has_value());
  EXPECT_EQ(*group->name(), "Book Club");
  EXPECT_EQ(*group->description(), "We read books");
  EXPECT_TRUE(group->created().has_value());
  // The human's prior-active DID is recorded as creator (§4.2).
  EXPECT_TRUE(group->creator().has_value());
  EXPECT_EQ(group->creator()->substr(0, 8), "did:key:");

  DidDocument doc;
  EXPECT_TRUE(group->Resolve(&doc));
  EXPECT_EQ(doc.id, group->did());
  EXPECT_EQ(doc.trust_level, "local");
  EXPECT_FALSE(doc.deactivated);
  // Group-of-one: the creator key holds every section (§11).
  EXPECT_EQ(doc.verification_method.size(), 1u);
  EXPECT_EQ(doc.capability_invocation.size(), 1u);
  EXPECT_EQ(doc.capability_delegation.size(), 1u);
  EXPECT_EQ(doc.assertion_method.size(), 1u);
  EXPECT_EQ(doc.authentication.size(), 1u);

  auto sm = group_detail::FirstLiteralOf(group->graph(), group->did(),
                                         kGroupSyncModule);
  EXPECT_TRUE(sm.has_value());
  EXPECT_EQ(*sm, "urn:sync:module:default");
}

TEST(Group_CreateRequiresSyncModule) {
  GroupFixture f;
  GroupCreationOptions opts;  // no sync_module
  auto group = f.groups.CreateGroup(opts);
  EXPECT_TRUE(group == nullptr);
  EXPECT_EQ(f.groups.last_error(), "SyntaxError");
}

// ---- groupify: one-way promotion of an existing graph (§4.2) ----

TEST(Group_GroupifyExistingGraphOneWay) {
  GroupFixture f;
  auto g = f.graphs.Create("Existing");
  EXPECT_TRUE(g->AddTriple(MakeLit("urn:note:1", "urn:p:body", "hi")));

  GroupifyOptions opts;
  opts.sync_module = "urn:sync:module:default";
  auto group = f.groups.Groupify(g.get(), opts);
  EXPECT_TRUE(group != nullptr);
  EXPECT_TRUE(g->did().has_value());
  EXPECT_EQ(*g->did(), group->did());
  // Pre-existing content survives groupification.
  auto body = group_detail::FirstLiteralOf(g.get(), "urn:note:1", "urn:p:body");
  EXPECT_TRUE(body.has_value());
  EXPECT_EQ(*body, "hi");

  // Re-groupify is rejected — groupification is one-way (§4.2).
  auto again = f.groups.Groupify(g.get(), opts);
  EXPECT_TRUE(again == nullptr);
  EXPECT_EQ(f.groups.last_error(), "InvalidStateError");
}

// ---- delegate management (§5.4, §8.1.4) ----

TEST(Group_AddAndRemoveDelegate) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());

  auto member = f.provider.CreateKey("Member");  // a did:key holder
  auto vm = group_detail::MethodFromDelegateDid(group->did(), member->did);
  EXPECT_TRUE(vm.has_value());

  EXPECT_TRUE(group->AddDelegate(
      *vm, {DIDCapabilitySection::kCapabilityInvocation,
            DIDCapabilitySection::kAssertionMethod}));
  EXPECT_TRUE(group->IsSigner(member->did));
  EXPECT_TRUE(
      group->IsSigner(member->did, DIDCapabilitySection::kAssertionMethod));
  EXPECT_FALSE(
      group->IsSigner(member->did, DIDCapabilitySection::kCapabilityDelegation));

  DidDocument doc;
  group->Resolve(&doc);
  EXPECT_EQ(doc.verification_method.size(), 2u);

  EXPECT_TRUE(group->RemoveDelegate(vm->id));
  EXPECT_FALSE(group->IsSigner(member->did));
  group->Resolve(&doc);
  EXPECT_EQ(doc.verification_method.size(), 1u);
}

TEST(Group_GrantAndRevokeSection) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());
  auto member = f.provider.CreateKey("Member");
  auto vm = group_detail::MethodFromDelegateDid(group->did(), member->did);
  EXPECT_TRUE(group->AddDelegate(*vm,
                                 {DIDCapabilitySection::kCapabilityInvocation}));
  EXPECT_FALSE(
      group->IsSigner(member->did, DIDCapabilitySection::kAuthentication));
  EXPECT_TRUE(
      group->GrantSection(vm->id, DIDCapabilitySection::kAuthentication));
  EXPECT_TRUE(
      group->IsSigner(member->did, DIDCapabilitySection::kAuthentication));
  EXPECT_TRUE(
      group->RevokeSection(vm->id, DIDCapabilitySection::kAuthentication));
  EXPECT_FALSE(
      group->IsSigner(member->did, DIDCapabilitySection::kAuthentication));
}

// ---- brick-state guards (§5.4) ----

TEST(Group_RemoveSoleCapabilityDelegationBricks) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());
  DidDocument doc;
  group->Resolve(&doc);
  EXPECT_EQ(doc.capability_delegation.size(), 1u);
  const std::string sole = doc.capability_delegation[0];

  // Removing the only capabilityDelegation method would brick the group (§5.4).
  EXPECT_FALSE(group->RemoveSigner(sole));
  EXPECT_EQ(group->last_error(), "InvalidStateError");
  // Revoking its capabilityDelegation membership likewise bricks.
  EXPECT_FALSE(
      group->RevokeSection(sole, DIDCapabilitySection::kCapabilityDelegation));
  EXPECT_EQ(group->last_error(), "InvalidStateError");
}

// ---- authorship rules (§6.2, §5.4) ----

TEST(Group_WritesRequireDelegateAuthority) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());

  // Add a capabilityInvocation-only delegate, then act as it.
  auto member = f.provider.CreateKey("Member");
  auto vm = group_detail::MethodFromDelegateDid(group->did(), member->did);
  EXPECT_TRUE(group->AddDelegate(*vm,
                                 {DIDCapabilitySection::kCapabilityInvocation}));
  group->SetActingCredential(member->id);

  // Accepting participation demands capabilityDelegation authorship (§6.2).
  EXPECT_FALSE(group->Invite("urn:person:bob"));
  EXPECT_EQ(group->last_error(), "NotAllowedError");
  // Managing delegates demands capabilityDelegation (§5.4).
  EXPECT_FALSE(
      group->AddDelegate(*vm, {DIDCapabilitySection::kAuthentication}));
  EXPECT_EQ(group->last_error(), "NotAllowedError");
  // signGraph demands assertionMethod (§5.4).
  SignedContentResult sr;
  EXPECT_FALSE(group->SignGraph(group->did(), &sr));
  EXPECT_EQ(group->last_error(), "NotAllowedError");
}

// ---- participation lifecycle (§7.1, §8.1.1-8.1.3) ----

TEST(Group_ParticipationLifecycle) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());
  EXPECT_FALSE(group->HasParticipant("urn:person:alice"));
  EXPECT_TRUE(group->Invite("urn:person:alice"));
  EXPECT_TRUE(group->HasParticipant("urn:person:alice"));

  auto parts = group->Participants();
  EXPECT_EQ(parts.size(), 1u);
  EXPECT_EQ(parts[0].did, "urn:person:alice");
  EXPECT_FALSE(parts[0].is_group);
  EXPECT_FALSE(parts[0].joined_at.empty());

  EXPECT_TRUE(group->RevokeParticipation("urn:person:alice"));
  EXPECT_FALSE(group->HasParticipant("urn:person:alice"));
}

// ---- signGraph, group-of-one (§5.4, §11) ----

TEST(Group_SignGraphGroupOfOne) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());
  SignedContentResult sr;
  EXPECT_TRUE(group->SignGraph(group->did(), &sr));
  EXPECT_EQ(sr.author, group->did());
  EXPECT_FALSE(sr.proof_sig.empty());
  EXPECT_EQ(sr.proof_type, "Ed25519Signature2020");
  EXPECT_EQ(sr.proof_method.substr(0, group->did().size()), group->did());
}

// ---- nesting + transitive participation (§6.3, §8.1.3) ----

TEST(Group_NestedTransitiveParticipants) {
  GroupFixture f;
  auto parent = f.groups.CreateGroup(DefaultGroupOptions());
  auto child = f.groups.CreateGroup(DefaultGroupOptions());

  EXPECT_TRUE(child->Invite("urn:person:alice"));
  EXPECT_TRUE(parent->Invite(child->did()));  // a sub-group participates
  EXPECT_TRUE(parent->Invite("urn:person:bob"));

  EXPECT_EQ(parent->Participants().size(), 2u);

  auto trans = parent->TransitiveParticipants();
  EXPECT_EQ(trans.size(), 2u);  // alice (via child) + bob; child is not an individual
  bool has_alice = false, has_bob = false;
  for (auto& p : trans) {
    EXPECT_FALSE(p.is_group);
    if (p.did == "urn:person:alice") has_alice = true;
    if (p.did == "urn:person:bob") has_bob = true;
  }
  EXPECT_TRUE(has_alice);
  EXPECT_TRUE(has_bob);

  auto kids = parent->ChildGroups();
  EXPECT_EQ(kids.size(), 1u);
  EXPECT_EQ(kids[0]->did(), child->did());
}

TEST(Group_TransitiveParticipantsCycleSafe) {
  GroupFixture f;
  auto a = f.groups.CreateGroup(DefaultGroupOptions());
  auto b = f.groups.CreateGroup(DefaultGroupOptions());
  EXPECT_TRUE(a->Invite(b->did()));
  EXPECT_TRUE(b->Invite(a->did()));  // mutual participation forms a cycle
  EXPECT_TRUE(a->Invite("urn:person:solo"));

  auto trans = a->TransitiveParticipants();  // must terminate
  EXPECT_EQ(trans.size(), 1u);
  EXPECT_EQ(trans[0].did, "urn:person:solo");
}

// ---- forking (§4.8) ----

TEST(Group_ForkInheritsAndRelinks) {
  GroupFixture f;
  auto opts = DefaultGroupOptions();
  opts.display_name = "Origin";
  auto parent = f.groups.CreateGroup(opts);
  const std::string parent_did = parent->did();

  // Plain content the fork should inherit.
  EXPECT_TRUE(
      parent->graph()->AddTriple(MakeLit("urn:book:1", "urn:p:title", "Dune")));

  ForkOptions fo;
  fo.sync_module = "urn:sync:module:default";
  fo.display_name = "Fork";
  auto child = f.groups.ForkGroup(parent_did, fo);
  EXPECT_TRUE(child != nullptr);
  const std::string child_did = child->did();
  EXPECT_NE(child_did, parent_did);

  // Inherited content survives in the child.
  auto title =
      group_detail::FirstLiteralOf(child->graph(), "urn:book:1", "urn:p:title");
  EXPECT_TRUE(title.has_value());
  EXPECT_EQ(*title, "Dune");

  // The child records its lineage (§4.8 step 4).
  auto ff =
      group_detail::FirstIriOf(child->graph(), child_did, kGroupForkedFrom);
  EXPECT_TRUE(ff.has_value());
  EXPECT_EQ(*ff, parent_did);
  auto fr = group_detail::FirstLiteralOf(child->graph(), child_did,
                                         kGroupForkedAtRevision);
  EXPECT_TRUE(fr.has_value());

  // The parent identity is stripped from the child (§4.8 step 3).
  DidDocument stale;
  group_detail::ProjectDidDocument(child->graph(), parent_did, &stale);
  EXPECT_EQ(stale.verification_method.size(), 0u);

  // The parent announces the fork (§4.8 step 6).
  auto to = group_detail::FirstIriOf(parent->graph(), parent_did, kGroupForkedTo);
  EXPECT_TRUE(to.has_value());
  EXPECT_EQ(*to, child_did);
}

// ---- deactivation + reopen (§4.9, §8.2) ----

TEST(Group_DeactivateReflectsInResolution) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());
  EXPECT_TRUE(group->Deactivate());
  DidDocument doc;
  group->Resolve(&doc);
  EXPECT_TRUE(doc.deactivated);
}

TEST(Group_OpenByDidAndByIri) {
  GroupFixture f;
  auto group = f.groups.CreateGroup(DefaultGroupOptions());
  const std::string did = group->did();

  auto by_did = f.groups.OpenGroup(did);
  EXPECT_TRUE(by_did != nullptr);
  EXPECT_EQ(by_did->did(), did);

  std::string iri;
  EXPECT_TRUE(group->iri(&iri));
  auto by_iri = f.groups.OpenGroup(iri);
  EXPECT_TRUE(by_iri != nullptr);
  EXPECT_EQ(by_iri->did(), did);

  EXPECT_TRUE(f.groups.OpenGroup("did:graph:zUnknown") == nullptr);
  EXPECT_EQ(f.groups.last_error(), "NotFoundError");
}

// ============================================================
// Spec 04 — Graph Capability Framework
// ============================================================

namespace {

// The credential whose DID equals |did| — for a group, its own adopted key.
std::string CredIdForDid(DIDKeyProvider& p, const std::string& did) {
  for (const DIDKeyPair* c : p.ListCredentials())
    if (c->did == did)
      return c->id;
  return std::string();
}

// A governance fixture: a group W (a graph bearing a did:graph whose DID document
// holds the group key in every capability section) plus a GovernanceEngine.
struct GovFixture {
  DIDKeyProvider provider;
  GraphManager graphs{&provider};
  GroupManager groups{&provider, &graphs};
  GovernanceEngine gov{&provider};
  std::unique_ptr<Group> group;
  std::string gcred;  // the group's own credential id (did == group->did())

  GovFixture() {
    provider.CreateKey("Human");
    GroupCreationOptions o;
    o.sync_module = "urn:sync:module:default";
    o.display_name = "Governed";
    group = groups.CreateGroup(o);
    gcred = CredIdForDid(provider, group->did());
  }
  Graph* W() { return group->graph(); }
  const std::string& Wdid() { return group->did(); }
};

// Mint the root, install the capability constraint, and set enforced mode, all
// authored by the group key (the graph's constitutional signer). Returns root id.
std::string BootstrapEnforced(
    GovFixture& f,
    const std::optional<std::vector<std::string>>& actions = std::nullopt) {
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, actions, &root));
  std::string cid;
  EXPECT_TRUE(
      f.gov.InstallCapabilityConstraint(f.W(), f.gcred, std::nullopt, &cid));
  EXPECT_TRUE(
      f.gov.SetEnforcementMode(f.W(), f.gcred, EnforcementMode::kEnforced));
  return root;
}

// A one-element expiry-caveat array at the given RFC-3339 instant (§9.2).
std::string ExpiryCaveat(const std::string& at) {
  return "[{\"type\":\"expiry\",\"value\":{\"expiresAt\":\"" + at + "\"}}]";
}

// A plug-in constraint kind (§9.3) that blocks writes to a named predicate.
class BlockPredicateConstraint : public ConstraintKindHandler {
 public:
  std::string kind() const override { return "blockPredicate"; }
  HandlerResult Validate(const std::optional<Triple>& triple,
                         const GraphConstraint& constraint,
                         const ValidationContext&) override {
    HandlerResult r;
    auto blocked = constraint.Property("governance://blocked_predicate");
    if (triple && blocked && triple->predicate == *blocked) {
      r.allowed = false;
      r.reason = "blocked_predicate";
    }
    return r;
  }
};

// A plug-in caveat (§9.3) that forbids a specific object-literal value.
class ForbidValueCaveat : public CaveatHandler {
 public:
  std::string type() const override { return "forbidValue"; }
  bool appliesToNonTripleOps() const override { return false; }
  HandlerResult Evaluate(const Caveat& caveat,
                         const std::optional<Triple>& triple,
                         const std::string&, const ValidationContext&) override {
    HandlerResult r;
    auto forbidden = JsonStringField(caveat.value_raw, "equals");
    if (triple && forbidden && triple->object.is_literal() &&
        triple->object.literal->lexical == *forbidden) {
      r.allowed = false;
      r.reason = "forbidden_value";
    }
    return r;
  }
};

}  // namespace

// ---- ZCAP canonicalisation core (§4.5.3.1, §8; zcap.{h,cc}) ----

TEST(Zcap_DelegationProofPreimageExactBytes) {
  ZcapProofFields fields;
  fields.id = "urn:uuid:cap";
  fields.invoker = "did:key:z6MkInvoker";
  fields.parent_capability = "urn:living-web:zcap:BootstrapRoot";
  fields.actions = "createLink,removeLink";
  fields.resource = "did:graph:z6MkGraph";
  fields.caveats = "";
  fields.proof_purpose = "capabilityDelegation";
  fields.created = "2026-07-08T00:00:00Z";
  const std::string expected =
      "living-web/zcap/delegation/v1\n"
      "urn:uuid:cap\n"
      "did:key:z6MkInvoker\n"
      "urn:living-web:zcap:BootstrapRoot\n"
      "createLink,removeLink\n"
      "did:graph:z6MkGraph\n"
      "\n"  // empty caveats field
      "capabilityDelegation\n"
      "2026-07-08T00:00:00Z";
  EXPECT_EQ(BuildDelegationProofPreimage(fields), expected);
}

TEST(Zcap_DefaultRootActionsAreFrameworkCore) {
  auto a = DefaultRootActions();
  EXPECT_EQ(a.size(), 8u);
  const std::string joined = JoinActions(a);
  EXPECT_TRUE(ActionInSet("createLink", joined));
  EXPECT_TRUE(ActionInSet("updateGovernance", joined));
  EXPECT_TRUE(ActionInSet("delegateCapability", joined));
  EXPECT_TRUE(ActionInSet("announceFork", joined));
  // §4.3 amendment: updateSHACL is a Spec-07 extension, NOT a default action.
  EXPECT_FALSE(ActionInSet("updateSHACL", joined));
}

TEST(Zcap_ActionsSubsetParseJoin) {
  EXPECT_TRUE(ActionsSubset("createLink", "createLink,removeLink"));
  EXPECT_TRUE(ActionsSubset("removeLink,createLink", "createLink,removeLink"));
  EXPECT_FALSE(ActionsSubset("updateGovernance", "createLink,removeLink"));
  EXPECT_TRUE(ActionsSubset("", "createLink"));  // empty child ⊆ anything
  auto p = ParseActions("  a , b ,, c ");
  EXPECT_EQ(p.size(), 3u);
  EXPECT_EQ(p[0], "a");
  EXPECT_EQ(p[2], "c");
  EXPECT_EQ(JoinActions({"a", "b", "c"}), "a,b,c");
}

TEST(Zcap_JsonScannerAndCaveatAttenuation) {
  std::vector<std::string> elems;
  EXPECT_TRUE(
      SplitJsonArray("[{\"type\":\"expiry\"},{\"type\":\"x\"}]", &elems));
  EXPECT_EQ(elems.size(), 2u);
  auto t = JsonStringField(elems[0], "type");
  EXPECT_TRUE(t.has_value());
  EXPECT_EQ(*t, "expiry");
  EXPECT_TRUE(SplitJsonArray("[]", &elems));
  EXPECT_EQ(elems.size(), 0u);
  EXPECT_FALSE(SplitJsonArray("not-json", &elems));
  // §8 immutable caveats: every parent element must reappear byte-identically.
  EXPECT_TRUE(CaveatsAttenuationOk("", "[{\"type\":\"x\"}]"));  // no parent caveats
  EXPECT_TRUE(CaveatsAttenuationOk("[{\"type\":\"x\"}]",
                                   "[{\"type\":\"x\"},{\"type\":\"y\"}]"));
  EXPECT_FALSE(CaveatsAttenuationOk("[{\"type\":\"x\"}]", "[{\"type\":\"y\"}]"));
  EXPECT_FALSE(CaveatsAttenuationOk("[{\"type\":\"x\"}]", ""));  // dropped
  EXPECT_FALSE(CaveatsAttenuationOk("bad", "[{\"type\":\"x\"}]"));  // fail-closed
}

// ---- bootstrap: mint the root (§4.3) ----

TEST(Cap_MintRootCapabilityRecordsAndLists) {
  GovFixture f;
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  EXPECT_EQ(root.substr(0, 9), "urn:uuid:");
  // The root is invoked by the graph DID and lists its framework-core actions.
  auto caps = f.gov.MyCapabilities(f.W(), f.Wdid());
  EXPECT_EQ(caps.size(), 1u);
  EXPECT_EQ(caps[0].id, root);
  EXPECT_EQ(caps[0].resource, f.Wdid());
  EXPECT_TRUE(ActionInSet("updateGovernance", JoinActions(caps[0].actions)));
}

TEST(Cap_MintRootRequiresGraphDid) {
  DIDKeyProvider provider;
  auto k = provider.CreateKey("A");
  GraphManager graphs(&provider);
  GovernanceEngine gov(&provider);
  auto g = graphs.Create("Plain");  // a local graph with no DID (§4.5.2)
  std::string root;
  EXPECT_FALSE(gov.MintRootCapability(g.get(), k->id, std::nullopt, &root));
  EXPECT_EQ(gov.last_error(), "InvalidStateError");
}

// ---- enforcement modes (§5.1) ----

TEST(Cap_OpenModeSkipsCapabilityChecks) {
  GovFixture f;
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  std::string cid;
  EXPECT_TRUE(
      f.gov.InstallCapabilityConstraint(f.W(), f.gcred, std::nullopt, &cid));
  // Default mode is open: an undelegated stranger is still allowed (§5.1).
  auto stranger = f.provider.CreateKey("Stranger");
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                              stranger->did);
  EXPECT_TRUE(r.allowed);
  EXPECT_EQ(r.mode, "open");
}

TEST(Cap_EnforcedAllowsHolderDeniesStranger) {
  GovFixture f;
  BootstrapEnforced(f);
  // The graph DID (the root invoker) is authorised.
  auto ok = f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                               f.Wdid());
  EXPECT_TRUE(ok.allowed);
  EXPECT_EQ(ok.mode, "enforced");
  // A stranger holding no capability is denied, attributed to the constraint.
  auto stranger = f.provider.CreateKey("Stranger");
  auto no = f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                               stranger->did);
  EXPECT_FALSE(no.allowed);
  EXPECT_EQ(no.constraint_kind, "capability");
}

TEST(Cap_AnnouncedModeComputesButAccepts) {
  GovFixture f;
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  std::string cid;
  EXPECT_TRUE(
      f.gov.InstallCapabilityConstraint(f.W(), f.gcred, std::nullopt, &cid));
  EXPECT_TRUE(
      f.gov.SetEnforcementMode(f.W(), f.gcred, EnforcementMode::kAnnounced));
  // A stranger would fail the capability check, but announced never rejects.
  auto stranger = f.provider.CreateKey("Stranger");
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                              stranger->did);
  EXPECT_TRUE(r.allowed);
  EXPECT_EQ(r.mode, "announced");
}

// ---- delegation + attenuation (§4.5.3, §8) ----

TEST(Cap_DelegateAttenuatesActions) {
  GovFixture f;
  std::string root = BootstrapEnforced(f);
  auto member = f.provider.CreateKey("Member");

  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  std::string child;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, req, &child));

  // Member can createLink...
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 member->did)
                  .allowed);
  // ...but cannot updateGovernance (never delegated).
  EXPECT_FALSE(
      f.gov.CanPerformAction(f.W(), kActionUpdateGovernance, member->did)
          .allowed);

  // A mid cap that CAN delegate, but only createLink.
  DelegationRequest mid;
  mid.parent_capability = root;
  mid.invoker = member->did;
  mid.actions = {kActionCreateLink, kActionDelegateCapability};
  std::string midcap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, mid, &midcap));

  // Member (mid invoker) cannot over-delegate an action outside mid (§8).
  auto m2 = f.provider.CreateKey("M2");
  DelegationRequest over;
  over.parent_capability = midcap;
  over.invoker = m2->did;
  over.actions = {kActionRemoveLink};
  std::string x;
  EXPECT_FALSE(f.gov.Delegate(f.W(), member->id, over, &x));
  EXPECT_EQ(f.gov.last_error(), "attenuation_actions");
}

TEST(Cap_DelegateRejectsResourceEscalation) {
  GovFixture f;
  std::string root = BootstrapEnforced(f);
  auto member = f.provider.CreateKey("Member");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  req.resource = "did:graph:z6MkSomethingElse";  // != parent.resource (§8)
  std::string x;
  EXPECT_FALSE(f.gov.Delegate(f.W(), f.gcred, req, &x));
  EXPECT_EQ(f.gov.last_error(), "attenuation_resource");
}

TEST(Cap_DelegateCaveatsAreImmutable) {
  GovFixture f;
  std::string root = BootstrapEnforced(f);
  auto member = f.provider.CreateKey("Member");
  // A mid cap carrying an expiry caveat + delegateCapability.
  DelegationRequest mid;
  mid.parent_capability = root;
  mid.invoker = member->did;
  mid.actions = {kActionCreateLink, kActionDelegateCapability};
  mid.caveats = ExpiryCaveat("2099-01-01T00:00:00Z");
  std::string midcap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, mid, &midcap));

  auto m2 = f.provider.CreateKey("M2");
  // Dropping the parent caveat is rejected (§8 immutable caveats).
  DelegationRequest drop;
  drop.parent_capability = midcap;
  drop.invoker = m2->did;
  drop.actions = {kActionCreateLink};
  drop.caveats = "";
  std::string x;
  EXPECT_FALSE(f.gov.Delegate(f.W(), member->id, drop, &x));
  EXPECT_EQ(f.gov.last_error(), "attenuation_caveats");

  // Preserving it byte-for-byte is accepted.
  DelegationRequest keep = drop;
  keep.caveats = ExpiryCaveat("2099-01-01T00:00:00Z");
  std::string ok;
  EXPECT_TRUE(f.gov.Delegate(f.W(), member->id, keep, &ok));
}

TEST(Cap_TwoLevelDelegationChainAuthorises) {
  GovFixture f;
  std::string root = BootstrapEnforced(f);
  auto member = f.provider.CreateKey("Member");
  DelegationRequest mid;
  mid.parent_capability = root;
  mid.invoker = member->did;
  mid.actions = {kActionCreateLink, kActionDelegateCapability};
  std::string midcap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, mid, &midcap));

  auto m2 = f.provider.CreateKey("M2");
  DelegationRequest leaf;
  leaf.parent_capability = midcap;
  leaf.invoker = m2->did;
  leaf.actions = {kActionCreateLink};
  std::string leafcap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), member->id, leaf, &leafcap));

  // The deepest invoker writes via the two-hop chain root → mid → leaf.
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 m2->did)
                  .allowed);
}

// ---- caveats (§9.2 expiry, §9.3 plug-ins) ----

TEST(Cap_ExpiryCaveatBlocksExpiredAllowsLive) {
  GovFixture f;
  std::string root = BootstrapEnforced(f);

  auto expired = f.provider.CreateKey("Expired");
  DelegationRequest e;
  e.parent_capability = root;
  e.invoker = expired->did;
  e.actions = {kActionCreateLink};
  e.caveats = ExpiryCaveat("2000-01-01T00:00:00Z");
  std::string ecap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, e, &ecap));
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                  expired->did)
                   .allowed);

  auto live = f.provider.CreateKey("Live");
  DelegationRequest l;
  l.parent_capability = root;
  l.invoker = live->did;
  l.actions = {kActionCreateLink};
  l.caveats = ExpiryCaveat("2099-01-01T00:00:00Z");
  std::string lcap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, l, &lcap));
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                                 live->did)
                  .allowed);
}

TEST(Cap_PluginCaveatHandler) {
  GovFixture f;
  f.gov.RegisterCaveatType(std::make_unique<ForbidValueCaveat>());
  std::string root = BootstrapEnforced(f);
  auto member = f.provider.CreateKey("Member");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  req.caveats = "[{\"type\":\"forbidValue\",\"value\":{\"equals\":\"secret\"}}]";
  std::string child;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, req, &child));
  // The caveat forbids the object literal "secret".
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(),
                                  MakeLit("urn:n:1", "urn:p:body", "secret"),
                                  member->did)
                   .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "ok"),
                                 member->did)
                  .allowed);
}

// ---- revocation + brick protection (§4.5.5, §13.10) ----

TEST(Cap_RevokeBlocksDelegatee) {
  GovFixture f;
  std::string root = BootstrapEnforced(f);
  auto member = f.provider.CreateKey("Member");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = member->did;
  req.actions = {kActionCreateLink};
  std::string child;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, req, &child));
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 member->did)
                  .allowed);

  // The graph DID (an ancestor invoker) revokes the child (§4.5.5).
  EXPECT_TRUE(f.gov.Revoke(f.W(), f.gcred, child));
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                                  member->did)
                   .allowed);
}

TEST(Cap_RootCapabilityIsUnrevokable) {
  GovFixture f;
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  // The root has no ancestor invoker, so no agent has standing to revoke it.
  EXPECT_FALSE(f.gov.Revoke(f.W(), f.gcred, root));
  EXPECT_EQ(f.gov.last_error(), "not_authorised_to_revoke");
}

TEST(Cap_RevokeRedundantGovernanceAllowed) {
  GovFixture f;
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  auto agent = f.provider.CreateKey("Agent");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = agent->did;
  req.actions = {kActionUpdateGovernance, kActionDelegateCapability};
  std::string gov_cap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, req, &gov_cap));
  // Root (invoker = the graph DID) still governs, so revoking the redundant
  // delegated governance capability is safe (§13.10 false branch).
  EXPECT_TRUE(f.gov.Revoke(f.W(), f.gcred, gov_cap));
  EXPECT_EQ(f.gov.MyCapabilities(f.W(), agent->did).size(), 0u);
}

TEST(Cap_RevokeRefusedWhenItWouldBrickGovernance) {
  GovFixture f;
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  // A did:key agent will hold the sole *exercisable* governance capability.
  auto agent = f.provider.CreateKey("Agent");
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = agent->did;
  req.actions = {kActionUpdateGovernance, kActionDelegateCapability};
  std::string gov_cap;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, req, &gov_cap));

  // White-box: strip the group key from the graph DID's capabilityInvocation so
  // the root (invoker = the graph DID) is no longer *exercisable*. The agent's
  // governance capability is then the only surviving one, and revoking it must
  // be refused as bricking (§13.10 true branch).
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    for (const auto& o : group_detail::QueryObjects(
             f.W(), f.Wdid(),
             SectionPredicate(DIDCapabilitySection::kCapabilityInvocation))) {
      if (o.is_literal())
        continue;
      bool removed = false;
      f.W()->RemoveTriple(
          group_detail::T_iri(
              f.Wdid(),
              SectionPredicate(DIDCapabilitySection::kCapabilityInvocation),
              o.iri_or_bnode),
          &removed);
    }
  }
  EXPECT_FALSE(f.gov.Revoke(f.W(), f.gcred, gov_cap));
  EXPECT_EQ(f.gov.last_error(), "would_brick_governance");
}

// ---- immutable seeds (§10) ----

TEST(Cap_ImmutableSeedPredicateRejectedInAllModes) {
  GovFixture f;  // open mode, no capability constraint yet
  // Rewriting the group's syncModule seed is rejected before any capability
  // logic, in every mode (§10).
  auto r = f.gov.CanAddTriple(
      f.W(), MakeLit(f.Wdid(), kGroupSyncModule, "urn:sync:module:evil"),
      f.Wdid());
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.reason, "immutable_seed_predicate");
}

// ---- constraint kinds (§9.3, §13.8) + governance gate (§5.2) ----

TEST(Cap_UnknownConstraintKindFailsClosed) {
  GovFixture f;
  const std::string cid = "urn:uuid:constraint-temporal";
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(f.W()->AddTriples({
        group_detail::T_iri(cid, kGovEntryType, kGovConstraintEntryType),
        group_detail::T_lit(cid, kGovConstraintKind, "temporal"),
        group_detail::T_iri(f.Wdid(), kGovHasConstraint, cid),
    }));
  }
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                              f.Wdid());
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "temporal");
  EXPECT_EQ(r.reason, "unknown_constraint_kind");
}

TEST(Cap_PluginConstraintKindHandler) {
  GovFixture f;
  f.gov.RegisterConstraintKind(std::make_unique<BlockPredicateConstraint>());
  const std::string cid = "urn:uuid:constraint-block";
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(f.W()->AddTriples({
        group_detail::T_iri(cid, kGovEntryType, kGovConstraintEntryType),
        group_detail::T_lit(cid, kGovConstraintKind, "blockPredicate"),
        group_detail::T_lit(cid, "governance://blocked_predicate",
                            "urn:p:forbidden"),
        group_detail::T_iri(f.Wdid(), kGovHasConstraint, cid),
    }));
  }
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(),
                                  MakeLit("urn:n:1", "urn:p:forbidden", "x"),
                                  f.Wdid())
                   .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "x"),
                                 f.Wdid())
                  .allowed);
}

TEST(Cap_SetEnforcementModeRequiresGovernance) {
  GovFixture f;
  BootstrapEnforced(f);
  // Once a capability constraint is installed, flipping the mode demands
  // updateGovernance (§5.2); a stranger cannot (§5.2).
  auto stranger = f.provider.CreateKey("Stranger");
  EXPECT_FALSE(
      f.gov.SetEnforcementMode(f.W(), stranger->id, EnforcementMode::kOpen));
  EXPECT_EQ(f.gov.last_error(), "not_authorised");
  EXPECT_TRUE(f.gov.GetEnforcementMode(f.W()) == EnforcementMode::kEnforced);
}

TEST(Cap_ConstraintsForListsCapabilityConstraint) {
  GovFixture f;
  std::string root;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  std::string cid;
  EXPECT_TRUE(
      f.gov.InstallCapabilityConstraint(f.W(), f.gcred, std::nullopt, &cid));
  bool found = false;
  for (const auto& c : f.gov.ConstraintsFor(f.W(), f.Wdid()))
    if (c.kind == "capability" && c.id == cid)
      found = true;
  EXPECT_TRUE(found);
}

// ============================================================
// Spec 05 — Graph Synchronisation Protocol
// ============================================================

namespace {

// A sync harness: an open-governance group graph W (bearing a did:graph) plus two
// SyncEngines standing in for a committing peer and a receiving peer. They share
// the graph, identity provider, and governance engine, but keep independent diff
// chains — so a receiver genuinely re-validates what a sender emits rather than
// short-circuiting on its own commit record.
struct SyncFixture {
  GovFixture gov_fixture;
  SyncEngine sender{&gov_fixture.provider, &gov_fixture.gov};
  SyncEngine receiver{&gov_fixture.provider, &gov_fixture.gov};

  DIDKeyProvider& provider() { return gov_fixture.provider; }
  GovernanceEngine& gov() { return gov_fixture.gov; }
  Graph* W() { return gov_fixture.W(); }
  const std::string& Wdid() { return gov_fixture.Wdid(); }
};

// Builds a fully-signed GraphDiff for |wdid| whose additions' reifiers are
// authored by |reifier_agent| while the bundle (commitId + signature) is authored
// by |bundle_agent|. With the two equal this reproduces the CommitDiff
// construction byte-for-byte; with them distinct it is the author-smuggling diff
// that §9.2.1 step 4 (the reifier↔bundle author binding) must reject — every
// content address still recomputes correctly, so only the binding stands in the
// way.
GraphDiff ForgeDiff(DIDKeyProvider& p,
                    const std::string& wdid,
                    const DIDKeyPair* reifier_agent,
                    const DIDKeyPair* bundle_agent,
                    const std::vector<Triple>& additions,
                    const std::string& timestamp,
                    const std::vector<std::string>& deps = {}) {
  GraphDiff d;
  d.graph_did = wdid;
  d.author = bundle_agent->did;
  d.timestamp = timestamp;
  d.dependencies = SortDependencies(deps);
  for (const Triple& t : additions) {
    std::string payload =
        crypto::SHA256HashString(BuildSignaturePreimage(t, timestamp, wdid));
    auto sig = p.SignRaw(reifier_agent->id,
                         std::vector<uint8_t>(payload.begin(), payload.end()));
    DiffTriple dt;
    dt.triple = t;
    dt.author = reifier_agent->did;
    dt.timestamp = timestamp;
    dt.method = reifier_agent->method_id;
    dt.signature = did_key::MultibaseEncode(*sig);
    d.additions.push_back(std::move(dt));
  }
  std::string block;
  for (size_t i = 0; i < d.additions.size(); ++i) {
    const DiffTriple& dt = d.additions[i];
    block += BuildTripleWithReifierNquads(dt.triple, "_:r" + std::to_string(i),
                                          dt.author, dt.timestamp, dt.method,
                                          dt.signature);
  }
  std::string canon_add, err;
  OxigraphStore::Canonicalize(block, CanonHash::kSha256, &canon_add, &err);
  d.revision = ToLowerHex(crypto::SHA256HashString(
      BuildRevisionPreimage(wdid, canon_add, std::string(), d.dependencies)));
  d.commit_id = ToLowerHex(crypto::SHA256HashString(
      BuildCommitIdPreimage(d.revision, d.author, d.timestamp, std::string())));
  std::string msg = BuildSignatureMessage(d.commit_id);
  auto bsig = p.SignRaw(bundle_agent->id,
                        std::vector<uint8_t>(msg.begin(), msg.end()));
  d.signature = did_key::MultibaseEncode(*bsig);
  return d;
}

}  // namespace

// ---- GraphDiff identity core (graph_diff.{h,cc}, §5.2) ----

TEST(Sync_RevisionPreimageExactBytes) {
  // §5.2.2.1: length-framed, domain-separated, dependency-sorted+deduped.
  std::vector<std::string> deps = {"revB", "revA", "revA"};
  const std::string expected =
      "living-web/sync/revision/v1\n"
      "did:graph:zW\n"
      "3\n"
      "ADD"
      "2\n"
      "RM"
      "2\n"
      "revA\n"
      "revB\n";
  EXPECT_EQ(BuildRevisionPreimage("did:graph:zW", "ADD", "RM",
                                  SortDependencies(deps)),
            expected);
}

TEST(Sync_CommitIdPreimageExactBytes) {
  const std::string expected =
      "living-web/sync/commit/v1\n"
      "abc123\n"
      "did:key:zAuthor\n"
      "2026-07-08T00:00:00Z\n"
      "urn:zcap:leaf";
  EXPECT_EQ(BuildCommitIdPreimage("abc123", "did:key:zAuthor",
                                  "2026-07-08T00:00:00Z", "urn:zcap:leaf"),
            expected);
}

TEST(Sync_SignatureMessageIsCommitIdDirect) {
  // Amendment 05/§5.2.2.1: the commitId hex is signed directly, not re-hashed.
  EXPECT_EQ(BuildSignatureMessage("deadbeef"), "deadbeef");
}

TEST(Sync_SortDependenciesOrdersAndDedups) {
  auto out = SortDependencies({"c", "a", "b", "a", "c"});
  EXPECT_EQ(out.size(), 3u);
  EXPECT_EQ(out[0], "a");
  EXPECT_EQ(out[1], "b");
  EXPECT_EQ(out[2], "c");
}

// ---- sync-space derivation (§7) ----

TEST(Sync_SpaceDerivationInputPerTopology) {
  EXPECT_EQ(
      BuildSpaceDerivationInput(SpaceTopology::kUnified, false, "ns", "did", ""),
      "lwsync:unified:ns");
  EXPECT_EQ(BuildSpaceDerivationInput(SpaceTopology::kPrivacyTiered, false, "ns",
                                      "did", ""),
            "lwsync:public:ns");
  EXPECT_EQ(BuildSpaceDerivationInput(SpaceTopology::kPrivacyTiered, true, "ns",
                                      "did", ""),
            "lwsync:dedicated:did");
  EXPECT_EQ(BuildSpaceDerivationInput(SpaceTopology::kFullyPartitioned, false,
                                      "ns", "did", ""),
            "lwsync:dedicated:did");
  EXPECT_EQ(BuildSpaceDerivationInput(SpaceTopology::kCustom, false, "ns", "did",
                                      "myspace"),
            "lwsync:named:myspace");
}

TEST(Sync_TopologyTokenRoundTrip) {
  EXPECT_EQ(std::string(SpaceTopologyToken(SpaceTopology::kUnified)), "unified");
  EXPECT_EQ(std::string(SpaceTopologyToken(SpaceTopology::kPrivacyTiered)),
            "privacy-tiered");
  EXPECT_EQ(std::string(SpaceTopologyToken(SpaceTopology::kFullyPartitioned)),
            "fully-partitioned");
  EXPECT_EQ(std::string(SpaceTopologyToken(SpaceTopology::kCustom)), "custom");
  EXPECT_TRUE(SpaceTopologyFromToken("privacy-tiered") ==
              SpaceTopology::kPrivacyTiered);
  EXPECT_TRUE(SpaceTopologyFromToken("fully-partitioned") ==
              SpaceTopology::kFullyPartitioned);
  EXPECT_TRUE(SpaceTopologyFromToken("custom") == SpaceTopology::kCustom);
  EXPECT_TRUE(SpaceTopologyFromToken("nonsense") == SpaceTopology::kUnified);
}

TEST(Sync_DeriveSpaceProducesStableSpaceUri) {
  SyncFixture f;
  auto s1 = f.sender.DeriveSpace(f.W(), SpaceTopology::kUnified);
  EXPECT_TRUE(s1.has_value());
  EXPECT_TRUE(s1->rfind("space://", 0) == 0);
  EXPECT_EQ(s1->size(), std::string("space://").size() + 64);  // sha256 hex
  auto s2 = f.sender.DeriveSpace(f.W(), SpaceTopology::kUnified);
  EXPECT_EQ(*s1, *s2);  // deterministic
  // Unified keys off the participates-in namespace, fully-partitioned off the
  // graph DID — distinct derivation inputs → distinct spaces (§7.3).
  auto s3 = f.sender.DeriveSpace(f.W(), SpaceTopology::kFullyPartitioned);
  EXPECT_TRUE(s3.has_value());
  EXPECT_NE(*s1, *s3);
}

TEST(Sync_IsRestrictedTracksCapabilityConstraint) {
  GovFixture f;
  SyncEngine se(&f.provider, &f.gov);
  EXPECT_FALSE(se.IsRestricted(f.W()));  // no capability constraint → public
  std::string root, cid;
  EXPECT_TRUE(f.gov.MintRootCapability(f.W(), f.gcred, std::nullopt, &root));
  EXPECT_TRUE(
      f.gov.InstallCapabilityConstraint(f.W(), f.gcred, std::nullopt, &cid));
  EXPECT_TRUE(se.IsRestricted(f.W()));  // capability constraint → restricted
}

// ---- validateReadAccess (§9.2.2) ----

TEST(Sync_ReadAccessOpenGraphAccepts) {
  SyncFixture f;
  auto reader = f.provider().CreateKey("Reader");
  EXPECT_TRUE(
      f.receiver.ValidateReadAccess(f.W(), reader->did, std::nullopt).accepted);
}

TEST(Sync_ReadAccessRestrictedGraphRejectsStranger) {
  GovFixture f;
  BootstrapEnforced(f);
  SyncEngine se(&f.provider, &f.gov);
  auto stranger = f.provider.CreateKey("Stranger");
  EXPECT_FALSE(
      se.ValidateReadAccess(f.W(), stranger->did, std::nullopt).accepted);
}

// ---- commit → validate round trip (§5.2.2, §9.2.1) ----

TEST(Sync_CommitDiffRoundTripAccepts) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  std::vector<Triple> adds = {
      MakeLit("urn:note:1", "https://schema.org/name", "Hello"),
      MakeIri("urn:note:1", "https://schema.org/about", "urn:topic:sync")};
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id, adds, {}, opts, &diff));
  EXPECT_FALSE(diff.revision.empty());
  EXPECT_FALSE(diff.commit_id.empty());
  EXPECT_FALSE(diff.signature.empty());
  EXPECT_EQ(diff.author, alice->did);
  EXPECT_EQ(diff.additions.size(), 2u);

  // A fresh receiving peer validates it against its own (empty) chain.
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), diff).accepted);
  EXPECT_TRUE(f.receiver.HasChain(f.Wdid()));
  // §14.4: replaying an already-applied revision is an idempotent accept.
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), diff).accepted);
}

TEST(Sync_RemovalsRoundTripAccepts) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:a", "urn:p", "keep")},
                                  {MakeLit("urn:b", "urn:p", "drop")}, opts,
                                  &diff));
  EXPECT_EQ(diff.additions.size(), 1u);
  EXPECT_EQ(diff.removals.size(), 1u);
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), diff).accepted);
}

TEST(Sync_BundleSignatureTamperRejected) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  auto bob = f.provider().CreateKey("Bob");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:s", "urn:p", "v")}, {}, opts,
                                  &diff));
  // Replace the bundle signature with Bob's signature over the same commitId: it
  // decodes to 64 bytes, but fails to verify against the author (Alice) key.
  std::string msg = BuildSignatureMessage(diff.commit_id);
  auto bobsig = f.provider().SignRaw(
      bob->id, std::vector<uint8_t>(msg.begin(), msg.end()));
  GraphDiff tampered = diff;
  tampered.signature = did_key::MultibaseEncode(*bobsig);
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), tampered);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "signature_invalid");
}

TEST(Sync_RevisionTamperRejected) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff diff;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:s", "urn:p", "original")}, {},
                                  opts, &diff));
  // Mutate the payload triple without recomputing the revision: the receiver's
  // recomputed content address no longer matches the claimed one (step 0).
  GraphDiff tampered = diff;
  tampered.additions[0].triple = MakeLit("urn:s", "urn:p", "tampered");
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), tampered);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "revision_invalid");
}

TEST(Sync_ForgeDiffFidelity) {
  // The forge helper reproduces the real CommitDiff construction: a diff whose
  // reifiers and bundle are the same agent validates cleanly.
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  GraphDiff honest =
      ForgeDiff(f.provider(), f.Wdid(), alice.get(), alice.get(),
                {MakeLit("urn:claim", "urn:p", "x")}, "2026-07-01T00:00:00Z");
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), honest).accepted);
}

TEST(Sync_ReifierAuthorSmuggleRejected) {
  // Regression: Alice authored the reifiers, but Mallory wraps + signs the
  // bundle. revision (over Alice's reifiers), commitId (over Mallory), and the
  // bundle signature (Mallory's) all recompute correctly — so ONLY the §9.2.1
  // step-4 author binding prevents Mallory from committing triples misattributed
  // to Alice. Removing that binding makes this diff wrongly accepted.
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  auto mallory = f.provider().CreateKey("Mallory");
  GraphDiff smuggled =
      ForgeDiff(f.provider(), f.Wdid(), alice.get(), mallory.get(),
                {MakeLit("urn:claim", "urn:p", "x")}, "2026-07-01T00:00:00Z");
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), smuggled);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "reifier_signature_invalid");
}

// ---- dependency validation (§5.2.1) ----

TEST(Sync_ChainRootAndSnapshotPromotion) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  CommitOptions o0;
  o0.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff first;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:a", "urn:p", "1")}, {}, o0,
                                  &first));
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), first).accepted);

  // A second chain-root (no dependencies) on a non-empty chain is rejected...
  CommitOptions o1;
  o1.timestamp = "2026-07-01T00:01:00Z";
  GraphDiff orphan;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:b", "urn:p", "2")}, {}, o1,
                                  &orphan));
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), orphan);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "chain_root_conflict");

  // ...unless it advertises a snapshot promotion (§5.2.1).
  CommitOptions o2;
  o2.timestamp = "2026-07-01T00:02:00Z";
  o2.snapshot_promotion = true;
  GraphDiff promo;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:c", "urn:p", "3")}, {}, o2,
                                  &promo));
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), promo).accepted);
}

TEST(Sync_MissingDependencyRejected) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2026-07-01T00:00:00Z";
  opts.dependencies = {"a-revision-the-receiver-never-saw"};
  GraphDiff diff;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:a", "urn:p", "1")}, {}, opts,
                                  &diff));
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), diff);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "missing_dependency");
}

// ---- timestamp plausibility (§14.5) ----

TEST(Sync_TimestampFutureRejected) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  CommitOptions opts;
  opts.timestamp = "2099-01-01T00:00:00Z";  // well beyond now + 300 s
  GraphDiff diff;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:a", "urn:p", "1")}, {}, opts,
                                  &diff));
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), diff);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "timestamp_future");
  EXPECT_EQ(r.constraint_kind, "temporal");
}

TEST(Sync_TimestampCausalRejected) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  CommitOptions p;
  p.timestamp = "2026-07-01T02:00:00Z";
  GraphDiff parent;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:a", "urn:p", "1")}, {}, p,
                                  &parent));
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), parent).accepted);

  // A child that depends on the parent but is dated before it violates causal
  // monotonicity.
  CommitOptions c;
  c.timestamp = "2026-07-01T01:00:00Z";
  c.dependencies = {parent.revision};
  GraphDiff child;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:b", "urn:p", "2")}, {}, c,
                                  &child));
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), child);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "timestamp_causal");
}

TEST(Sync_TimestampMonotonicRejected) {
  SyncFixture f;
  auto alice = f.provider().CreateKey("Alice");
  CommitOptions o0;
  o0.timestamp = "2026-07-01T00:00:00Z";
  GraphDiff d0;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:a", "urn:p", "1")}, {}, o0,
                                  &d0));
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), d0).accepted);

  CommitOptions o2;
  o2.timestamp = "2026-07-01T02:00:00Z";
  o2.dependencies = {d0.revision};
  GraphDiff d2;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:b", "urn:p", "2")}, {}, o2,
                                  &d2));
  EXPECT_TRUE(f.receiver.ValidateDiff(f.W(), d2).accepted);

  // A later commit dated before the author's max applied timestamp, depending
  // only on the root (so no dependency is newer than it — causal is satisfied),
  // still violates per-author monotonicity (§14.5).
  CommitOptions o1;
  o1.timestamp = "2026-07-01T01:00:00Z";
  o1.dependencies = {d0.revision};
  GraphDiff d1;
  EXPECT_TRUE(f.sender.CommitDiff(f.W(), alice->id,
                                  {MakeLit("urn:c", "urn:p", "3")}, {}, o1,
                                  &d1));
  SyncValidationResult r = f.receiver.ValidateDiff(f.W(), d1);
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(r.reason, "timestamp_monotonic");
}

TEST(Sync_Rfc3339EpochParsing) {
  int64_t e = 0;
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("1970-01-01T00:00:00Z", &e));
  EXPECT_EQ(e, int64_t(0));
  int64_t earlier = 0, later = 0;
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-01T00:00:00Z", &earlier));
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-01T00:00:01Z", &later));
  EXPECT_EQ(later - earlier, int64_t(1));
  // Offset designators normalise to UTC: 12:00+02:00 == 10:00Z == 08:00-02:00.
  int64_t z = 0, plus = 0, minus = 0;
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-08T10:00:00Z", &z));
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-08T12:00:00+02:00", &plus));
  EXPECT_TRUE(sync_detail::Rfc3339ToEpoch("2026-07-08T08:00:00-02:00", &minus));
  EXPECT_EQ(z, plus);
  EXPECT_EQ(z, minus);
  EXPECT_FALSE(sync_detail::Rfc3339ToEpoch("not-a-timestamp", &e));
}

// ---- invitation links (§12) ----

TEST(Sync_InvitationFormatParseRoundTrip) {
  const std::string relay = "relay.example.com:8443";
  const std::string space = "space://abc123";  // arbitrary bytes → base64url
  const std::string did = "did:graph:z6MkExample";
  const std::string module = "sha256:deadbeef";
  const std::string name = "Alice & Bob's Space";  // spaces + reserved chars
  std::string uri = SyncEngine::FormatInvitation(relay, space, did, module, name);
  EXPECT_TRUE(uri.rfind("web+graph://", 0) == 0);

  SyncEngine::Invitation inv;
  EXPECT_TRUE(SyncEngine::ParseInvitation(uri, &inv));
  EXPECT_EQ(inv.relay_host, relay);
  EXPECT_EQ(inv.space_uri, space);
  EXPECT_EQ(inv.graph_did, did);
  EXPECT_EQ(inv.module_hash, module);
  EXPECT_EQ(inv.name, name);
}

TEST(Sync_InvitationOptionalFieldsAbsent) {
  std::string uri =
      SyncEngine::FormatInvitation("relay", "space://x", "did:graph:zX");
  SyncEngine::Invitation inv;
  EXPECT_TRUE(SyncEngine::ParseInvitation(uri, &inv));
  EXPECT_EQ(inv.graph_did, "did:graph:zX");
  EXPECT_TRUE(inv.module_hash.empty());
  EXPECT_TRUE(inv.name.empty());
}

TEST(Sync_InvitationRequiresDid) {
  // A well-formed URI missing the required did= parameter is rejected (§12.2).
  std::string uri = "web+graph://relay.example.com/" +
                    sync_detail::Base64UrlEncode("space://x") + "?name=NoDid";
  SyncEngine::Invitation inv;
  EXPECT_FALSE(SyncEngine::ParseInvitation(uri, &inv));
}

TEST(Sync_InvitationRejectsWrongScheme) {
  SyncEngine::Invitation inv;
  EXPECT_FALSE(SyncEngine::ParseInvitation("https://relay/x?did=y", &inv));
}

// ---- reconnection primitives (§13) ----

TEST(Sync_DiffQueueDedupesByCommitId) {
  DiffQueue q;
  GraphDiff a;
  a.commit_id = "c1";
  GraphDiff b;
  b.commit_id = "c2";
  EXPECT_TRUE(q.Enqueue(a));
  EXPECT_FALSE(q.Enqueue(a));  // same commitId → not re-enqueued
  EXPECT_TRUE(q.Enqueue(b));
  EXPECT_EQ(q.Size(), 2u);
  EXPECT_TRUE(q.Contains("c1"));
  EXPECT_TRUE(q.Acknowledge("c1"));
  EXPECT_FALSE(q.Contains("c1"));
  EXPECT_EQ(q.Size(), 1u);
  EXPECT_FALSE(q.Acknowledge("c1"));  // already acknowledged
}

TEST(Sync_DiffQueueBatchCapsAndOrders) {
  DiffQueue q;
  for (int i = 0; i < 150; ++i) {
    GraphDiff d;
    d.commit_id = "c" + std::to_string(i);
    EXPECT_TRUE(q.Enqueue(d));
  }
  EXPECT_EQ(q.Size(), 150u);
  EXPECT_EQ(q.NextBatch().size(), kBatchMaxDiffs);  // default cap = 100 (§13.4)
  EXPECT_EQ(q.NextBatch(10).size(), 10u);
  auto batch = q.NextBatch(3);  // commit order preserved
  EXPECT_EQ(batch[0].commit_id, "c0");
  EXPECT_EQ(batch[1].commit_id, "c1");
  EXPECT_EQ(batch[2].commit_id, "c2");
}

TEST(Sync_ReconnectBackoffDoublesAndCaps) {
  EXPECT_EQ(ReconnectBackoffMs(0), uint64_t(5000));
  EXPECT_EQ(ReconnectBackoffMs(1), uint64_t(10000));
  EXPECT_EQ(ReconnectBackoffMs(2), uint64_t(20000));
  EXPECT_EQ(ReconnectBackoffMs(3), uint64_t(40000));
  EXPECT_EQ(ReconnectBackoffMs(4), uint64_t(80000));
  EXPECT_EQ(ReconnectBackoffMs(5), uint64_t(160000));
  EXPECT_EQ(ReconnectBackoffMs(6), uint64_t(300000));    // 320000 capped
  EXPECT_EQ(ReconnectBackoffMs(100), uint64_t(300000));  // stays capped
}

// ============================================================
// Spec 06 — Sync Module Architecture
// ============================================================
//
// These tests exercise the Chromium-independent module-runtime host contract
// (ModuleRuntime + the two shared cores) directly: the test plays the WASM
// module, calling the §6.3 host imports the way a component would, so every
// grant/scope/quota/lifecycle decision the runtime makes is asserted without a
// V8/component-model instance. The injected backends are REAL — a real Oxigraph
// graph store (Spec 02 `Graph`), a real Ed25519 signer (`DIDKeyProvider`), a
// real wall/monotonic clock and the OpenSSL CSPRNG — so the same bytes flow as
// in the browser; only WASM instantiation itself (the §6.1 boundary) is absent.

namespace {

// The fake module binaries the harness content-addresses. The standalone
// runtime never executes them — WASM instantiation is the browser overlay's
// V8/component-model boundary (§6.1) — so any distinct bytes serve to drive the
// host contract; two binaries give two distinct §4.2 content hashes.
const char kModWasmA[] = "living-web-sync-module-A::wasm-component-bytes::v1";
const char kModWasmB[] = "living-web-sync-module-B::wasm-component-bytes::v1";

std::string ModContentHash(const std::string& wasm) {
  return FormatModuleContentHash(crypto::SHA256HashString(wasm));
}

std::string ModJsonArr(const std::vector<std::string>& v) {
  std::string s = "[";
  for (size_t i = 0; i < v.size(); ++i) {
    s += "\"" + v[i] + "\"";
    if (i + 1 < v.size())
      s += ",";
  }
  return s + "]";
}

// A §8.2 manifest JSON binding |content_hash|, requiring |kinds| / |caps|.
std::string ModManifest(const std::string& name,
                        const std::string& version,
                        const std::string& content_hash,
                        const std::vector<std::string>& kinds,
                        const std::vector<std::string>& caps) {
  return std::string("{") + "\"name\":\"" + name + "\"," + "\"version\":\"" +
         version + "\"," + "\"wasmContentHash\":\"" + content_hash + "\"," +
         "\"supportedConstraintKinds\":" + ModJsonArr(kinds) + "," +
         "\"capabilitiesRequired\":" + ModJsonArr(caps) + "}";
}

// host-graph backing over real Spec 02 graphs, keyed by graph-did.
class ModGraphBackend : public HostGraphBackend {
 public:
  explicit ModGraphBackend(DIDKeyProvider* identity) : identity_(identity) {}

  Graph* AddGraph(const std::string& graph_did) {
    auto g =
        std::make_unique<Graph>(identity_, graph_did, GraphTrustLevel::kLocal);
    Graph* raw = g.get();
    graphs_[graph_did] = std::move(g);
    return raw;
  }
  Graph* Get(const std::string& graph_did) {
    auto it = graphs_.find(graph_did);
    return it == graphs_.end() ? nullptr : it->second.get();
  }

  bool QueryTriples(const std::string& graph_did,
                    const TripleQuery& query,
                    std::vector<Triple>* out,
                    std::string* err) override {
    Graph* g = Get(graph_did);
    if (!g) {
      *err = "unknown graph";
      return false;
    }
    if (!g->QueryTriples(query, out)) {
      *err = g->last_error();
      return false;
    }
    return true;
  }
  bool QuerySparql(const std::string& graph_did,
                   const std::string& sparql,
                   std::string* out,
                   std::string* err) override {
    Graph* g = Get(graph_did);
    if (!g) {
      *err = "unknown graph";
      return false;
    }
    SparqlResult r = g->QuerySparql(sparql, {});
    if (!r.ok) {
      *err = r.error;
      return false;
    }
    *out = r.payload;
    return true;
  }
  bool Snapshot(const std::string& graph_did,
                std::vector<Triple>* out,
                std::string* err) override {
    Graph* g = Get(graph_did);
    if (!g) {
      *err = "unknown graph";
      return false;
    }
    if (!g->Snapshot(out)) {
      *err = g->last_error();
      return false;
    }
    return true;
  }
  bool Apply(const std::string& graph_did,
             const GraphDiff& diff,
             std::string* err) override {
    Graph* g = Get(graph_did);
    if (!g) {
      *err = "unknown graph";
      return false;
    }
    std::vector<Triple> adds;
    for (const DiffTriple& dt : diff.additions)
      adds.push_back(dt.triple);
    if (!adds.empty() && !g->AddTriples(adds)) {
      *err = g->last_error();
      return false;
    }
    for (const DiffTriple& dt : diff.removals) {
      bool removed = false;
      if (!g->RemoveTriple(dt.triple, &removed)) {
        *err = g->last_error();
        return false;
      }
    }
    return true;
  }

 private:
  DIDKeyProvider* identity_;
  std::map<std::string, std::unique_ptr<Graph>> graphs_;
};

// host-crypto backing: the scoped Ed25519 signer over a real DIDKeyProvider.
class ModCryptoBackend : public HostCryptoBackend {
 public:
  ModCryptoBackend(DIDKeyProvider* identity, std::string signer_cred_id)
      : identity_(identity), signer_(std::move(signer_cred_id)) {}

  bool SignCommit(const std::string& /*graph_did*/,
                  const std::string& commit_id,
                  HostSigned* out,
                  std::string* err) override {
    const std::string msg = BuildSignatureMessage(commit_id);
    auto sig = identity_->SignRaw(
        signer_, std::vector<uint8_t>(msg.begin(), msg.end()));
    if (!sig) {
      *err = "sign failed";
      return false;
    }
    out->signature = *sig;
    const DIDKeyPair* k = identity_->GetCredential(signer_);
    out->verification_method = k ? k->method_id : std::string();
    return true;
  }
  bool SignSignal(const std::string& space_uri,
                  const std::string& local_did,
                  const std::string& remote_did,
                  const std::vector<uint8_t>& payload,
                  HostSigned* out,
                  std::string* err) override {
    std::string pre = space_uri;
    pre.push_back('\x1f');
    pre += local_did;
    pre.push_back('\x1f');
    pre += remote_did;
    pre.push_back('\x1f');
    pre.append(payload.begin(), payload.end());
    auto sig = identity_->SignRaw(
        signer_, std::vector<uint8_t>(pre.begin(), pre.end()));
    if (!sig) {
      *err = "sign failed";
      return false;
    }
    out->signature = *sig;
    const DIDKeyPair* k = identity_->GetCredential(signer_);
    out->verification_method = k ? k->method_id : std::string();
    return true;
  }
  bool Verify(const std::vector<uint8_t>& message,
              const HostSigned& signature,
              const std::string& public_key,
              bool* valid) override {
    auto pub = did_key::ParseDidKeyEd25519(public_key);
    if (!pub || pub->size() != 32 || signature.signature.size() != 64) {
      *valid = false;
      return true;
    }
    *valid = ed25519_verify(signature.signature.data(), message.data(),
                            message.size(), pub->data()) == 1;
    return true;
  }

 private:
  DIDKeyProvider* identity_;
  std::string signer_;
};

// An in-process loopback transport: framed messages sent are echoed back on
// receive. No external I/O, but a real byte stream with real close semantics.
class ModConnection : public HostConnection {
 public:
  bool Send(const std::vector<uint8_t>& message, HostError* err) override {
    if (!open_) {
      *err = HostError::kNetworkError;
      return false;
    }
    inbox_.push_back(message);
    return true;
  }
  bool Receive(std::vector<uint8_t>* out,
               bool* closed,
               HostError* /*err*/) override {
    if (inbox_.empty()) {
      out->clear();
      *closed = !open_;
      return true;
    }
    *out = inbox_.front();
    inbox_.erase(inbox_.begin());
    *closed = false;
    return true;
  }
  bool IsOpen() const override { return open_; }
  void Close() override { open_ = false; }

 private:
  bool open_ = true;
  std::vector<std::vector<uint8_t>> inbox_;
};

class ModNetworkBackend : public HostNetworkBackend {
 public:
  HostConnection* Connect(const std::string&,
                          RelayProtocol,
                          HostError*) override {
    conns_.push_back(std::make_unique<ModConnection>());
    return conns_.back().get();
  }
  HostConnection* PeerConnect(const std::string&,
                              const std::string&,
                              HostError*) override {
    conns_.push_back(std::make_unique<ModConnection>());
    return conns_.back().get();
  }
  bool Fetch(const std::string& url,
             std::vector<uint8_t>* out,
             HostError*) override {
    out->assign(url.begin(), url.end());  // echo the URL bytes as the body
    return true;
  }

 private:
  std::vector<std::unique_ptr<ModConnection>> conns_;
};

// Wire the injected primitives: real SHA-256, real clocks, the OpenSSL CSPRNG.
ModuleRuntimeDeps ModDeps(HostGraphBackend* g,
                          HostCryptoBackend* c,
                          HostNetworkBackend* n) {
  ModuleRuntimeDeps d;
  d.sha256_raw = [](const std::string& s) {
    return crypto::SHA256HashString(s);
  };
  d.graph = g;
  d.crypto = c;
  d.network = n;
  d.now_wallclock_ms = []() -> uint64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
  };
  d.now_monotonic_ns = []() -> uint64_t {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  };
  d.random_bytes = [](uint32_t len) {
    std::vector<uint8_t> v(len);
    if (len)
      RAND_bytes(v.data(), static_cast<int>(len));
    return v;
  };
  return d;
}

}  // namespace

// ---- §4.2 content-addressing (module_manifest.cc) ----

TEST(Module_ContentHash_FormatAndWellFormedness) {
  const std::string h = FormatModuleContentHash(crypto::SHA256HashString("abc"));
  EXPECT_EQ(h.size(), size_t(71));               // "sha256-" (7) + 64 hex
  EXPECT_TRUE(h.compare(0, 7, "sha256-") == 0);
  EXPECT_TRUE(IsWellFormedContentHash(h));
  // Deterministic: same binary → same address (§4.2 mutual verifiability).
  EXPECT_EQ(h, FormatModuleContentHash(crypto::SHA256HashString("abc")));

  EXPECT_FALSE(IsWellFormedContentHash(h.substr(0, 70)));  // 63 hex digits
  EXPECT_FALSE(IsWellFormedContentHash("sha256-" + std::string(64, 'g')));
  std::string upper = h;
  upper[7] = 'A';  // uppercase hex is not lowercase-hex
  EXPECT_FALSE(IsWellFormedContentHash(upper));
  EXPECT_FALSE(IsWellFormedContentHash("sha512-" + h.substr(7)));  // wrong prefix
}

// ---- §8.2 manifest parse ----

TEST(Module_Manifest_ParseValidPopulatesFields) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest m;
  std::string err;
  EXPECT_TRUE(ParseModuleManifest(
      ModManifest("Default Sync", "1.2.0", ch, {"capability", "shape"},
                  {"graph.read", "graph.write"}),
      &m, &err));
  EXPECT_TRUE(m.valid);
  EXPECT_EQ(m.name, std::string("Default Sync"));
  EXPECT_EQ(m.version, std::string("1.2.0"));
  EXPECT_EQ(m.wasm_content_hash, ch);
  EXPECT_EQ(m.supported_constraint_kinds.size(), size_t(2));
  EXPECT_EQ(m.capabilities_required.size(), size_t(2));

  // Optional publisher/description are captured when present, ignored when not.
  ModuleManifest m2;
  EXPECT_TRUE(ParseModuleManifest(
      std::string("{\"name\":\"n\",\"version\":\"1\",\"wasmContentHash\":\"") +
          ch +
          "\",\"supportedConstraintKinds\":[],\"capabilitiesRequired\":[],"
          "\"publisher\":\"acme\",\"description\":\"d\"}",
      &m2, &err));
  EXPECT_EQ(m2.publisher, std::string("acme"));
  EXPECT_EQ(m2.description, std::string("d"));
}

TEST(Module_Manifest_RejectsMalformed) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest m;
  std::string err;
  auto reject = [&](const std::string& json) {
    return !ParseModuleManifest(json, &m, &err) && !m.valid;
  };
  // Missing each required field.
  EXPECT_TRUE(reject(std::string("{\"version\":\"1\",\"wasmContentHash\":\"") +
                     ch +
                     "\",\"supportedConstraintKinds\":[],"
                     "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"wasmContentHash\":\"") + ch +
                     "\",\"supportedConstraintKinds\":[],"
                     "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(
      "{\"name\":\"n\",\"version\":\"1\",\"supportedConstraintKinds\":[],"
      "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch + "\",\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch + "\",\"supportedConstraintKinds\":[]}"));
  // Malformed content hash.
  EXPECT_TRUE(
      reject("{\"name\":\"n\",\"version\":\"1\",\"wasmContentHash\":\"sha256-xy"
             "\",\"supportedConstraintKinds\":[],\"capabilitiesRequired\":[]}"));
  // Wrong-typed array fields.
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch +
                     "\",\"supportedConstraintKinds\":\"nope\","
                     "\"capabilitiesRequired\":[]}"));
  EXPECT_TRUE(reject(std::string("{\"name\":\"n\",\"version\":\"1\","
                                 "\"wasmContentHash\":\"") +
                     ch +
                     "\",\"supportedConstraintKinds\":[],"
                     "\"capabilitiesRequired\":[1,2]}"));
}

TEST(Module_Manifest_BindsContentHash) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest m;
  std::string err;
  EXPECT_TRUE(ParseModuleManifest(
      ModManifest("n", "1", ch, {"capability"}, {"graph.read"}), &m, &err));
  EXPECT_TRUE(ManifestBindsContentHash(m, ch));
  EXPECT_FALSE(ManifestBindsContentHash(m, ModContentHash(kModWasmB)));
  EXPECT_FALSE(ManifestBindsContentHash(m, std::string()));
}

// ---- §7.1 installation ----

TEST(Module_Install_VerifiesContentHashAndCaps) {
  ModGraphBackend gb(nullptr);
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));
  const std::string ch = ModContentHash(kModWasmA);

  // A manifest that binds the exact binary installs, consent pending (§7.2).
  auto ok = rt.Install(
      kModWasmA, ModManifest("m", "1", ch, {"capability"}, {"graph.read"}));
  EXPECT_TRUE(ok.ok);
  EXPECT_EQ(ok.content_hash, ch);
  EXPECT_TRUE(rt.IsInstalled(ch));
  EXPECT_TRUE(rt.ConsentOf(ch) == ConsentDecision::kPending);

  // A manifest binding a DIFFERENT binary is rejected (§8.2/§9.2).
  auto wrong = rt.Install(
      kModWasmA,
      ModManifest("m", "1", ModContentHash(kModWasmB), {"capability"},
                  {"graph.read"}));
  EXPECT_FALSE(wrong.ok);
  EXPECT_TRUE(wrong.error == HostError::kInvalidArgument);

  // An unknown capability token is rejected at install (§7.1 step 3).
  auto badcap = rt.Install(
      kModWasmB,
      ModManifest("m", "1", ModContentHash(kModWasmB), {"capability"},
                  {"graph.read", "totally.made.up"}));
  EXPECT_FALSE(badcap.ok);
  EXPECT_TRUE(badcap.error == HostError::kInvalidArgument);
}

// ---- §7.2 consent gates instantiation and every surface ----

TEST(Module_Consent_GatesInstantiationAndSurfaces) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"}, {"graph.read"}))
          .ok);

  // Instantiation before consent is not-authorised (§7.2).
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"})
                  .error == HostError::kNotAuthorised);

  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"})
                  .ok);
  EXPECT_TRUE(rt.ReaderSnapshot(ch, "space://s", "did:graph:g1").ok);

  // Revoking consent immediately closes the surfaces (§8.3 — no forging past).
  EXPECT_TRUE(rt.DenyConsent(ch));
  EXPECT_TRUE(rt.ReaderSnapshot(ch, "space://s", "did:graph:g1").error ==
              HostError::kNotAuthorised);
}

// ---- §6.3 host-graph: capability + scope + real read/write ----

TEST(Module_HostGraph_CapabilityScopeAndRealIO) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(rt.Install(kModWasmA,
                         ModManifest("m", "1", ch, {"capability"},
                                     {"graph.read", "graph.write"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  // Write a real diff through the writer surface; it lands in Oxigraph.
  GraphDiff diff;
  diff.graph_did = "did:graph:g1";
  DiffTriple dt;
  dt.triple = MakeLit("urn:note:1", "https://schema.org/name", "Hello");
  diff.additions.push_back(dt);
  EXPECT_TRUE(rt.WriterApply(ch, "space://s", "did:graph:g1", diff).ok);

  // Read it back through the reader surface.
  auto q = rt.ReaderQueryTriples(ch, "space://s", "did:graph:g1", TripleQuery{});
  EXPECT_TRUE(q.ok);
  EXPECT_EQ(q.value.size(), size_t(1));
  EXPECT_EQ(q.value[0].subject, std::string("urn:note:1"));

  // Snapshot and SPARQL are equally real.
  auto snap = rt.ReaderSnapshot(ch, "space://s", "did:graph:g1");
  EXPECT_TRUE(snap.ok);
  EXPECT_EQ(snap.value.size(), size_t(1));
  auto sr = rt.ReaderQuerySparql(ch, "space://s", "did:graph:g1",
                                 "SELECT (COUNT(*) AS ?n) WHERE { ?s ?p ?o }");
  EXPECT_TRUE(sr.ok);
  EXPECT_GT(sr.value.size(), size_t(0));

  // A graph outside the authorised set is unknown-scope (§5.3), not a read.
  EXPECT_TRUE(
      rt.ReaderQueryTriples(ch, "space://s", "did:graph:other", TripleQuery{})
          .error == HostError::kUnknownScope);
}

TEST(Module_HostGraph_WriteRequiresGrant) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));
  const std::string ch = ModContentHash(kModWasmA);
  // graph.read only — no graph.write.
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"}, {"graph.read"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  GraphDiff diff;
  diff.graph_did = "did:graph:g1";
  DiffTriple dt;
  dt.triple = MakeLit("urn:x", "urn:p", "v");
  diff.additions.push_back(dt);
  EXPECT_TRUE(rt.WriterApply(ch, "space://s", "did:graph:g1", diff).error ==
              HostError::kNotAuthorised);
}

// ---- §5.4 / §9.7 scoped signer ----

TEST(Module_ScopedSigner_CommitLedgerAndVerify) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  DIDKeyProvider sp;
  auto signer = sp.CreateKey("Signer");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModCryptoBackend cb(&sp, signer->id);
  ModuleRuntime rt(ModDeps(&gb, &cb, nullptr));
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(rt.Install(kModWasmA,
                         ModManifest("m", "1", ch, {"capability"},
                                     {"crypto.commit-sign", "crypto.verify"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  const std::string commit_id =
      ToLowerHex(crypto::SHA256HashString("commit-payload-1"));

  // §9.7: a commit-id the module never built cannot be signed.
  EXPECT_TRUE(rt.SignCommit(ch, "space://s", "did:graph:g1", commit_id).error ==
              HostError::kSigningRefused);

  // The runtime observes module.commit build the diff → the id becomes eligible.
  EXPECT_TRUE(rt.RecordCommit(ch, "space://s", "did:graph:g1", commit_id).ok);
  auto sig = rt.SignCommit(ch, "space://s", "did:graph:g1", commit_id);
  EXPECT_TRUE(sig.ok);
  EXPECT_EQ(sig.value.signature.size(), size_t(64));

  // The signature verifies over the commit-id via the verify surface.
  std::vector<uint8_t> msg(commit_id.begin(), commit_id.end());
  auto ver = rt.Verify(ch, "space://s", msg, sig.value, signer->did);
  EXPECT_TRUE(ver.ok);
  EXPECT_TRUE(ver.value);

  // Recording against a non-authorised graph is unknown-scope; signing a
  // commit for a graph it was not built on stays refused (exhaustive shapes).
  EXPECT_TRUE(
      rt.RecordCommit(ch, "space://s", "did:graph:other", commit_id).error ==
      HostError::kUnknownScope);
  EXPECT_TRUE(rt.SignCommit(ch, "space://s", "did:graph:other", commit_id)
                  .error == HostError::kSigningRefused);
}

TEST(Module_ScopedSigner_SignalGatedByCapability) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  DIDKeyProvider sp;
  auto signer = sp.CreateKey("Signer");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModCryptoBackend cb(&sp, signer->id);
  const std::string ch = ModContentHash(kModWasmA);

  // Without crypto.signal-sign the signal signer is not-authorised.
  ModuleRuntime ro(ModDeps(&gb, &cb, nullptr));
  EXPECT_TRUE(ro.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                 {"crypto.commit-sign"}))
                  .ok);
  EXPECT_TRUE(ro.GrantConsent(ch));
  EXPECT_TRUE(
      ro.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(ro.SignSignal(ch, "space://s", "did:key:peer", {1, 2, 3}).error ==
              HostError::kNotAuthorised);

  // With it, a signal envelope is signed.
  ModuleRuntime rw(ModDeps(&gb, &cb, nullptr));
  EXPECT_TRUE(rw.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                {"crypto.signal-sign"}))
                  .ok);
  EXPECT_TRUE(rw.GrantConsent(ch));
  EXPECT_TRUE(
      rw.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  auto s = rw.SignSignal(ch, "space://s", "did:key:peer", {1, 2, 3});
  EXPECT_TRUE(s.ok);
  EXPECT_EQ(s.value.signature.size(), size_t(64));
}

// ---- §8.1 host-storage: quota + per-(module,graph) isolation ----

TEST(Module_HostStorage_QuotaScopeAndIsolation) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));

  const std::string chA = ModContentHash(kModWasmA);
  const std::string chB = ModContentHash(kModWasmB);
  EXPECT_TRUE(rt.Install(kModWasmA, ModManifest("A", "1", chA, {"capability"},
                                                {"storage.module.64"}))
                  .ok);
  EXPECT_TRUE(rt.Install(kModWasmB, ModManifest("B", "1", chB, {"capability"},
                                                {"storage.module.64"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(chA));
  EXPECT_TRUE(rt.GrantConsent(chB));
  EXPECT_TRUE(
      rt.Instantiate(chA, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(
      rt.Instantiate(chB, "space://s", "did:key:local", {"did:graph:g1"}).ok);

  // Within the 64-byte cap ("k"=1 + 63 value = 64): accepted.
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "k",
                            std::vector<uint8_t>(63, 'x'))
                  .ok);
  auto got = rt.StorageGet(chA, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(got.ok);
  EXPECT_TRUE(got.value.has_value());
  EXPECT_EQ(got.value->size(), size_t(63));

  // One more byte exceeds the declared cap (§8.1).
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "k",
                            std::vector<uint8_t>(64, 'y'))
                  .error == HostError::kQuotaExceeded);

  // Module B shares the graph but sees NONE of A's keys (§9.5 isolation).
  auto b = rt.StorageGet(chB, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(b.ok);
  EXPECT_FALSE(b.value.has_value());

  // Storage outside the authorised graph set is unknown-scope.
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:other", "k", {1})
                  .error == HostError::kUnknownScope);

  // Delete frees the accounting so subsequent writes fit; list-keys honours
  // the prefix filter. "k" (64 bytes) must be released before "p1" + "big"
  // (3 + 53 = 56 bytes) can be admitted under the 64-byte cap.
  EXPECT_TRUE(rt.StorageDelete(chA, "space://s", "did:graph:g1", "k").ok);
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "p1", {1}).ok);
  EXPECT_TRUE(rt.StorageSet(chA, "space://s", "did:graph:g1", "big",
                            std::vector<uint8_t>(50, 'z'))
                  .ok);
  auto keys = rt.StorageListKeys(chA, "space://s", "did:graph:g1",
                                 std::optional<std::string>("p"));
  EXPECT_TRUE(keys.ok);
  EXPECT_EQ(keys.value.size(), size_t(1));
  EXPECT_EQ(keys.value[0], std::string("p1"));
}

// ---- §6.3 host-network: capability gating over a loopback transport ----

TEST(Module_HostNetwork_GatingAndTransport) {
  ModNetworkBackend nb;
  ModuleRuntime rt(ModDeps(nullptr, nullptr, &nb));
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"},
                             {"network.relay.wss://relay.example/hub",
                              "network.peer.lw-sync/1",
                              "network.fetch.https://cdn.example/"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {}).ok);

  // Granted relay endpoint: a live connection with real send/receive/close.
  auto conn = rt.NetworkConnect(ch, "space://s", "wss://relay.example/hub",
                                RelayProtocol::kWebSocket);
  EXPECT_TRUE(conn.ok);
  HostError se = HostError::kNone;
  EXPECT_TRUE(conn.value->Send({7, 8, 9}, &se));
  std::vector<uint8_t> rx;
  bool closed = true;
  HostError re = HostError::kNone;
  EXPECT_TRUE(conn.value->Receive(&rx, &closed, &re));
  EXPECT_EQ(rx.size(), size_t(3));
  EXPECT_FALSE(closed);
  conn.value->Close();
  EXPECT_FALSE(conn.value->IsOpen());

  // Un-granted relay endpoint: not-authorised.
  EXPECT_TRUE(rt.NetworkConnect(ch, "space://s", "wss://evil.example/",
                                RelayProtocol::kWebSocket)
                  .error == HostError::kNotAuthorised);

  // Peer protocol match / mismatch.
  EXPECT_TRUE(
      rt.PeerConnect(ch, "space://s", "did:key:peer", "lw-sync/1").ok);
  EXPECT_TRUE(rt.PeerConnect(ch, "space://s", "did:key:peer", "other/9").error ==
              HostError::kNotAuthorised);

  // Fetch is origin-scoped: same origin ok, foreign origin denied.
  auto f = rt.Fetch(ch, "space://s", "https://cdn.example/model.bin");
  EXPECT_TRUE(f.ok);
  EXPECT_GT(f.value.size(), size_t(0));
  EXPECT_TRUE(rt.Fetch(ch, "space://s", "https://evil.example/x").error ==
              HostError::kNotAuthorised);
}

// ---- §6.3 host-clock / host-random gating ----

TEST(Module_HostClockRandom_GatingAndCoarsening) {
  ModuleRuntime rt(ModDeps(nullptr, nullptr, nullptr));
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA,
                 ModManifest("m", "1", ch, {"capability"},
                             {"time.wallclock", "time.monotonic",
                              "random.csprng"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(rt.Instantiate(ch, "space://s", "did:key:local", {}).ok);

  auto wc = rt.NowWallclockMs(ch, "space://s");
  EXPECT_TRUE(wc.ok);
  EXPECT_EQ(wc.value % 1000, uint64_t(0));  // §8 coarsened to 1s
  EXPECT_TRUE(rt.NowMonotonicNs(ch, "space://s").ok);
  auto rnd = rt.GetRandomBytes(ch, "space://s", 16);
  EXPECT_TRUE(rnd.ok);
  EXPECT_EQ(rnd.value.size(), size_t(16));

  // A module without these grants is denied on every clock/random surface.
  const std::string ch2 = ModContentHash(kModWasmB);
  EXPECT_TRUE(
      rt.Install(kModWasmB,
                 ModManifest("m", "1", ch2, {"capability"}, {"graph.read"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch2));
  EXPECT_TRUE(rt.Instantiate(ch2, "space://s", "did:key:local", {}).ok);
  EXPECT_TRUE(rt.NowWallclockMs(ch2, "space://s").error ==
              HostError::kNotAuthorised);
  EXPECT_TRUE(rt.NowMonotonicNs(ch2, "space://s").error ==
              HostError::kNotAuthorised);
  EXPECT_TRUE(rt.GetRandomBytes(ch2, "space://s", 8).error ==
              HostError::kNotAuthorised);
}

// ---- §7.4 / §7.5 lifecycle: suspend, resume, remove (stores preserved) ----

TEST(Module_Lifecycle_SuspendResumeRemovePreservesStores) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(rt.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                {"storage.module.128"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(rt.StorageSet(ch, "space://s", "did:graph:g1", "k",
                            std::vector<uint8_t>{1, 2, 3, 4})
                  .ok);

  // §7.5 suspension stops surface activity.
  EXPECT_TRUE(rt.Suspend(ch, "space://s").ok);
  EXPECT_TRUE(rt.StorageGet(ch, "space://s", "did:graph:g1", "k").error ==
              HostError::kNotAuthorised);
  // Resume restores it without re-instantiation.
  EXPECT_TRUE(rt.Resume(ch, "space://s").ok);
  auto got = rt.StorageGet(ch, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(got.ok);
  EXPECT_TRUE(got.value.has_value());

  // §7.4 removal drops instances + grants but PRESERVES the per-graph store.
  EXPECT_TRUE(rt.Remove(ch));
  EXPECT_FALSE(rt.IsInstalled(ch));
  EXPECT_EQ(rt.InstanceCount(), size_t(0));

  // Re-install + re-consent + re-mount: the preserved store is still there.
  EXPECT_TRUE(rt.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                                {"storage.module.128"}))
                  .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://s", "did:key:local", {"did:graph:g1"}).ok);
  auto revived = rt.StorageGet(ch, "space://s", "did:graph:g1", "k");
  EXPECT_TRUE(revived.ok);
  EXPECT_TRUE(revived.value.has_value());
  EXPECT_EQ(revived.value->size(), size_t(4));

  // Purging after the grace period truly clears it.
  EXPECT_TRUE(rt.PurgeStorage(ch, "did:graph:g1"));
  EXPECT_FALSE(
      rt.StorageGet(ch, "space://s", "did:graph:g1", "k").value.has_value());
}

// ---- §7.3 fork constraint-kind superset precondition ----

TEST(Module_Fork_ConstraintKindSuperset) {
  const std::string ch = ModContentHash(kModWasmA);
  ModuleManifest child;
  std::string err;
  EXPECT_TRUE(ParseModuleManifest(
      ModManifest("child", "2", ch, {"capability", "expiry", "shape"},
                  {"graph.read"}),
      &child, &err));

  std::vector<std::string> missing;
  // Child supports a superset of the parent's in-force kinds → compatible.
  EXPECT_TRUE(ModuleRuntime::ForkCompatible(child, {"capability", "expiry"},
                                            &missing));
  EXPECT_TRUE(missing.empty());

  // A kind the child lacks blocks the fork and is reported.
  EXPECT_FALSE(ModuleRuntime::ForkCompatible(child, {"capability", "geo"},
                                             &missing));
  EXPECT_EQ(missing.size(), size_t(1));
  EXPECT_EQ(missing[0], std::string("geo"));
}

// ---- §4.4 instancing + §7.6 introspection ----

TEST(Module_Instancing_PerSpaceScope) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  gb.AddGraph("did:graph:g2");
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));
  const std::string ch = ModContentHash(kModWasmA);
  EXPECT_TRUE(
      rt.Install(kModWasmA, ModManifest("m", "1", ch, {"capability"},
                                        {"graph.read", "storage.module.64"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(ch));

  // One instance per (content-hash, space-uri); each carries its own scope.
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://A", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(
      rt.Instantiate(ch, "space://B", "did:key:local", {"did:graph:g2"}).ok);
  EXPECT_EQ(rt.InstanceCount(), size_t(2));

  // Space A cannot reach graph g2 (authorised only in space B).
  EXPECT_TRUE(
      rt.ReaderQueryTriples(ch, "space://A", "did:graph:g2", TripleQuery{})
          .error == HostError::kUnknownScope);
  EXPECT_TRUE(
      rt.ReaderQueryTriples(ch, "space://B", "did:graph:g2", TripleQuery{}).ok);
}

TEST(Module_ListModules_Introspection) {
  DIDKeyProvider gp;
  gp.CreateKey("Human");
  ModGraphBackend gb(&gp);
  gb.AddGraph("did:graph:g1");
  ModuleRuntime rt(ModDeps(&gb, nullptr, nullptr));
  const std::string chA = ModContentHash(kModWasmA);
  const std::string chB = ModContentHash(kModWasmB);
  EXPECT_TRUE(
      rt.Install(kModWasmA, ModManifest("Alpha", "1", chA, {"capability"},
                                        {"storage.module.128"}))
          .ok);
  EXPECT_TRUE(
      rt.Install(kModWasmB,
                 ModManifest("Beta", "1", chB, {"capability"}, {"graph.read"}))
          .ok);
  EXPECT_TRUE(rt.GrantConsent(chA));  // Beta stays pending

  EXPECT_TRUE(
      rt.Instantiate(chA, "space://A", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(
      rt.Instantiate(chA, "space://B", "did:key:local", {"did:graph:g1"}).ok);
  EXPECT_TRUE(rt.StorageSet(chA, "space://A", "did:graph:g1", "k",
                            std::vector<uint8_t>(10, 'a'))
                  .ok);

  bool saw_alpha = false, saw_beta = false;
  for (const ModuleStatus& s : rt.ListModules()) {
    if (s.content_hash == chA) {
      saw_alpha = true;
      EXPECT_TRUE(s.consent == ConsentDecision::kGranted);
      EXPECT_EQ(s.space_count, size_t(2));
      EXPECT_GT(s.storage_bytes, uint64_t(0));
      EXPECT_EQ(s.name, std::string("Alpha"));
    } else if (s.content_hash == chB) {
      saw_beta = true;
      EXPECT_TRUE(s.consent == ConsentDecision::kPending);
      EXPECT_EQ(s.space_count, size_t(0));
    }
  }
  EXPECT_TRUE(saw_alpha);
  EXPECT_TRUE(saw_beta);
}

// ============================================================
// Spec 07 — Dynamic Graph Shape Validation
// ============================================================

namespace {

// A well-formed §4 Person shape: three properties (a required scalar `name`, an
// optional scalar `age` typed xsd:integer, an unbounded `knows` collection of
// URIs) and a four-action constructor (the §4.5 rdf://type discriminator plus a
// setter/collection action per property).
constexpr char kPersonShape[] = R"JSON({
  "targetClass": "http://schema.org/Person",
  "properties": [
    {"path": "http://schema.org/name", "name": "name", "datatype": "xsd:string", "minCount": 1, "maxCount": 1},
    {"path": "http://schema.org/age", "name": "age", "datatype": "xsd:integer", "maxCount": 1},
    {"path": "http://schema.org/knows", "name": "knows", "datatype": "URI"}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://schema.org/Person"},
    {"action": "shape://actions/setSingleTarget", "subject": "this", "predicate": "http://schema.org/name", "object": "name"},
    {"action": "shape://actions/setSingleTarget", "subject": "this", "predicate": "http://schema.org/age", "object": "age"},
    {"action": "shape://actions/addCollectionTarget", "subject": "this", "predicate": "http://schema.org/knows", "object": "knows"}
  ]
})JSON";

// A Thing shape exercising every §4.2 setter classification: `title` scalar,
// `locked` read-only (no setter), `tag` unbounded collection.
constexpr char kThingShape[] = R"JSON({
  "targetClass": "http://example.org/Thing",
  "properties": [
    {"path": "http://example.org/title", "name": "title", "datatype": "xsd:string", "minCount": 1, "maxCount": 1},
    {"path": "http://example.org/locked", "name": "locked", "datatype": "xsd:string", "maxCount": 1, "readOnly": true},
    {"path": "http://example.org/tag", "name": "tag", "datatype": "xsd:string"}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Thing"},
    {"action": "shape://actions/setSingleTarget", "subject": "this", "predicate": "http://example.org/title", "object": "title"}
  ]
})JSON";

constexpr char kAnimalShape[] = R"JSON({
  "targetClass": "http://example.org/Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 0, "maxCount": 1}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Animal"}
  ]
})JSON";

// Extends Animal and narrows it (legs becomes required) — a valid §4.6 refinement.
constexpr char kDogShape[] = R"JSON({
  "targetClass": "http://example.org/Dog",
  "extends": "Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 1, "maxCount": 1}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Dog"}
  ]
})JSON";

// Extends Animal but LOOSENS it (maxCount 1 → 4) — an invalid §4.6 extension.
constexpr char kCatShape[] = R"JSON({
  "targetClass": "http://example.org/Cat",
  "extends": "Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 0, "maxCount": 4}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Cat"}
  ]
})JSON";

// A same-name "Animal" shape that strictly narrows the inherited Animal (legs
// minCount 0 → 1) WITHOUT `extends` — a §7.3 local override that shadows the
// inherited definition. Not an extension, so it carries no `extends` key.
constexpr char kAnimalNarrowedShape[] = R"JSON({
  "targetClass": "http://example.org/Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 1, "maxCount": 1}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Animal"}
  ]
})JSON";

ShapePropertyInfo* FindInfoProp(ShapeInfo* s, const std::string& name) {
  for (auto& p : s->properties)
    if (p.name == name)
      return &p;
  return nullptr;
}

ShapeInfo* FindInfo(std::vector<ShapeInfo>* v, const std::string& name) {
  for (auto& s : *v)
    if (s.name == name)
      return &s;
  return nullptr;
}

}  // namespace

// ---- shared core: §4 grammar, §6.3 addressing, §4.4/§4.6 rules ----

TEST(Shape_ParseValidDefinition) {
  ShapeDefinition d;
  std::string err;
  EXPECT_TRUE(ParseShapeDefinition(kPersonShape, &d, &err));
  EXPECT_TRUE(d.valid);
  EXPECT_EQ(d.target_class, std::string("http://schema.org/Person"));
  EXPECT_EQ(d.properties.size(), size_t(3));
  EXPECT_EQ(d.constructor.size(), size_t(4));
  const ShapePropertyDef* name = FindPropertyByName(d, "name");
  EXPECT_TRUE(name != nullptr);
  EXPECT_EQ(name->min_count, 1ul);
  EXPECT_TRUE(name->max_count.has_value() && *name->max_count == 1ul);
  const ShapePropertyDef* knows = FindPropertyByName(d, "knows");
  EXPECT_TRUE(knows != nullptr);
  EXPECT_FALSE(knows->max_count.has_value());  // unbounded collection
  EXPECT_FALSE(d.extends.has_value());
}

TEST(Shape_ParseRejectsMalformed) {
  ShapeDefinition d;
  std::string err;
  // Missing targetClass.
  EXPECT_FALSE(ParseShapeDefinition(
      R"({"properties":[],"constructor":[]})", &d, &err));
  // Property name violating the §4.2 grammar.
  EXPECT_FALSE(ParseShapeDefinition(
      R"({"targetClass":"C","properties":[{"path":"p","name":"1bad"}],"constructor":[]})",
      &d, &err));
  // maxCount < minCount.
  EXPECT_FALSE(ParseShapeDefinition(
      R"({"targetClass":"C","properties":[{"path":"p","name":"x","minCount":3,"maxCount":1}],"constructor":[]})",
      &d, &err));
  // Constructor subject not "this".
  EXPECT_FALSE(ParseShapeDefinition(
      R"({"targetClass":"C","properties":[],"constructor":[{"action":"shape://actions/addLink","subject":"that","predicate":"p","object":"o"}]})",
      &d, &err));
  // Unknown constructor action URI.
  EXPECT_FALSE(ParseShapeDefinition(
      R"({"targetClass":"C","properties":[],"constructor":[{"action":"shape://actions/bogus","subject":"this","predicate":"p","object":"o"}]})",
      &d, &err));
  // Duplicate property name.
  EXPECT_FALSE(ParseShapeDefinition(
      R"({"targetClass":"C","properties":[{"path":"p","name":"x"},{"path":"q","name":"x"}],"constructor":[]})",
      &d, &err));
}

TEST(Shape_PropertyNameGrammar) {
  EXPECT_TRUE(IsValidShapePropertyName("name"));
  EXPECT_TRUE(IsValidShapePropertyName("_x9"));
  EXPECT_TRUE(IsValidShapePropertyName("A_b_2"));
  EXPECT_FALSE(IsValidShapePropertyName(""));
  EXPECT_FALSE(IsValidShapePropertyName("9x"));
  EXPECT_FALSE(IsValidShapePropertyName("has-dash"));
  EXPECT_FALSE(IsValidShapePropertyName("a b"));
}

TEST(Shape_ContentAddressStableAcrossFormatting) {
  // Two byte-different encodings of the same JSON object (key order + spacing).
  const std::string a =
      R"({"targetClass":"C","properties":[],"constructor":[]})";
  const std::string b =
      "{  \"constructor\" : [] ,\n \"properties\":[],  \"targetClass\":\"C\" }";
  auto ca = CanonicalizeShapeJson(a);
  auto cb = CanonicalizeShapeJson(b);
  EXPECT_TRUE(ca.has_value() && cb.has_value());
  EXPECT_EQ(*ca, *cb);  // JCS collapses both to identical bytes
  const std::string addr_a =
      FormatShapeAddress(crypto::SHA256HashString(*ca));
  const std::string addr_b =
      FormatShapeAddress(crypto::SHA256HashString(*cb));
  EXPECT_EQ(addr_a, addr_b);
  EXPECT_TRUE(IsWellFormedShapeAddress(addr_a));
  EXPECT_EQ(addr_a.substr(0, 7), std::string("sha256:"));  // colon, not hyphen
  EXPECT_FALSE(IsWellFormedShapeAddress("sha256:deadbeef"));
  EXPECT_FALSE(CanonicalizeShapeJson("not json").has_value());
}

TEST(Shape_NormalizeAndValidateDatatype) {
  EXPECT_EQ(NormalizeDatatype("xsd:integer"),
            std::string("http://www.w3.org/2001/XMLSchema#integer"));
  EXPECT_EQ(NormalizeDatatype("URI"), std::string("URI"));
  EXPECT_EQ(NormalizeDatatype("http://example.org/custom"),
            std::string("http://example.org/custom"));
  EXPECT_TRUE(IsUriDatatype(NormalizeDatatype("URI")));
  EXPECT_FALSE(IsUriDatatype(NormalizeDatatype("xsd:string")));

  EXPECT_TRUE(ValidateLexicalForDatatype("42", NormalizeDatatype("xsd:integer")));
  EXPECT_FALSE(ValidateLexicalForDatatype("4.5", NormalizeDatatype("xsd:integer")));
  EXPECT_TRUE(ValidateLexicalForDatatype("true", NormalizeDatatype("xsd:boolean")));
  EXPECT_FALSE(ValidateLexicalForDatatype("yes", NormalizeDatatype("xsd:boolean")));
  EXPECT_TRUE(ValidateLexicalForDatatype("2026-07-08T00:00:00Z",
                                         NormalizeDatatype("xsd:dateTime")));
  EXPECT_FALSE(ValidateLexicalForDatatype("not-a-date",
                                          NormalizeDatatype("xsd:dateTime")));
  EXPECT_TRUE(ValidateLexicalForDatatype("did:example:x",
                                         NormalizeDatatype("URI")));
  EXPECT_FALSE(ValidateLexicalForDatatype("has space",
                                          NormalizeDatatype("URI")));
  EXPECT_TRUE(ValidateLexicalForDatatype("-5", NormalizeDatatype("xsd:integer")));
  EXPECT_FALSE(ValidateLexicalForDatatype(
      "-5", NormalizeDatatype("xsd:nonNegativeInteger")));
}

TEST(Shape_SetterClassification) {
  ShapeDefinition d;
  std::string err;
  EXPECT_TRUE(ParseShapeDefinition(kThingShape, &d, &err));
  EXPECT_EQ(int(SetterKindFor(*FindPropertyByName(d, "title"))),
            int(SetterKind::kScalar));
  EXPECT_EQ(int(SetterKindFor(*FindPropertyByName(d, "locked"))),
            int(SetterKind::kNone));  // readOnly → no setter
  EXPECT_EQ(int(SetterKindFor(*FindPropertyByName(d, "tag"))),
            int(SetterKind::kCollection));  // unbounded
}

TEST(Shape_NarrowingRule) {
  ShapeDefinition parent, dog, cat;
  std::string err;
  EXPECT_TRUE(ParseShapeDefinition(kAnimalShape, &parent, &err));
  EXPECT_TRUE(ParseShapeDefinition(kDogShape, &dog, &err));
  EXPECT_TRUE(ParseShapeDefinition(kCatShape, &cat, &err));
  std::string reason;
  EXPECT_TRUE(ShapeNarrows(parent, dog, &reason));   // tightened minCount
  EXPECT_FALSE(ShapeNarrows(parent, cat, &reason));  // loosened maxCount
  EXPECT_FALSE(reason.empty());
}

TEST(Shape_ConstructorKeyAliases) {
  // The §12 source/target aliases parse to the canonical subject/object fields.
  const char kAlias[] = R"({
    "targetClass": "C",
    "properties": [{"path": "p", "name": "x"}],
    "constructor": [{"action": "shape://actions/setSingleTarget", "source": "this", "predicate": "p", "target": "x"}]
  })";
  ShapeDefinition d;
  std::string err;
  EXPECT_TRUE(ParseShapeDefinition(kAlias, &d, &err));
  EXPECT_EQ(d.constructor.size(), size_t(1));
  EXPECT_EQ(d.constructor[0].subject, std::string("this"));
  EXPECT_EQ(d.constructor[0].object, std::string("x"));
}

// ---- §5 service: registration, storage, listing ----

TEST(Shape_AddShapeStoresAndLists) {
  GovFixture f;  // open mode: no capability constraint installed
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));

  auto shapes = svc.GetShapes(f.W());
  EXPECT_EQ(shapes.size(), size_t(1));
  ShapeInfo* p = FindInfo(&shapes, "Person");
  EXPECT_TRUE(p != nullptr);
  EXPECT_EQ(p->target_class, std::string("http://schema.org/Person"));
  EXPECT_EQ(p->source_graph_did, f.Wdid());  // registered locally
  EXPECT_TRUE(IsWellFormedShapeAddress(p->definition_address));
  EXPECT_EQ(p->properties.size(), size_t(3));
  EXPECT_TRUE(FindInfoProp(p, "name") != nullptr);
}

TEST(Shape_DuplicateNameConstraintError) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));
  EXPECT_FALSE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));
  EXPECT_EQ(svc.last_error(), std::string("ConstraintError"));
}

TEST(Shape_MalformedSyntaxError) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_FALSE(svc.AddShape(f.W(), "Bad", "{not a shape", f.gcred));
  EXPECT_EQ(svc.last_error(), std::string("SyntaxError"));
}

TEST(Shape_UnknownAuthorInvalidState) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_FALSE(svc.AddShape(f.W(), "Person", kPersonShape, "urn:uuid:nope"));
  EXPECT_EQ(svc.last_error(), std::string("InvalidStateError"));
}

TEST(Shape_ExtendsNarrowingEnforced) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Animal", kAnimalShape, f.gcred));
  EXPECT_TRUE(svc.AddShape(f.W(), "Dog", kDogShape, f.gcred));  // valid narrowing
  EXPECT_FALSE(svc.AddShape(f.W(), "Cat", kCatShape, f.gcred));  // loosens
  EXPECT_EQ(svc.last_error(), std::string("ConstraintError"));
  // extends an unresolvable parent name → ConstraintError.
  const char kGhost[] = R"({"targetClass":"G","extends":"Nonexistent","properties":[],"constructor":[]})";
  EXPECT_FALSE(svc.AddShape(f.W(), "Ghost", kGhost, f.gcred));
  EXPECT_EQ(svc.last_error(), std::string("ConstraintError"));
}

TEST(Shape_RemoveShape) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));
  EXPECT_EQ(svc.GetShapes(f.W()).size(), size_t(1));
  EXPECT_TRUE(svc.RemoveShape(f.W(), "Person", f.gcred));
  EXPECT_EQ(svc.GetShapes(f.W()).size(), size_t(0));
  // Removing a shape that was never registered is a no-op success.
  EXPECT_TRUE(svc.RemoveShape(f.W(), "Ghost", f.gcred));
}

// ---- §5.5/§5.6 instance construction + query ----

TEST(Shape_CreateInstanceExecutesConstructor) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));

  std::string inst;
  std::map<std::string, std::string> vals = {
      {"name", "Ada Lovelace"}, {"age", "36"}, {"knows", "did:example:bob"}};
  EXPECT_TRUE(svc.CreateShapeInstance(f.W(), "Person", "", vals, f.gcred, &inst));
  EXPECT_EQ(inst.substr(0, 9), std::string("urn:uuid:"));

  std::vector<std::string> instances;
  EXPECT_TRUE(svc.GetShapeInstances(f.W(), "Person", &instances));
  EXPECT_EQ(instances.size(), size_t(1));
  EXPECT_EQ(instances[0], inst);  // matched via the rdf://type IRI discriminator

  ShapeInstanceData data;
  EXPECT_TRUE(svc.GetShapeInstanceData(f.W(), "Person", inst, &data));
  EXPECT_EQ(data["name"].size(), size_t(1));
  EXPECT_EQ(data["name"][0], std::string("Ada Lovelace"));
  EXPECT_EQ(data["age"][0], std::string("36"));
  EXPECT_EQ(data["knows"][0], std::string("did:example:bob"));  // URI → IRI term
}

TEST(Shape_CreateInstanceRequiredMissingTypeError) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));
  std::string inst;
  std::map<std::string, std::string> vals = {{"age", "36"}};  // no required name
  EXPECT_FALSE(
      svc.CreateShapeInstance(f.W(), "Person", "", vals, f.gcred, &inst));
  EXPECT_EQ(svc.last_error(), std::string("TypeError"));
}

TEST(Shape_CreateInstanceDatatypeTypeError) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "X"}, {"age", "notanumber"}};
  EXPECT_FALSE(
      svc.CreateShapeInstance(f.W(), "Person", "", vals, f.gcred, &inst));
  EXPECT_EQ(svc.last_error(), std::string("TypeError"));
}

TEST(Shape_CreateInstanceUnknownShapeNotFound) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "X"}};
  EXPECT_FALSE(
      svc.CreateShapeInstance(f.W(), "Nope", "", vals, f.gcred, &inst));
  EXPECT_EQ(svc.last_error(), std::string("NotFoundError"));
}

// ---- §5.7 setters + collection operations ----

TEST(Shape_ScalarSetterAndGuards) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Thing", kThingShape, f.gcred));
  std::string inst;
  std::map<std::string, std::string> vals = {{"title", "Hello"}};
  EXPECT_TRUE(svc.CreateShapeInstance(f.W(), "Thing", "", vals, f.gcred, &inst));

  // Scalar setter replaces the single value.
  EXPECT_TRUE(
      svc.SetShapeProperty(f.W(), "Thing", inst, "title", "World", f.gcred));
  ShapeInstanceData data;
  EXPECT_TRUE(svc.GetShapeInstanceData(f.W(), "Thing", inst, &data));
  EXPECT_EQ(data["title"].size(), size_t(1));
  EXPECT_EQ(data["title"][0], std::string("World"));

  // Read-only property: no setter (§4.2).
  EXPECT_FALSE(
      svc.SetShapeProperty(f.W(), "Thing", inst, "locked", "x", f.gcred));
  EXPECT_EQ(svc.last_error(), std::string("NoModificationAllowedError"));

  // Collection property via the scalar setter → wrong accessor.
  EXPECT_FALSE(
      svc.SetShapeProperty(f.W(), "Thing", inst, "tag", "x", f.gcred));
  EXPECT_EQ(svc.last_error(), std::string("InvalidAccessError"));
}

TEST(Shape_CollectionAddRemove) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Thing", kThingShape, f.gcred));
  std::string inst;
  std::map<std::string, std::string> vals = {{"title", "T"}};
  EXPECT_TRUE(svc.CreateShapeInstance(f.W(), "Thing", "", vals, f.gcred, &inst));

  EXPECT_TRUE(
      svc.AddToShapeCollection(f.W(), "Thing", inst, "tag", "red", f.gcred));
  EXPECT_TRUE(
      svc.AddToShapeCollection(f.W(), "Thing", inst, "tag", "blue", f.gcred));
  ShapeInstanceData data;
  EXPECT_TRUE(svc.GetShapeInstanceData(f.W(), "Thing", inst, &data));
  EXPECT_EQ(data["tag"].size(), size_t(2));

  EXPECT_TRUE(
      svc.RemoveFromShapeCollection(f.W(), "Thing", inst, "tag", "red", f.gcred));
  data.clear();
  EXPECT_TRUE(svc.GetShapeInstanceData(f.W(), "Thing", inst, &data));
  EXPECT_EQ(data["tag"].size(), size_t(1));
  EXPECT_EQ(data["tag"][0], std::string("blue"));

  // The scalar `title` rejects collection operations.
  EXPECT_FALSE(
      svc.AddToShapeCollection(f.W(), "Thing", inst, "title", "x", f.gcred));
  EXPECT_EQ(svc.last_error(), std::string("InvalidAccessError"));
}

// ---- §5.2/§10.4 updateSHACL authorisation under enforcement ----

TEST(Shape_UpdateShaclRequiredUnderEnforcement) {
  GovFixture f;
  BootstrapEnforced(f);  // root holds the 8 framework-core actions, NOT updateSHACL
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_FALSE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));
  EXPECT_EQ(svc.last_error(), std::string("NotAllowedError"));
}

TEST(Shape_UpdateShaclGrantedUnderEnforcement) {
  GovFixture f;
  // Mint the root WITH the updateSHACL extension action (+ the write actions the
  // constructor needs + updateGovernance, which BootstrapEnforced's
  // SetEnforcementMode requires once a capability constraint is installed).
  BootstrapEnforced(f, std::vector<std::string>{"createLink", "removeLink",
                                                "updateSHACL", "updateGovernance"});
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "Grace"}};
  EXPECT_TRUE(svc.CreateShapeInstance(f.W(), "Person", "", vals, f.gcred, &inst));
}

// ---- §7 cross-graph inheritance + §10.5 tamper defence ----

TEST(Shape_InheritanceRequiresAcceptance) {
  GovFixture f;  // f.group is the PARENT context
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Person", kPersonShape, f.gcred));

  // A child context that unilaterally declares participation in the parent.
  GroupCreationOptions co;
  co.sync_module = "urn:sync:module:default";
  co.display_name = "Child";
  co.participates_in = f.Wdid();
  std::unique_ptr<Group> child = f.groups.CreateGroup(co);
  EXPECT_TRUE(child != nullptr);
  Graph* C = child->graph();
  const std::string ccred = CredIdForDid(f.provider, child->did());

  // §10.5: without the parent's acceptance the inherited shape is invisible.
  EXPECT_EQ(svc.GetShapes(C).size(), size_t(0));
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "X"}};
  EXPECT_FALSE(svc.CreateShapeInstance(C, "Person", "", vals, ccred, &inst));
  EXPECT_EQ(svc.last_error(), std::string("NotFoundError"));

  // Parent accepts the child (authored by a capabilityDelegation delegate).
  f.group->SetActingCredential(f.gcred);
  EXPECT_TRUE(f.group->Invite(child->did()));

  // Now the shape is inherited and instantiable in the child, and construction
  // triples land in the CHILD graph (§5.5 step 4).
  auto shapes = svc.GetShapes(C);
  EXPECT_EQ(shapes.size(), size_t(1));
  ShapeInfo* p = FindInfo(&shapes, "Person");
  EXPECT_TRUE(p != nullptr);
  EXPECT_EQ(p->source_graph_did, f.Wdid());  // sourced from the parent
  EXPECT_TRUE(svc.CreateShapeInstance(C, "Person", "", vals, ccred, &inst));
  std::vector<std::string> in_child;
  EXPECT_TRUE(svc.GetShapeInstances(C, "Person", &in_child));
  EXPECT_EQ(in_child.size(), size_t(1));
  // The parent graph holds no instances of its own.
  std::vector<std::string> in_parent;
  EXPECT_TRUE(svc.GetShapeInstances(f.W(), "Person", &in_parent));
  EXPECT_EQ(in_parent.size(), size_t(0));
}

TEST(Shape_LocalOverridesInherited) {
  GovFixture f;
  ShapeService svc(&f.provider, &f.gov, &f.groups);
  EXPECT_TRUE(svc.AddShape(f.W(), "Animal", kAnimalShape, f.gcred));

  GroupCreationOptions co;
  co.sync_module = "urn:sync:module:default";
  co.display_name = "Child";
  co.participates_in = f.Wdid();
  std::unique_ptr<Group> child = f.groups.CreateGroup(co);
  Graph* C = child->graph();
  const std::string ccred = CredIdForDid(f.provider, child->did());
  f.group->SetActingCredential(f.gcred);
  EXPECT_TRUE(f.group->Invite(child->did()));

  // Child registers a same-name shape that strictly narrows the inherited one.
  EXPECT_TRUE(svc.AddShape(C, "Animal", kAnimalNarrowedShape, ccred));

  auto shapes = svc.GetShapes(C);
  ShapeInfo* a = FindInfo(&shapes, "Animal");
  EXPECT_TRUE(a != nullptr);
  EXPECT_EQ(a->source_graph_did, child->did());  // local shadows inherited (§7.3)
  ShapePropertyInfo* legs = FindInfoProp(a, "legs");
  EXPECT_TRUE(legs != nullptr);
  EXPECT_EQ(legs->min_count, 1ul);  // the child's tightened constraint
}

// ============================================================
// Spec 08 — Governance Constraint Vocabulary
// ============================================================

namespace {

// Installs a graph constraint of |kind| carrying the given (predicate,
// literal-object) defining triples, authored by |cred|, and binds it to the
// graph DID via governance://has_constraint (Spec 04 §4.2 — a constraint binds
// to the graph it governs and applies to every write in that graph; the handler
// decides pass/fail from the current author's own state, Spec 08 §3).
void InstallKindConstraint(
    GovFixture& f, const std::string& cred, const std::string& kind,
    const std::string& cid,
    const std::vector<std::pair<std::string, std::string>>& props) {
  group_detail::ScopedActive active(&f.provider, cred);
  std::vector<Triple> t = {
      group_detail::T_iri(cid, kGovEntryType, kGovConstraintEntryType),
      group_detail::T_lit(cid, kGovConstraintKind, kind),
  };
  for (const auto& kv : props)
    t.push_back(group_detail::T_lit(cid, kv.first, kv.second));
  t.push_back(group_detail::T_iri(f.Wdid(), kGovHasConstraint, cid));
  EXPECT_TRUE(f.W()->AddTriples(t));
}

// Writes |triple| into W authored by |cred| (recording a reifier the temporal /
// authorOnly provenance queries read back). AddTriple bypasses governance, so
// this seeds history in any enforcement mode.
void WriteAs(GovFixture& f, const std::string& cred, const Triple& triple) {
  group_detail::ScopedActive active(&f.provider, cred);
  EXPECT_TRUE(f.W()->AddTriple(triple));
}

// Delegates a createLink capability to |invoker_did| under |caveats| JSON,
// returning the child capability id (assumes BootstrapEnforced already ran).
std::string DelegateWithCaveats(GovFixture& f, const std::string& root,
                                const std::string& invoker_did,
                                const std::string& caveats) {
  DelegationRequest req;
  req.parent_capability = root;
  req.invoker = invoker_did;
  req.actions = {kActionCreateLink};
  req.caveats = caveats;
  std::string child;
  EXPECT_TRUE(f.gov.Delegate(f.W(), f.gcred, req, &child));
  return child;
}

}  // namespace

// ---- pure decision core (constraint_vocabulary.{h,cc}) ----

TEST(Gov_CoreGlobMatch) {
  EXPECT_TRUE(constraint_vocab::GlobMatch("a*c", "abbbc"));
  EXPECT_TRUE(constraint_vocab::GlobMatch("*", "anything"));
  EXPECT_TRUE(constraint_vocab::GlobMatch("exact", "exact"));
  EXPECT_FALSE(constraint_vocab::GlobMatch("exact", "exactly"));
  EXPECT_TRUE(constraint_vocab::GlobMatch("did:key:*", "did:key:z6Mk1"));
  EXPECT_FALSE(constraint_vocab::GlobMatch("did:key:*", "did:web:example"));
  EXPECT_TRUE(constraint_vocab::GlobMatch("*.example.com", "a.b.example.com"));
  EXPECT_FALSE(constraint_vocab::GlobMatch("*.example.com", "example.org"));
}

TEST(Gov_CoreEvalAllowDeny) {
  using AD = constraint_vocab::AllowDeny;
  // Deny-only: anything not denied is accepted (§7.2).
  EXPECT_TRUE(constraint_vocab::EvalAllowDeny({}, {"x"}, "y") == AD::kAccept);
  EXPECT_TRUE(constraint_vocab::EvalAllowDeny({}, {"x"}, "x") == AD::kDenied);
  // Allow-list restricts to its members.
  EXPECT_TRUE(constraint_vocab::EvalAllowDeny({"a"}, {}, "a") == AD::kAccept);
  EXPECT_TRUE(constraint_vocab::EvalAllowDeny({"a"}, {}, "b") == AD::kNotAllowed);
  // Deny wins over allow (§7.2 deny-wins).
  EXPECT_TRUE(constraint_vocab::EvalAllowDeny({"a"}, {"a"}, "a") == AD::kDenied);
}

TEST(Gov_CoreRfc3339ToEpoch) {
  int64_t e = -1;
  EXPECT_TRUE(constraint_vocab::ParseRfc3339ToEpoch("1970-01-01T00:00:00Z", &e));
  EXPECT_EQ(e, int64_t(0));
  EXPECT_TRUE(constraint_vocab::ParseRfc3339ToEpoch("2000-01-01T00:00:00Z", &e));
  EXPECT_EQ(e, int64_t(946684800));
  // A numeric offset is honoured.
  EXPECT_TRUE(
      constraint_vocab::ParseRfc3339ToEpoch("2000-01-01T00:00:00+00:00", &e));
  EXPECT_EQ(e, int64_t(946684800));
  EXPECT_FALSE(constraint_vocab::ParseRfc3339ToEpoch("not-a-date", &e));
  EXPECT_FALSE(constraint_vocab::ParseRfc3339ToEpoch("2000-01-01", &e));
}

TEST(Gov_CorePlausibility) {
  // Within the +300 s future bound → plausible (§5.3 check 1).
  constraint_vocab::PlausibilityInput ok;
  ok.t = "2026-01-01T00:00:10Z";
  ok.now = "2026-01-01T00:00:00Z";
  EXPECT_TRUE(constraint_vocab::CheckTimestampPlausibility(ok).ok);
  // Beyond the bound → future-bound reject.
  constraint_vocab::PlausibilityInput future;
  future.t = "2026-01-01T01:00:00Z";
  future.now = "2026-01-01T00:00:00Z";
  auto fb = constraint_vocab::CheckTimestampPlausibility(future);
  EXPECT_FALSE(fb.ok);
  EXPECT_EQ(fb.reason, "future-bound");
  // A timestamp earlier than a resolved parent → causal-monotonicity reject.
  constraint_vocab::PlausibilityInput causal;
  causal.t = "2026-01-01T00:00:00Z";
  causal.now = "2026-01-01T00:00:00Z";
  causal.parent_timestamps = {"2026-01-01T00:01:00Z"};
  auto cm = constraint_vocab::CheckTimestampPlausibility(causal);
  EXPECT_FALSE(cm.ok);
  EXPECT_EQ(cm.reason, "causal-monotonicity");
}

TEST(Gov_CoreContentPolicyOrder) {
  cv::RegexMatcher matcher = MakeStdRegexMatcher();
  constraint_vocab::ContentPolicy p;
  p.max_length = 5;
  EXPECT_FALSE(constraint_vocab::EvaluateContentText(p, "toolong", matcher).allowed);
  EXPECT_TRUE(constraint_vocab::EvaluateContentText(p, "ok", matcher).allowed);
  // Blocked pattern (§6.2 step 4) fires after length.
  constraint_vocab::ContentPolicy b;
  b.blocked_patterns = {"bad[0-9]+"};
  auto r = constraint_vocab::EvaluateContentText(b, "contains bad42 here", matcher);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.reason, "blocked-pattern");
  EXPECT_TRUE(constraint_vocab::EvaluateContentText(b, "all clean", matcher).allowed);
  // URL policy + domain whitelist (§6.2 steps 5-6).
  constraint_vocab::ContentPolicy u;
  u.allow_urls = false;
  EXPECT_FALSE(
      constraint_vocab::EvaluateContentText(u, "go http://x.example/y", matcher)
          .allowed);
  constraint_vocab::ContentPolicy d;
  d.allow_urls = true;
  d.allowed_domains = {"example.com"};
  EXPECT_TRUE(constraint_vocab::EvaluateContentText(
                  d, "see https://example.com/a", matcher)
                  .allowed);
  EXPECT_FALSE(constraint_vocab::EvaluateContentText(
                   d, "see https://evil.example/a", matcher)
                   .allowed);
}

TEST(Gov_CoreVcPreimageDeterministic) {
  constraint_vocab::LivingWebVc vc;
  vc.types = {"VerifiableCredential", "EmailVerified"};
  vc.issuer = "did:key:zIssuer";
  vc.issuance_date = "2020-01-01T00:00:00Z";
  vc.subject_id = "did:key:zSubject";
  vc.status_id = "urn:status:1";
  vc.proof_purpose = "assertionMethod";
  vc.proof_created = "2020-01-01T00:00:00Z";
  vc.proof_method = "did:key:zIssuer";
  const std::string expected =
      "living-web/vc/credential/v1\n"
      "VerifiableCredential,EmailVerified\n"
      "did:key:zIssuer\n"
      "2020-01-01T00:00:00Z\n"
      "did:key:zSubject\n"
      "urn:status:1\n"
      "assertionMethod\n"
      "2020-01-01T00:00:00Z\n"
      "did:key:zIssuer";
  EXPECT_EQ(constraint_vocab::BuildVcProofPreimage(vc), expected);
}

TEST(Gov_UsageLedgerWindowAndLifetime) {
  UsageLedger led;
  // §7.5 sliding window: max 2 uses in a 100 s window.
  EXPECT_TRUE(led.CheckAndRecordRate("z", "a", 2, 100, 1000));
  EXPECT_TRUE(led.CheckAndRecordRate("z", "a", 2, 100, 1050));
  EXPECT_FALSE(led.CheckAndRecordRate("z", "a", 2, 100, 1090));  // 2 already
  EXPECT_TRUE(led.CheckAndRecordRate("z", "a", 2, 100, 1200));   // window slid
  // A different author has an independent counter.
  EXPECT_TRUE(led.CheckAndRecordRate("z", "b", 2, 100, 1090));
  // A non-positive bound admits nothing.
  EXPECT_FALSE(led.CheckAndRecordRate("z", "a", 0, 100, 2000));
  // §7.6 lifetime cap.
  EXPECT_TRUE(led.CheckAndRecordCardinality("c", "a", 2));
  EXPECT_TRUE(led.CheckAndRecordCardinality("c", "a", 2));
  EXPECT_FALSE(led.CheckAndRecordCardinality("c", "a", 2));
  EXPECT_TRUE(led.CheckAndRecordCardinality("c", "b", 2));  // distinct author
}

TEST(Gov_StdRegexMatcherMatchNoMatchTimeout) {
  cv::RegexMatcher m = MakeStdRegexMatcher(200);
  EXPECT_TRUE(m("ab+c", "xxabbbcyy") == cv::RegexOutcome::kMatch);
  EXPECT_TRUE(m("^zzz$", "abc") == cv::RegexOutcome::kNoMatch);
  // A pathological pattern against a non-matching input forces catastrophic
  // backtracking in std::regex; the bounded matcher must return kTimeout rather
  // than block, and MUST NOT report a (false) match (§9.3).
  cv::RegexMatcher slow = MakeStdRegexMatcher(50);
  const std::string evil = std::string(50, 'a') + "b";
  EXPECT_TRUE(slow("(a+)+$", evil) == cv::RegexOutcome::kTimeout);
}

// ---- §4 credential constraint ----

TEST(Gov_CredentialConstraintHolderVsStranger) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto issuer = f.provider.CreateKey("Issuer");
  auto holder = f.provider.CreateKey("Holder");
  auto stranger = f.provider.CreateKey("Stranger");

  const std::string vc = MakeSignedLivingWebVc(
      &f.provider, issuer->id, issuer->did, {"EmailVerified"}, holder->did,
      "2020-01-01T00:00:00Z");
  std::string addr;
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(StoreCredential(f.W(), holder->did, vc, &addr));
  }
  // One graph-wide credential requirement governs every writer (Spec 04 §4.2);
  // the handler decides per-author from each writer's own held credentials.
  InstallKindConstraint(
      f, f.gcred, constraint_vocab::kKindCredential, "urn:uuid:cred-c1",
      {{constraint_vocab::kGovRequiresCredentialType, "EmailVerified"}});
  // The holder presents a matching, valid credential → allowed.
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 holder->did)
                  .allowed);
  // The stranger, under the same requirement, holds nothing → rejected.
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                              stranger->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "credential");
  EXPECT_EQ(r.reason, "credential_required");
}

TEST(Gov_CredentialConstraintIssuerFreshnessRevocation) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto issuer = f.provider.CreateKey("Issuer");
  auto holder = f.provider.CreateKey("Holder");
  const std::string status = "urn:status:cred:kyc";

  const std::string vc = MakeSignedLivingWebVc(
      &f.provider, issuer->id, issuer->did, {"KYC"}, holder->did,
      "2020-01-01T00:00:00Z", status);
  std::string addr;
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(StoreCredential(f.W(), holder->did, vc, &addr));
  }
  InstallKindConstraint(
      f, f.gcred, constraint_vocab::kKindCredential, "urn:uuid:cred-r",
      {{constraint_vocab::kGovRequiresCredentialType, "KYC"},
       {constraint_vocab::kGovCredentialIssuerPattern, issuer->did},
       {constraint_vocab::kGovCredentialMinAgeHours, "24"}});
  // Matching issuer, older than 24 h, not revoked → allowed.
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 holder->did)
                  .allowed);
  // Revoking the credential's status subject flips it to rejected (§4.2.2.7).
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(RevokeCredentialStatus(f.W(), status));
  }
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                                  holder->did)
                   .allowed);
}

// ---- §5 temporal constraint ----

TEST(Gov_TemporalConstraintInterval) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  // A prior matching write event, ~now.
  WriteAs(f, w->id, MakeLit("urn:e:1", "urn:p:post", "first"));
  InstallKindConstraint(
      f, f.gcred, constraint_vocab::kKindTemporal, "urn:uuid:temporal-i",
      {{constraint_vocab::kGovTemporalMinIntervalSeconds, "3600"},
       {constraint_vocab::kGovTemporalAppliesToPredicates, "urn:p:post"}});
  // A second write < 3600 s after the first → interval reject (§5.2.3.3).
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:e:2", "urn:p:post", "second"),
                              w->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "temporal");
  EXPECT_EQ(r.reason, "temporal_interval");
  // A predicate outside applies-to is out of scope → allowed (§5.2.3.1).
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:e:3", "urn:p:other", "x"),
                                 w->did)
                  .allowed);
}

TEST(Gov_TemporalConstraintWindowCount) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  WriteAs(f, w->id, MakeLit("urn:e:1", "urn:p:post", "a"));
  WriteAs(f, w->id, MakeLit("urn:e:2", "urn:p:post", "b"));
  InstallKindConstraint(
      f, f.gcred, constraint_vocab::kKindTemporal, "urn:uuid:temporal-w",
      {{constraint_vocab::kGovTemporalMaxCountPerWindow, "2"},
       {constraint_vocab::kGovTemporalWindowSeconds, "3600"},
       {constraint_vocab::kGovTemporalAppliesToPredicates, "urn:p:post"}});
  // Two prior events already fill the window → the third is rejected (§5.2.3.4).
  auto r = f.gov.CanAddTriple(f.W(), MakeLit("urn:e:3", "urn:p:post", "c"),
                              w->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.reason, "temporal_window");
}

// ---- §6 content constraint ----

TEST(Gov_ContentConstraintLength) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  InstallKindConstraint(
      f, f.gcred, constraint_vocab::kKindContent, "urn:uuid:content-len",
      {{constraint_vocab::kGovContentMaxLength, "8"},
       {constraint_vocab::kGovContentAppliesToPredicates, "urn:p:body"}});
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "short"),
                                 w->did)
                  .allowed);
  auto r = f.gov.CanAddTriple(
      f.W(), MakeLit("urn:n:2", "urn:p:body", "way too long"), w->did);
  EXPECT_FALSE(r.allowed);
  EXPECT_EQ(r.constraint_kind, "content");
  // Out-of-scope predicate is unaffected by the length rule.
  EXPECT_TRUE(f.gov.CanAddTriple(
                  f.W(), MakeLit("urn:n:3", "urn:p:other", "way too long"),
                  w->did)
                  .allowed);
}

TEST(Gov_ContentConstraintBlockedPattern) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto w = f.provider.CreateKey("Writer");
  InstallKindConstraint(
      f, f.gcred, constraint_vocab::kKindContent, "urn:uuid:content-pat",
      {{constraint_vocab::kGovContentBlockedPatterns, "badword|forbidden"},
       {constraint_vocab::kGovContentAppliesToPredicates, "urn:p:body"}});
  EXPECT_FALSE(f.gov.CanAddTriple(
                   f.W(), MakeLit("urn:n:1", "urn:p:body", "has a badword in it"),
                   w->did)
                   .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(
                  f.W(), MakeLit("urn:n:2", "urn:p:body", "totally clean text"),
                  w->did)
                  .allowed);
}

TEST(Gov_ContentConstraintUrlPolicyAndDomain) {
  // A content constraint binds to the graph and governs every write (Spec 04
  // §4.2), so the two conflicting URL policies below live in two graphs.
  {
    GovFixture f;
    RegisterConstraintVocabulary(&f.gov);
    auto w = f.provider.CreateKey("Writer");
    // Disallow URLs entirely.
    InstallKindConstraint(
        f, f.gcred, constraint_vocab::kKindContent, "urn:uuid:content-url",
        {{constraint_vocab::kGovContentAllowUrls, "false"},
         {constraint_vocab::kGovContentAppliesToPredicates, "urn:p:body"}});
    EXPECT_FALSE(
        f.gov.CanAddTriple(
             f.W(), MakeLit("urn:n:1", "urn:p:body", "go http://evil.example/x"),
             w->did)
            .allowed);
    EXPECT_TRUE(f.gov.CanAddTriple(f.W(),
                                   MakeLit("urn:n:2", "urn:p:body", "no link"),
                                   w->did)
                    .allowed);
  }

  // A second graph permits URLs but only to a whitelisted domain.
  {
    GovFixture f;
    RegisterConstraintVocabulary(&f.gov);
    auto w = f.provider.CreateKey("Writer");
    InstallKindConstraint(
        f, f.gcred, constraint_vocab::kKindContent, "urn:uuid:content-dom",
        {{constraint_vocab::kGovContentAllowUrls, "true"},
         {constraint_vocab::kGovContentAllowedDomains, "example.com"},
         {constraint_vocab::kGovContentAppliesToPredicates, "urn:p:body"}});
    EXPECT_TRUE(
        f.gov.CanAddTriple(
             f.W(), MakeLit("urn:n:3", "urn:p:body", "see https://example.com/a"),
             w->did)
            .allowed);
    EXPECT_FALSE(
        f.gov.CanAddTriple(
             f.W(), MakeLit("urn:n:4", "urn:p:body", "see https://evil.example/a"),
             w->did)
            .allowed);
  }
}

// ---- §7 caveat types ----

TEST(Gov_PredicateCaveatDenyWins) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"predicate\",\"value\":{\"denied\":[\"urn:p:secret\"]}}]");
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(),
                                  MakeLit("urn:n:1", "urn:p:secret", "x"), m->did)
                   .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:ok", "x"),
                                 m->did)
                  .allowed);
}

TEST(Gov_PropertyCaveatAllowList) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"property\",\"value\":{\"allowed\":[\"urn:p:ok\"]}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:ok", "x"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:other", "x"),
                                  m->did)
                   .allowed);
}

TEST(Gov_SubjectGlobCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"subject\",\"value\":{\"pattern\":\"urn:allowed:*\"}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:allowed:1", "urn:p:body", "x"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:other:1", "urn:p:body", "x"),
                                  m->did)
                   .allowed);
}

TEST(Gov_ObjectGlobCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"object\",\"value\":{\"pattern\":\"https://good.example/*\"}}]");
  EXPECT_TRUE(
      f.gov.CanAddTriple(
           f.W(), MakeIri("urn:n:1", "urn:p:ref", "https://good.example/a"),
           m->did)
          .allowed);
  EXPECT_FALSE(
      f.gov.CanAddTriple(
           f.W(), MakeIri("urn:n:2", "urn:p:ref", "https://bad.example/a"),
           m->did)
          .allowed);
}

TEST(Gov_RateLimitCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"rateLimit\",\"value\":{\"maxPerWindow\":2,"
      "\"windowSeconds\":3600}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "a"),
                                 m->did)
                  .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "b"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:3", "urn:p:body", "c"),
                                  m->did)
                   .allowed);
}

TEST(Gov_CardinalityCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(f, root, m->did,
                      "[{\"type\":\"cardinality\",\"value\":{\"max\":2}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "a"),
                                 m->did)
                  .allowed);
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "b"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:3", "urn:p:body", "c"),
                                  m->did)
                   .allowed);
}

TEST(Gov_AuthorOnlyCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  // The group DID introduces urn:doc:1 (its author of record).
  WriteAs(f, f.gcred, MakeLit("urn:doc:1", "urn:p:body", "original"));
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(f, root, m->did, "[{\"type\":\"authorOnly\"}]");
  // M is not urn:doc:1's author of record → rejected (§7.7).
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(),
                                  MakeLit("urn:doc:1", "urn:p:extra", "y"),
                                  m->did)
                   .allowed);
  // A subject with no prior author of record → accepted (§7.7).
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:doc:2", "urn:p:body", "z"),
                                 m->did)
                  .allowed);
}

TEST(Gov_ShapeCaveatConformsAndFailClosed) {
  // Conforming case: an injected shape service accepts only urn:ok:1.
  GovFixture f;
  ConstraintVocabOptions opts;
  opts.shape_conforms = [](Graph*, const std::string&, const Triple& t) {
    return t.subject == "urn:ok:1";
  };
  RegisterConstraintVocabulary(&f.gov, opts);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"shape\",\"value\":{\"shapeIri\":\"urn:shape:X\"}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:ok:1", "urn:p:body", "hi"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:no:1", "urn:p:body", "hi"),
                                  m->did)
                   .allowed);

  // Fail-closed: with no shape service wired, any shape caveat rejects (§9.6).
  GovFixture f2;
  RegisterConstraintVocabulary(&f2.gov);
  const std::string root2 = BootstrapEnforced(f2);
  auto m2 = f2.provider.CreateKey("M2");
  DelegateWithCaveats(
      f2, root2, m2->did,
      "[{\"type\":\"shape\",\"value\":{\"shapeIri\":\"urn:shape:X\"}}]");
  EXPECT_FALSE(f2.gov.CanAddTriple(f2.W(), MakeLit("urn:ok:1", "urn:p:body", "hi"),
                                   m2->did)
                   .allowed);
}

TEST(Gov_ContentSparqlAskCaveat) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  const std::string root = BootstrapEnforced(f);
  auto m = f.provider.CreateKey("M");
  // The ASK passes only when the written triple binds urn:p:body on $this.
  DelegateWithCaveats(
      f, root, m->did,
      "[{\"type\":\"content\",\"value\":{\"sparql\":"
      "\"ASK { $this <urn:p:body> ?o }\"}}]");
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:x:1", "urn:p:body", "hi"),
                                 m->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:x:1", "urn:p:other", "hi"),
                                  m->did)
                   .allowed);
}

TEST(Gov_CredentialCaveatRequires) {
  GovFixture f;
  RegisterConstraintVocabulary(&f.gov);
  auto issuer = f.provider.CreateKey("Issuer");
  const std::string root = BootstrapEnforced(f);
  auto holder = f.provider.CreateKey("Holder");
  auto bare = f.provider.CreateKey("Bare");

  const std::string vc = MakeSignedLivingWebVc(
      &f.provider, issuer->id, issuer->did, {"EmailVerified"}, holder->did,
      "2020-01-01T00:00:00Z");
  std::string addr;
  {
    group_detail::ScopedActive active(&f.provider, f.gcred);
    EXPECT_TRUE(StoreCredential(f.W(), holder->did, vc, &addr));
  }
  const std::string caveats =
      "[{\"type\":\"credential\",\"value\":{\"requires\":"
      "[{\"type\":\"EmailVerified\"}]}}]";
  DelegateWithCaveats(f, root, holder->did, caveats);
  DelegateWithCaveats(f, root, bare->did, caveats);
  // The holder satisfies the required credential; the bare agent does not.
  EXPECT_TRUE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:1", "urn:p:body", "hi"),
                                 holder->did)
                  .allowed);
  EXPECT_FALSE(f.gov.CanAddTriple(f.W(), MakeLit("urn:n:2", "urn:p:body", "hi"),
                                  bare->did)
                   .allowed);
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
