// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 09 browser-process Default Sync Module port — the
// //crypto + BoringSSL SyncCrypto seam (content::MakeChromiumSyncCrypto), the
// exception-free OpenMLS engine wrapper (content::mls_engine::Member) and the
// per-space encrypted-sync backend (content::DefaultSyncBackend) — driving the
// shared, Chromium-independent Spec 09 core (default_sync_module.{h,cc}).
//
// These exercise the same normative behaviour as the standalone Sync09_*
// conformance harness, but against the browser resolutions of the two crypto
// seams, so the full-tree content_unittests build has direct coverage of the
// §4.1 module identity, the §6.3.9 key schedule (HKDF / MLS-Exporter), the
// §6.3.3 did:key→X25519 binding, the §6.3.10 AEAD frame envelope, the §8 OR-Set
// merge, and — end to end — a real RFC 9420 MLS ceremony (create / add / remove
// / update) driving the exporter seam into the core's key schedule and AEAD.
// The byte-critical schedule + envelope are shared verbatim with the harness, so
// the frame bytes a space encrypts never diverge between the two build worlds.

#include "content/browser/graph_sync/default_sync_backend.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph_sync/cbor.h"
#include "content/browser/graph_sync/default_sync_crypto.h"
#include "content/browser/graph_sync/default_sync_module.h"
#include "content/browser/graph_sync/mls_engine.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"

namespace content {
namespace {

namespace ds = living_web::default_sync;
using living_web::ObjectTerm;
using living_web::Triple;

// ---- helpers (mirror the standalone Sync09 fixtures) -----------------------

std::string BytesToHex(const std::string& bytes) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char c : bytes) {
    out.push_back(kHex[c >> 4]);
    out.push_back(kHex[c & 0x0f]);
  }
  return out;
}

std::string HexToBytes(const std::string& hex) {
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    return c - 'A' + 10;
  };
  std::string out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
    out.push_back(static_cast<char>((nib(hex[i]) << 4) | nib(hex[i + 1])));
  return out;
}

Triple IriTriple(const std::string& s,
                 const std::string& p,
                 const std::string& o) {
  Triple t;
  t.subject = s;
  t.predicate = p;
  t.object = ObjectTerm::Iri(o);
  return t;
}

// A space:// URI whose authority is SHA-256(|seed|), via the //crypto seam.
std::string SpaceUri(const std::string& seed) {
  return "space://" + BytesToHex(MakeChromiumSyncCrypto().sha256(seed));
}

// ===========================================================================
// Shared-core coverage against the //crypto seam
// ===========================================================================

TEST(DefaultSyncModuleTest, ModuleContentHash) {
  ds::SyncCrypto crypto = MakeChromiumSyncCrypto();
  // SHA-256("hello") is a well-known digest.
  EXPECT_EQ(ds::DefaultModuleContentHash("hello", crypto.sha256),
            std::string("sha256-2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa742"
                        "5e73043362938b9824"));
}

TEST(DefaultSyncModuleTest, HkdfExpandKnownAnswer) {
  // RFC 5869 Appendix A.1 Test Case 1 (HKDF-Expand step) through the BoringSSL
  // HMAC-SHA256 primitive.
  ds::SyncCrypto crypto = MakeChromiumSyncCrypto();
  const std::string prk = HexToBytes(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
  const std::string info = HexToBytes("f0f1f2f3f4f5f6f7f8f9");
  EXPECT_EQ(BytesToHex(ds::HkdfExpandSha256(prk, info, 42, crypto)),
            std::string("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02"
                        "d56ecc4c5bf34007208d5b887185865"));
  EXPECT_TRUE(
      ds::HkdfExpandSha256(prk, info, 255 * 32 + 1, crypto).empty());
}

TEST(DefaultSyncModuleTest, GroupIdFromSpaceUri) {
  const std::string hex(64, 'a');
  std::string gid;
  EXPECT_TRUE(ds::GroupIdFromSpaceUri("space://" + hex, &gid));
  EXPECT_EQ(gid.size(), 32u);
  EXPECT_EQ(BytesToHex(gid), hex);
  std::string bad;
  EXPECT_FALSE(ds::GroupIdFromSpaceUri("https://" + hex, &bad));
  EXPECT_FALSE(ds::GroupIdFromSpaceUri("space://abc", &bad));
  EXPECT_FALSE(ds::GroupIdFromSpaceUri("space://" + std::string(64, 'A'), &bad));
}

TEST(DefaultSyncModuleTest, X25519MatchesEdwardsMap) {
  // The §6.3.3 birational map (pure field arithmetic) must agree with the
  // scalar route (clamp(SHA-512(seed)) then X25519(·,9) via BoringSSL) for a
  // real Ed25519 keypair — that equality is exactly the §6.3.4 check-4 binding.
  ds::SyncCrypto crypto = MakeChromiumSyncCrypto();
  for (int i = 0; i < 8; ++i) {
    uint8_t pub[32], priv[64];
    ED25519_keypair(pub, priv);  // priv[0..32) is the RFC 8032 seed
    std::string seed(reinterpret_cast<char*>(priv), 32);
    std::string ed_pub(reinterpret_cast<char*>(pub), 32);

    std::string scalar = ds::DeriveX25519PrivateScalar(seed, crypto);
    std::string x_from_scalar = ds::DeriveX25519Public(scalar, crypto);
    EXPECT_EQ(x_from_scalar.size(), 32u);

    std::string x_from_edwards;
    EXPECT_TRUE(ds::Ed25519PubToX25519Pub(ed_pub, &x_from_edwards));
    EXPECT_EQ(x_from_scalar, x_from_edwards);
    EXPECT_TRUE(ds::VerifyEncryptionKeyBinding(ed_pub, x_from_scalar));
    std::string wrong = x_from_scalar;
    wrong[0] ^= 0x01;
    EXPECT_FALSE(ds::VerifyEncryptionKeyBinding(ed_pub, wrong));
  }
}

TEST(DefaultSyncModuleTest, FrameKeysDeterministic) {
  ds::SyncCrypto crypto = MakeChromiumSyncCrypto();
  const std::string sts = crypto.sha256("space-traffic-secret");
  ds::FrameKeys k1 = ds::DeriveFrameKeys(sts, crypto);
  ds::FrameKeys k2 = ds::DeriveFrameKeys(sts, crypto);
  EXPECT_EQ(k1.key, k2.key);
  EXPECT_EQ(k1.nonce, k2.nonce);
  EXPECT_EQ(k1.key.size(), 16u);
  EXPECT_EQ(k1.nonce.size(), 12u);
  // A different secret yields different keys.
  ds::FrameKeys k3 = ds::DeriveFrameKeys(crypto.sha256("other"), crypto);
  EXPECT_NE(k1.key, k3.key);
}

TEST(DefaultSyncModuleTest, FrameSealOpenRoundTrip) {
  ds::SyncCrypto crypto = MakeChromiumSyncCrypto();
  const std::string space = SpaceUri("seal-open");
  ds::FrameKeys keys = ds::DeriveFrameKeys(crypto.sha256("epoch-secret"), crypto);

  ds::WireFrame plain;
  plain.type = ds::FrameType::kDiff;
  plain.space_uri = space;
  plain.from = {"did:key:zAlice", "sa"};
  plain.to = std::nullopt;
  plain.payload = ds::SignalToCbor("payload-bytes");

  ds::EncryptedFrame enc;
  EXPECT_TRUE(ds::SealFrame(keys, plain, /*epoch=*/7, /*seq=*/3, crypto, &enc));
  EXPECT_EQ(enc.epoch, 7u);
  EXPECT_EQ(enc.seq, 3u);

  ds::WireFrame opened;
  EXPECT_TRUE(ds::OpenFrame(keys, enc, crypto, &opened));
  std::string body;
  EXPECT_TRUE(ds::SignalFromCbor(opened.payload, &body));
  EXPECT_EQ(body, std::string("payload-bytes"));

  // A one-bit flip in the ciphertext fails authentication.
  ds::EncryptedFrame tampered = enc;
  tampered.ct[0] ^= 0x01;
  ds::WireFrame discard;
  EXPECT_FALSE(ds::OpenFrame(keys, tampered, crypto, &discard));
  // As does a header (associated-data) change: the epoch is bound into the AAD.
  ds::EncryptedFrame reheadered = enc;
  reheadered.epoch = 8;
  EXPECT_FALSE(ds::OpenFrame(keys, reheadered, crypto, &discard));
}

TEST(DefaultSyncModuleTest, OrSetConverges) {
  // Two replicas applying the same diffs in opposite orders converge (§8.1).
  ds::DiffWire add;
  add.graph_did = "did:graph:zGraph";
  add.revision = "rev-add";
  add.additions = {IriTriple("s", "p", "o1"), IriTriple("s", "p", "o2")};

  ds::DiffWire remove;
  remove.graph_did = "did:graph:zGraph";
  remove.revision = "rev-rem";
  remove.dependencies = {"rev-add"};
  ds::DiffRemoval r;
  r.triple = IriTriple("s", "p", "o1");
  r.removed_tags = {"rev-add"};
  remove.removals = {r};

  ds::OrSet a;
  a.ApplyDiff(add);
  a.ApplyDiff(remove);

  ds::OrSet b;
  b.ApplyDiff(remove);  // reverse order
  b.ApplyDiff(add);

  EXPECT_EQ(a.Members(), b.Members());
  EXPECT_EQ(a.Size(), 1u);  // o1 removed, o2 remains
}

TEST(DefaultSyncModuleTest, SnapshotThreshold) {
  EXPECT_FALSE(ds::ShouldPromote(ds::kDefaultSnapshotThreshold - 1));
  EXPECT_TRUE(ds::ShouldPromote(ds::kDefaultSnapshotThreshold));
  EXPECT_TRUE(ds::ShouldPromote(5, 5));
  EXPECT_FALSE(ds::ShouldPromote(4, 5));
}

// ===========================================================================
// MLS ceremony via the browser (exception-free) engine
// ===========================================================================

TEST(DefaultSyncModuleTest, MlsTwoMemberExporterAgree) {
  ds::SyncCrypto crypto = MakeChromiumSyncCrypto();
  const std::string space = SpaceUri("mls-space-alpha");
  std::string gid;
  ASSERT_TRUE(ds::GroupIdFromSpaceUri(space, &gid));

  mls_engine::Member alice("did:key:zAlice");
  mls_engine::Member bob("did:key:zBob");
  ASSERT_TRUE(alice.ok());
  ASSERT_TRUE(bob.ok());
  ASSERT_TRUE(alice.CreateGroup(gid));

  std::string bob_kp;
  ASSERT_TRUE(bob.KeyPackage(&bob_kp));
  std::string commit, welcome;
  ASSERT_TRUE(alice.Add(bob_kp, &commit, &welcome));
  ASSERT_TRUE(bob.Join(welcome));

  size_t alice_count = 0, bob_count = 0;
  ASSERT_TRUE(alice.MemberCount(&alice_count));
  ASSERT_TRUE(bob.MemberCount(&bob_count));
  EXPECT_EQ(alice_count, 2u);
  EXPECT_EQ(bob_count, 2u);
  uint64_t alice_epoch = 0, bob_epoch = 0;
  ASSERT_TRUE(alice.Epoch(&alice_epoch));
  ASSERT_TRUE(bob.Epoch(&bob_epoch));
  EXPECT_EQ(alice_epoch, bob_epoch);

  // The RFC 9420 §8.5 exporter (the §6.3.9 seam) yields the core's space traffic
  // secret; both members agree on it and on the derived frame keys.
  const std::string label = ds::kSpaceFrameExporterLabel;
  std::string sts_a, sts_b;
  ASSERT_TRUE(alice.ExportSecret(label, space, 32, &sts_a));
  ASSERT_TRUE(bob.ExportSecret(label, space, 32, &sts_b));
  EXPECT_EQ(sts_a.size(), 32u);
  EXPECT_EQ(sts_a, sts_b);

  ds::FrameKeys keys_a = ds::DeriveFrameKeys(sts_a, crypto);
  ds::FrameKeys keys_b = ds::DeriveFrameKeys(sts_b, crypto);
  EXPECT_EQ(keys_a.key, keys_b.key);
  EXPECT_EQ(keys_a.nonce, keys_b.nonce);
}

TEST(DefaultSyncModuleTest, MlsEndToEndFrameExchange) {
  ds::SyncCrypto crypto = MakeChromiumSyncCrypto();
  const std::string space = SpaceUri("mls-space-e2e");
  const std::string label = ds::kSpaceFrameExporterLabel;
  std::string gid;
  ASSERT_TRUE(ds::GroupIdFromSpaceUri(space, &gid));

  mls_engine::Member alice("did:key:zAlice");
  mls_engine::Member bob("did:key:zBob");
  ASSERT_TRUE(alice.ok());
  ASSERT_TRUE(bob.ok());
  ASSERT_TRUE(alice.CreateGroup(gid));
  std::string bob_kp, commit, welcome;
  ASSERT_TRUE(bob.KeyPackage(&bob_kp));
  ASSERT_TRUE(alice.Add(bob_kp, &commit, &welcome));
  ASSERT_TRUE(bob.Join(welcome));

  auto frame_keys = [&](mls_engine::Member& m) {
    std::string sts;
    EXPECT_TRUE(m.ExportSecret(label, space, 32, &sts));
    return ds::DeriveFrameKeys(sts, crypto);
  };
  uint64_t epoch = 0;
  ASSERT_TRUE(alice.Epoch(&epoch));
  ds::FrameKeys keys_a = frame_keys(alice);
  ds::FrameKeys keys_b = frame_keys(bob);
  EXPECT_EQ(keys_a.key, keys_b.key);

  // Alice → Bob.
  ds::WireFrame a2b;
  a2b.type = ds::FrameType::kDiff;
  a2b.space_uri = space;
  a2b.from = {"did:key:zAlice", "sa"};
  a2b.to = std::nullopt;
  a2b.payload = ds::SignalToCbor("alice-diff");
  ds::EncryptedFrame enc_a;
  ASSERT_TRUE(ds::SealFrame(keys_a, a2b, epoch, 1, crypto, &enc_a));
  ds::WireFrame got_by_bob;
  ASSERT_TRUE(ds::OpenFrame(keys_b, enc_a, crypto, &got_by_bob));
  std::string body_b;
  EXPECT_TRUE(ds::SignalFromCbor(got_by_bob.payload, &body_b));
  EXPECT_EQ(body_b, std::string("alice-diff"));

  // Epoch advance: Bob self-updates, Alice applies the commit; the exporter
  // rotates, so the derived frame keys rotate with it.
  std::string update;
  ASSERT_TRUE(bob.Update(&update));
  ASSERT_TRUE(alice.ProcessCommit(update));
  uint64_t new_epoch = 0;
  ASSERT_TRUE(alice.Epoch(&new_epoch));
  EXPECT_GT(new_epoch, epoch);

  ds::FrameKeys keys_a2 = frame_keys(alice);
  ds::FrameKeys keys_b2 = frame_keys(bob);
  EXPECT_EQ(keys_a2.key, keys_b2.key);
  EXPECT_NE(keys_a2.key, keys_a.key);

  ds::WireFrame post;
  post.type = ds::FrameType::kDiff;
  post.space_uri = space;
  post.from = {"did:key:zAlice", "sa"};
  post.to = std::nullopt;
  post.payload = ds::SignalToCbor("post-rotation");
  ds::EncryptedFrame enc_post;
  ASSERT_TRUE(ds::SealFrame(keys_a2, post, new_epoch, 2, crypto, &enc_post));
  ds::WireFrame post_open;
  ASSERT_TRUE(ds::OpenFrame(keys_b2, enc_post, crypto, &post_open));
  // The stale pre-rotation keys can no longer open the new-epoch frame.
  ds::WireFrame discard;
  EXPECT_FALSE(ds::OpenFrame(keys_b, enc_post, crypto, &discard));
}

TEST(DefaultSyncModuleTest, MlsGroupAddRemove) {
  const std::string space = SpaceUri("mls-space-abc");
  const std::string label = ds::kSpaceFrameExporterLabel;
  std::string gid;
  ASSERT_TRUE(ds::GroupIdFromSpaceUri(space, &gid));

  mls_engine::Member alice("did:key:zAlice");
  mls_engine::Member bob("did:key:zBob");
  mls_engine::Member carol("did:key:zCarol");
  ASSERT_TRUE(alice.ok() && bob.ok() && carol.ok());
  ASSERT_TRUE(alice.CreateGroup(gid));

  // Alice adds Bob.
  std::string bob_kp, c1, w1;
  ASSERT_TRUE(bob.KeyPackage(&bob_kp));
  ASSERT_TRUE(alice.Add(bob_kp, &c1, &w1));
  ASSERT_TRUE(bob.Join(w1));

  // Alice adds Carol; Bob (already a member) applies the same commit.
  std::string carol_kp, c2, w2;
  ASSERT_TRUE(carol.KeyPackage(&carol_kp));
  ASSERT_TRUE(alice.Add(carol_kp, &c2, &w2));
  ASSERT_TRUE(bob.ProcessCommit(c2));
  ASSERT_TRUE(carol.Join(w2));

  size_t na = 0, nb = 0, nc = 0;
  ASSERT_TRUE(alice.MemberCount(&na));
  ASSERT_TRUE(bob.MemberCount(&nb));
  ASSERT_TRUE(carol.MemberCount(&nc));
  EXPECT_EQ(na, 3u);
  EXPECT_EQ(nb, 3u);
  EXPECT_EQ(nc, 3u);

  std::string s_a, s_b, s_c;
  ASSERT_TRUE(alice.ExportSecret(label, space, 32, &s_a));
  ASSERT_TRUE(bob.ExportSecret(label, space, 32, &s_b));
  ASSERT_TRUE(carol.ExportSecret(label, space, 32, &s_c));
  EXPECT_EQ(s_a, s_b);
  EXPECT_EQ(s_a, s_c);

  // Alice removes Carol; Bob applies the commit; Carol is evicted.
  uint32_t carol_leaf = 0;
  ASSERT_TRUE(carol.OwnLeafIndex(&carol_leaf));
  std::string rm;
  ASSERT_TRUE(alice.Remove(carol_leaf, &rm));
  ASSERT_TRUE(bob.ProcessCommit(rm));

  ASSERT_TRUE(alice.MemberCount(&na));
  ASSERT_TRUE(bob.MemberCount(&nb));
  EXPECT_EQ(na, 2u);
  EXPECT_EQ(nb, 2u);

  std::string s_a2, s_b2, s_c_stale;
  ASSERT_TRUE(alice.ExportSecret(label, space, 32, &s_a2));
  ASSERT_TRUE(bob.ExportSecret(label, space, 32, &s_b2));
  ASSERT_TRUE(carol.ExportSecret(label, space, 32, &s_c_stale));
  EXPECT_EQ(s_a2, s_b2);        // remaining members still agree …
  EXPECT_NE(s_a2, s_a);         // … on a fresh post-removal secret …
  EXPECT_NE(s_c_stale, s_a2);   // … that Carol's stale secret does not match.
}

// ===========================================================================
// DefaultSyncBackend — the per-space browser service, end to end
// ===========================================================================

TEST(DefaultSyncBackendTest, FoundAddSealOpenRotate) {
  DefaultSyncBackend alice_node;
  DefaultSyncBackend bob_node;
  const std::string space = SpaceUri("backend-e2e");

  ASSERT_TRUE(alice_node.FoundSpace(space, "did:key:zAlice"))
      << alice_node.last_error();
  std::string bob_kp;
  ASSERT_TRUE(bob_node.PrepareJoin(space, "did:key:zBob", &bob_kp))
      << bob_node.last_error();
  std::string commit, welcome;
  ASSERT_TRUE(alice_node.AddMember(space, bob_kp, &commit, &welcome))
      << alice_node.last_error();
  ASSERT_TRUE(bob_node.JoinSpace(space, welcome)) << bob_node.last_error();

  size_t count = 0;
  ASSERT_TRUE(alice_node.MemberCount(space, &count));
  EXPECT_EQ(count, 2u);
  uint64_t ea = 0, eb = 0;
  ASSERT_TRUE(alice_node.Epoch(space, &ea));
  ASSERT_TRUE(bob_node.Epoch(space, &eb));
  EXPECT_EQ(ea, eb);

  // Alice seals a DIFF; Bob opens it. The backend derives the epoch keys from
  // the exporter seam under the hood.
  ds::WireFrame frame;
  frame.type = ds::FrameType::kDiff;
  frame.space_uri = space;
  frame.from = {"did:key:zAlice", "sa"};
  frame.to = std::nullopt;
  frame.payload = ds::SignalToCbor("hello-space");
  ds::EncryptedFrame enc;
  ASSERT_TRUE(alice_node.SealFrame(space, frame, &enc)) << alice_node.last_error();
  EXPECT_EQ(enc.seq, 0u);  // first frame consumes sequence 0
  ds::WireFrame opened;
  ASSERT_TRUE(bob_node.OpenFrame(space, enc, &opened)) << bob_node.last_error();
  std::string body;
  EXPECT_TRUE(ds::SignalFromCbor(opened.payload, &body));
  EXPECT_EQ(body, std::string("hello-space"));

  // A stale frame captured at the current epoch is rejected once the epoch
  // advances: Bob rotates, Alice applies the commit, both move forward.
  std::string update;
  ASSERT_TRUE(bob_node.RotateKey(space, &update)) << bob_node.last_error();
  ASSERT_TRUE(alice_node.ProcessCommit(space, update))
      << alice_node.last_error();
  uint64_t ea2 = 0, eb2 = 0;
  ASSERT_TRUE(alice_node.Epoch(space, &ea2));
  ASSERT_TRUE(bob_node.Epoch(space, &eb2));
  EXPECT_EQ(ea2, eb2);
  EXPECT_GT(ea2, ea);
  ds::WireFrame stale;
  EXPECT_FALSE(bob_node.OpenFrame(space, enc, &stale));  // epoch_mismatch

  // A fresh frame under the new epoch still round-trips.
  ds::WireFrame frame2 = frame;
  frame2.payload = ds::SignalToCbor("after-rotation");
  ds::EncryptedFrame enc2;
  ASSERT_TRUE(alice_node.SealFrame(space, frame2, &enc2))
      << alice_node.last_error();
  ds::WireFrame opened2;
  ASSERT_TRUE(bob_node.OpenFrame(space, enc2, &opened2)) << bob_node.last_error();
  std::string body2;
  EXPECT_TRUE(ds::SignalFromCbor(opened2.payload, &body2));
  EXPECT_EQ(body2, std::string("after-rotation"));
}

TEST(DefaultSyncBackendTest, MergeDiffAddRemove) {
  DefaultSyncBackend node;
  const std::string space = SpaceUri("backend-merge");
  ASSERT_TRUE(node.FoundSpace(space, "did:key:zAlice")) << node.last_error();

  ds::DiffWire add;
  add.graph_did = "did:graph:zGraph";
  add.revision = "rev-1";
  add.additions = {IriTriple("s", "p", "o1"), IriTriple("s", "p", "o2")};
  node.MergeDiff(space, add);
  EXPECT_EQ(node.Size(space), 2u);

  ds::DiffWire remove;
  remove.graph_did = "did:graph:zGraph";
  remove.revision = "rev-2";
  remove.dependencies = {"rev-1"};
  ds::DiffRemoval r;
  r.triple = IriTriple("s", "p", "o1");
  r.removed_tags = {"rev-1"};
  remove.removals = {r};
  node.MergeDiff(space, remove);
  EXPECT_EQ(node.Size(space), 1u);
}

TEST(DefaultSyncBackendTest, RejectsUnknownAndDuplicateSpace) {
  DefaultSyncBackend node;
  const std::string space = SpaceUri("backend-dup");

  // Operations on an unknown space fail cleanly.
  uint64_t epoch = 0;
  EXPECT_FALSE(node.Epoch(space, &epoch));
  EXPECT_EQ(node.last_error(), std::string("unknown_space"));

  ASSERT_TRUE(node.FoundSpace(space, "did:key:zAlice")) << node.last_error();
  // Founding the same space twice is rejected.
  EXPECT_FALSE(node.FoundSpace(space, "did:key:zAlice"));
  EXPECT_EQ(node.last_error(), std::string("space_exists"));

  // A malformed space URI is rejected up front.
  EXPECT_FALSE(node.FoundSpace("not-a-space", "did:key:zAlice"));
  EXPECT_EQ(node.last_error(), std::string("invalid_space_uri"));
}

TEST(DefaultSyncBackendTest, ModuleContentHash) {
  DefaultSyncBackend node;
  EXPECT_EQ(node.ModuleContentHash("hello"),
            std::string("sha256-2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa742"
                        "5e73043362938b9824"));
}

}  // namespace
}  // namespace content
