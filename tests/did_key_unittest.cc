// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for DIDKeyProvider — Ed25519 key management.

#include "content/browser/did/did_key_provider.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

TEST(DIDKeyProviderTest, CreateKey) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Test Identity");
  ASSERT_NE(key, nullptr);
  EXPECT_FALSE(key->did.empty());
  EXPECT_EQ(key->algorithm, "Ed25519");
  EXPECT_EQ(key->display_name, "Test Identity");
  EXPECT_FALSE(key->is_locked);
  EXPECT_EQ(key->public_key.size(), 32u);
  EXPECT_EQ(key->private_key.size(), 64u);
  // did:key should start with the Ed25519 multicodec prefix.
  EXPECT_EQ(key->did.substr(0, 12), "did:key:z6Mk");
}

TEST(DIDKeyProviderTest, ListCredentials) {
  DIDKeyProvider provider;
  provider.CreateKey("First");
  provider.CreateKey("Second");
  auto creds = provider.ListCredentials();
  EXPECT_EQ(creds.size(), 2u);
}

TEST(DIDKeyProviderTest, ActiveCredential) {
  DIDKeyProvider provider;
  auto first = provider.CreateKey("First");
  auto second = provider.CreateKey("Second");

  // First created should be active by default.
  auto active = provider.GetActiveCredential();
  ASSERT_NE(active, nullptr);
  EXPECT_EQ(active->id, first->id);

  // Switch active.
  EXPECT_TRUE(provider.SetActiveCredential(second->id));
  active = provider.GetActiveCredential();
  ASSERT_NE(active, nullptr);
  EXPECT_EQ(active->id, second->id);
}

TEST(DIDKeyProviderTest, DeleteCredential) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("ToDelete");
  EXPECT_TRUE(provider.DeleteCredential(key->id));
  EXPECT_EQ(provider.ListCredentials().size(), 0u);
  EXPECT_FALSE(provider.DeleteCredential("nonexistent"));
}

TEST(DIDKeyProviderTest, SignAndVerify) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Signer");

  auto result = provider.Sign(key->id, R"({"message":"hello"})");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->author, key->did);
  EXPECT_FALSE(result->proof_sig.empty());
  EXPECT_FALSE(result->timestamp.empty());

  // Verify the signature.
  EXPECT_TRUE(provider.Verify(
      result->author, result->data_json,
      result->timestamp, result->proof_sig));

  // Tampered data should fail.
  EXPECT_FALSE(provider.Verify(
      result->author, R"({"message":"tampered"})",
      result->timestamp, result->proof_sig));
}

TEST(DIDKeyProviderTest, SignLockedKey) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Lockable");

  EXPECT_TRUE(provider.Lock(key->id));
  auto result = provider.Sign(key->id, "data");
  EXPECT_FALSE(result.has_value());

  EXPECT_TRUE(provider.Unlock(key->id));
  result = provider.Sign(key->id, "data");
  EXPECT_TRUE(result.has_value());
}

TEST(DIDKeyProviderTest, ResolveDID) {
  DIDKeyProvider provider;
  auto key = provider.CreateKey("Resolvable");

  auto doc = provider.ResolveDID(key->did);
  EXPECT_FALSE(doc.empty());
  EXPECT_NE(doc.find(key->did), std::string::npos);
  EXPECT_NE(doc.find("Ed25519VerificationKey2020"), std::string::npos);
}

TEST(DIDKeyProviderTest, ResolveInvalidDID) {
  DIDKeyProvider provider;
  auto doc = provider.ResolveDID("did:web:example.com");
  EXPECT_TRUE(doc.empty());  // Only did:key supported.
}

}  // namespace
}  // namespace content
