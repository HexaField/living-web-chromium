// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The browser-process resolution of the Spec 09 `SyncCrypto` seam
// (content/browser/graph_sync/default_sync_module.h §6.3). It is the //crypto /
// BoringSSL analogue of the standalone harness's OpenSSL provider
// (standalone/default_sync_provider.h::MakeOpenSslSyncCrypto): the shared
// Chromium-independent core performs no cryptography itself, so both build
// worlds inject the same eight primitives — SHA-256/512, HMAC-SHA256, X25519,
// AES-128-GCM seal/open, and Ed25519 verify/sign — and the key schedule
// (§6.3.9) and AEAD envelope (§6.3.10) compute byte-identically on either side.

#ifndef CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_CRYPTO_H_
#define CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_CRYPTO_H_

#include "content/browser/graph_sync/default_sync_module.h"

namespace content {

// Builds the BoringSSL-backed primitive seam the shared Spec 09 core consumes.
// The returned struct owns no state; the underlying primitives are stateless, so
// a single instance is safe to share across every space in a realm.
living_web::default_sync::SyncCrypto MakeChromiumSyncCrypto();

}  // namespace content

#endif  // CONTENT_BROWSER_GRAPH_SYNC_DEFAULT_SYNC_CRYPTO_H_
