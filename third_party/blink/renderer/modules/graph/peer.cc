// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/peer.h"

namespace blink {

// static
Peer* Peer::FromMojo(const graph::mojom::blink::PeerPtr& peer) {
  // public_key / device_label are nullable strings (null when absent); last_seen
  // is a nullable uint64 carried straight into the optional.
  return MakeGarbageCollected<Peer>(peer->did, peer->session_id,
                                    peer->public_key, peer->device_label,
                                    peer->last_seen, peer->online);
}

}  // namespace blink
