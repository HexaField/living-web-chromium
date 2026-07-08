// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Peer — a single agent session in a graph's sync space (Graph Synchronisation
// Protocol spec §5.4). Browser-returned as an element of Graph.peers() /
// onlinePeers() and as the payload of the peerjoined / peerleft / signal events.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_H_

#include <optional>

#include "mojo/public/mojom/graph/graph.mojom-blink.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class Peer final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  // Build a renderer Peer from the Mojo payload (browser -> renderer).
  static Peer* FromMojo(const graph::mojom::blink::PeerPtr& peer);

  Peer(const String& did,
       const String& session_id,
       const String& public_key,
       const String& device_label,
       std::optional<uint64_t> last_seen,
       bool online)
      : did_(did),
        session_id_(session_id),
        public_key_(public_key),
        device_label_(device_label),
        last_seen_(last_seen),
        online_(online) {}

  const String& did() const { return did_; }
  const String& sessionId() const { return session_id_; }
  const String& publicKey() const { return public_key_; }      // null when none
  const String& deviceLabel() const { return device_label_; }  // null when none
  std::optional<uint64_t> lastSeen() const { return last_seen_; }
  bool online() const { return online_; }

  void Trace(Visitor* visitor) const override {
    ScriptWrappable::Trace(visitor);
  }

 private:
  String did_;
  String session_id_;
  String public_key_;
  String device_label_;
  std::optional<uint64_t> last_seen_;
  bool online_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_GRAPH_PEER_H_
