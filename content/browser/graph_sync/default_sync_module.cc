// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph_sync/default_sync_module.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace living_web {
namespace default_sync {

namespace {

// ---- small byte helpers ----------------------------------------------------

std::string ToLowerHex(const std::string& bytes) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char c : bytes) {
    out.push_back(kHex[c >> 4]);
    out.push_back(kHex[c & 0x0f]);
  }
  return out;
}

bool IsLowerHexChar(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

// Decodes an even-length lowercase-hex string to bytes. Returns false on any
// non-lowercase-hex character or an odd length.
bool DecodeLowerHex(const std::string& hex, std::string* out) {
  if (hex.size() % 2 != 0)
    return false;
  std::string bytes;
  bytes.reserve(hex.size() / 2);
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    return c - 'a' + 10;
  };
  for (size_t i = 0; i < hex.size(); i += 2) {
    if (!IsLowerHexChar(hex[i]) || !IsLowerHexChar(hex[i + 1]))
      return false;
    bytes.push_back(static_cast<char>((nib(hex[i]) << 4) | nib(hex[i + 1])));
  }
  *out = std::move(bytes);
  return true;
}

// n-byte big-endian encoding of |v| (I2OSP). For n > 8 the high-order bytes are
// zero; the loop stops at byte 8 so the shift never reaches 64 (a shift >= the
// width of uint64_t is undefined behaviour).
std::string I2OSP(uint64_t v, size_t n) {
  std::string out(n, '\0');
  for (size_t i = 0; i < n && i < 8; ++i)
    out[n - 1 - i] = static_cast<char>((v >> (8 * i)) & 0xff);
  return out;
}

// RFC 9420 §2.1.2 variable-length integer (the QUIC varint), used for the
// opaque<V> length prefixes inside KDFLabel.
void AppendVarint(std::string* out, uint64_t v) {
  if (v <= 0x3f) {
    out->push_back(static_cast<char>(v));
  } else if (v <= 0x3fff) {
    out->push_back(static_cast<char>(0x40 | (v >> 8)));
    out->push_back(static_cast<char>(v & 0xff));
  } else if (v <= 0x3fffffff) {
    out->push_back(static_cast<char>(0x80 | (v >> 24)));
    out->push_back(static_cast<char>((v >> 16) & 0xff));
    out->push_back(static_cast<char>((v >> 8) & 0xff));
    out->push_back(static_cast<char>(v & 0xff));
  } else {
    out->push_back(static_cast<char>(0xc0 | (v >> 56)));
    for (int shift = 48; shift >= 0; shift -= 8)
      out->push_back(static_cast<char>((v >> shift) & 0xff));
  }
}

// An MLS opaque<V> field: varint(len) followed by the bytes.
void AppendOpaqueV(std::string* out, const std::string& bytes) {
  AppendVarint(out, bytes.size());
  out->append(bytes);
}

}  // namespace

// ===========================================================================
// §4.1 — Module identity
// ===========================================================================

std::string DefaultModuleContentHash(
    const std::string& wasm_binary,
    const std::function<std::string(const std::string&)>& sha256) {
  return "sha256-" + ToLowerHex(sha256(wasm_binary));
}

// ===========================================================================
// §5 — Wire protocol
// ===========================================================================

const char* FrameTypeToToken(FrameType type) {
  switch (type) {
    case FrameType::kDiff:
      return "DIFF";
    case FrameType::kPull:
      return "PULL";
    case FrameType::kPullDenied:
      return "PULL_DENIED";
    case FrameType::kSnapshot:
      return "SNAPSHOT";
    case FrameType::kSignal:
      return "SIGNAL";
    case FrameType::kModuleUpdate:
      return "MODULE_UPDATE";
    case FrameType::kPeerHello:
      return "PEER_HELLO";
    case FrameType::kPeerBye:
      return "PEER_BYE";
  }
  return "SIGNAL";
}

bool FrameTypeFromToken(const std::string& token, FrameType* out) {
  if (token == "DIFF") {
    *out = FrameType::kDiff;
  } else if (token == "PULL") {
    *out = FrameType::kPull;
  } else if (token == "PULL_DENIED") {
    *out = FrameType::kPullDenied;
  } else if (token == "SNAPSHOT") {
    *out = FrameType::kSnapshot;
  } else if (token == "SIGNAL") {
    *out = FrameType::kSignal;
  } else if (token == "MODULE_UPDATE") {
    *out = FrameType::kModuleUpdate;
  } else if (token == "PEER_HELLO") {
    *out = FrameType::kPeerHello;
  } else if (token == "PEER_BYE") {
    *out = FrameType::kPeerBye;
  } else {
    return false;
  }
  return true;
}

namespace {

cbor::Value PeerRefToCbor(const PeerRef& p) {
  return cbor::Value::Map({
      {cbor::Value::Text("did"), cbor::Value::Text(p.did)},
      {cbor::Value::Text("sessionId"), cbor::Value::Text(p.session_id)},
  });
}

bool PeerRefFromCbor(const cbor::Value& v, PeerRef* out) {
  if (!v.IsMap())
    return false;
  const cbor::Value* did = v.Find("did");
  const cbor::Value* sid = v.Find("sessionId");
  if (!did || !sid)
    return false;
  return did->AsText(&out->did) && sid->AsText(&out->session_id);
}

// ---- Triple ↔ CBOR (the OR-Set carries structured triples) -----------------

cbor::Value ObjectToCbor(const ObjectTerm& o) {
  if (o.is_literal()) {
    const LiteralValue& lit = *o.literal;
    std::vector<cbor::Value> arr;
    arr.push_back(cbor::Value::Uint(0));  // discriminator: literal
    arr.push_back(cbor::Value::Text(lit.lexical));
    arr.push_back(cbor::Value::Text(lit.datatype));
    arr.push_back(lit.language ? cbor::Value::Text(*lit.language)
                               : cbor::Value::Null());
    return cbor::Value::Array(std::move(arr));
  }
  std::vector<cbor::Value> arr;
  arr.push_back(cbor::Value::Uint(1));  // discriminator: IRI / blank node
  arr.push_back(cbor::Value::Text(o.iri_or_bnode));
  return cbor::Value::Array(std::move(arr));
}

bool ObjectFromCbor(const cbor::Value& v, ObjectTerm* out) {
  if (!v.IsArray() || v.arr.empty())
    return false;
  uint64_t disc = 0;
  if (!v.arr[0].AsUint(&disc))
    return false;
  if (disc == 0) {
    if (v.arr.size() != 4)
      return false;
    LiteralValue lit;
    if (!v.arr[1].AsText(&lit.lexical) || !v.arr[2].AsText(&lit.datatype))
      return false;
    if (!v.arr[3].IsNull()) {
      std::string lang;
      if (!v.arr[3].AsText(&lang))
        return false;
      lit.language = lang;
    }
    *out = ObjectTerm::Literal(lit);
    return true;
  }
  if (disc == 1) {
    if (v.arr.size() != 2)
      return false;
    std::string iri;
    if (!v.arr[1].AsText(&iri))
      return false;
    out->literal.reset();
    out->iri_or_bnode = iri;
    return true;
  }
  return false;
}

cbor::Value TripleToCbor(const Triple& t) {
  std::vector<cbor::Value> arr;
  arr.push_back(cbor::Value::Text(t.subject));
  arr.push_back(cbor::Value::Text(t.predicate));
  arr.push_back(ObjectToCbor(t.object));
  return cbor::Value::Array(std::move(arr));
}

bool TripleFromCbor(const cbor::Value& v, Triple* out) {
  if (!v.IsArray() || v.arr.size() != 3)
    return false;
  if (!v.arr[0].AsText(&out->subject) || !v.arr[1].AsText(&out->predicate))
    return false;
  return ObjectFromCbor(v.arr[2], &out->object);
}

cbor::Value TextArray(const std::vector<std::string>& items) {
  std::vector<cbor::Value> arr;
  arr.reserve(items.size());
  for (const std::string& s : items)
    arr.push_back(cbor::Value::Text(s));
  return cbor::Value::Array(std::move(arr));
}

bool TextArrayFrom(const cbor::Value& v, std::vector<std::string>* out) {
  if (!v.IsArray())
    return false;
  out->clear();
  out->reserve(v.arr.size());
  for (const cbor::Value& e : v.arr) {
    std::string s;
    if (!e.AsText(&s))
      return false;
    out->push_back(std::move(s));
  }
  return true;
}

}  // namespace

std::string EncodeOpenFrame(const WireFrame& frame) {
  cbor::Value m = cbor::Value::Map({
      {cbor::Value::Text("type"),
       cbor::Value::Text(FrameTypeToToken(frame.type))},
      {cbor::Value::Text("spaceUri"), cbor::Value::Text(frame.space_uri)},
      {cbor::Value::Text("from"), PeerRefToCbor(frame.from)},
      {cbor::Value::Text("to"),
       frame.to ? PeerRefToCbor(*frame.to) : cbor::Value::Null()},
      {cbor::Value::Text("payload"), frame.payload},
  });
  return cbor::Encode(m);
}

bool DecodeOpenFrame(const std::string& in, WireFrame* out) {
  cbor::Value m;
  if (!cbor::Decode(in, &m) || !m.IsMap())
    return false;
  const cbor::Value* type = m.Find("type");
  const cbor::Value* space = m.Find("spaceUri");
  const cbor::Value* from = m.Find("from");
  const cbor::Value* to = m.Find("to");
  const cbor::Value* payload = m.Find("payload");
  if (!type || !space || !from || !to || !payload)
    return false;
  std::string token;
  if (!type->AsText(&token) || !FrameTypeFromToken(token, &out->type))
    return false;
  if (!space->AsText(&out->space_uri))
    return false;
  if (!PeerRefFromCbor(*from, &out->from))
    return false;
  if (to->IsNull()) {
    out->to.reset();
  } else {
    PeerRef p;
    if (!PeerRefFromCbor(*to, &p))
      return false;
    out->to = p;
  }
  out->payload = *payload;
  return true;
}

// ---- §5.2 DIFF -------------------------------------------------------------

cbor::Value DiffToCbor(const DiffWire& diff) {
  std::vector<cbor::Value> additions;
  additions.reserve(diff.additions.size());
  for (const Triple& t : diff.additions)
    additions.push_back(TripleToCbor(t));

  std::vector<cbor::Value> removals;
  removals.reserve(diff.removals.size());
  for (const DiffRemoval& r : diff.removals) {
    std::vector<cbor::Value> pair;
    pair.push_back(TripleToCbor(r.triple));
    pair.push_back(TextArray(r.removed_tags));
    removals.push_back(cbor::Value::Array(std::move(pair)));
  }

  return cbor::Value::Map({
      {cbor::Value::Text("graphDid"), cbor::Value::Text(diff.graph_did)},
      {cbor::Value::Text("revision"), cbor::Value::Text(diff.revision)},
      {cbor::Value::Text("dependencies"), TextArray(diff.dependencies)},
      {cbor::Value::Text("additions"),
       cbor::Value::Array(std::move(additions))},
      {cbor::Value::Text("removals"), cbor::Value::Array(std::move(removals))},
      {cbor::Value::Text("author"), cbor::Value::Text(diff.author)},
      {cbor::Value::Text("timestamp"), cbor::Value::Text(diff.timestamp)},
  });
}

bool DiffFromCbor(const cbor::Value& v, DiffWire* out) {
  if (!v.IsMap())
    return false;
  const cbor::Value* graph = v.Find("graphDid");
  const cbor::Value* rev = v.Find("revision");
  const cbor::Value* deps = v.Find("dependencies");
  const cbor::Value* adds = v.Find("additions");
  const cbor::Value* rems = v.Find("removals");
  const cbor::Value* author = v.Find("author");
  const cbor::Value* ts = v.Find("timestamp");
  if (!graph || !rev || !deps || !adds || !rems || !author || !ts)
    return false;
  if (!graph->AsText(&out->graph_did) || !rev->AsText(&out->revision) ||
      !author->AsText(&out->author) || !ts->AsText(&out->timestamp))
    return false;
  if (!TextArrayFrom(*deps, &out->dependencies))
    return false;
  if (!adds->IsArray() || !rems->IsArray())
    return false;

  out->additions.clear();
  out->additions.reserve(adds->arr.size());
  for (const cbor::Value& e : adds->arr) {
    Triple t;
    if (!TripleFromCbor(e, &t))
      return false;
    out->additions.push_back(std::move(t));
  }

  out->removals.clear();
  out->removals.reserve(rems->arr.size());
  for (const cbor::Value& e : rems->arr) {
    if (!e.IsArray() || e.arr.size() != 2)
      return false;
    DiffRemoval r;
    if (!TripleFromCbor(e.arr[0], &r.triple))
      return false;
    if (!TextArrayFrom(e.arr[1], &r.removed_tags))
      return false;
    out->removals.push_back(std::move(r));
  }
  return true;
}

// ---- §5.3 PULL -------------------------------------------------------------

cbor::Value PullToCbor(const PullPayload& p) {
  std::vector<std::pair<cbor::Value, cbor::Value>> m;
  m.emplace_back(cbor::Value::Text("graphDid"), cbor::Value::Text(p.graph_did));
  m.emplace_back(cbor::Value::Text("fromRevision"),
                 p.from_revision ? cbor::Value::Text(*p.from_revision)
                                 : cbor::Value::Null());
  m.emplace_back(cbor::Value::Text("authorDid"),
                 cbor::Value::Text(p.author_did));
  if (p.capability_proof)
    m.emplace_back(cbor::Value::Text("capabilityProof"), *p.capability_proof);
  return cbor::Value::Map(std::move(m));
}

bool PullFromCbor(const cbor::Value& v, PullPayload* out) {
  if (!v.IsMap())
    return false;
  const cbor::Value* graph = v.Find("graphDid");
  const cbor::Value* rev = v.Find("fromRevision");
  const cbor::Value* author = v.Find("authorDid");
  if (!graph || !rev || !author)
    return false;
  if (!graph->AsText(&out->graph_did) || !author->AsText(&out->author_did))
    return false;
  if (rev->IsNull()) {
    out->from_revision.reset();
  } else {
    std::string r;
    if (!rev->AsText(&r))
      return false;
    out->from_revision = r;
  }
  const cbor::Value* proof = v.Find("capabilityProof");
  if (proof)
    out->capability_proof = *proof;
  else
    out->capability_proof.reset();
  return true;
}

// ---- §5.4.1 PULL_DENIED ----------------------------------------------------

cbor::Value PullDeniedToCbor(const PullDeniedPayload& p) {
  std::vector<std::pair<cbor::Value, cbor::Value>> m;
  m.emplace_back(cbor::Value::Text("graphDid"), cbor::Value::Text(p.graph_did));
  m.emplace_back(cbor::Value::Text("reason"), cbor::Value::Text(p.reason));
  if (p.constraint_id)
    m.emplace_back(cbor::Value::Text("constraintId"),
                   cbor::Value::Text(*p.constraint_id));
  return cbor::Value::Map(std::move(m));
}

bool PullDeniedFromCbor(const cbor::Value& v, PullDeniedPayload* out) {
  if (!v.IsMap())
    return false;
  const cbor::Value* graph = v.Find("graphDid");
  const cbor::Value* reason = v.Find("reason");
  if (!graph || !reason)
    return false;
  if (!graph->AsText(&out->graph_did) || !reason->AsText(&out->reason))
    return false;
  const cbor::Value* cid = v.Find("constraintId");
  if (cid) {
    std::string s;
    if (!cid->AsText(&s))
      return false;
    out->constraint_id = s;
  } else {
    out->constraint_id.reset();
  }
  return true;
}

// ---- §5.4 SNAPSHOT ---------------------------------------------------------

cbor::Value SnapshotToCbor(const SnapshotPayload& p) {
  return cbor::Value::Map({
      {cbor::Value::Text("graphDid"), cbor::Value::Text(p.graph_did)},
      {cbor::Value::Text("snapshot"), cbor::Value::Bytes(p.snapshot)},
  });
}

bool SnapshotFromCbor(const cbor::Value& v, SnapshotPayload* out) {
  if (!v.IsMap())
    return false;
  const cbor::Value* graph = v.Find("graphDid");
  const cbor::Value* snap = v.Find("snapshot");
  if (!graph || !snap)
    return false;
  return graph->AsText(&out->graph_did) && snap->AsBytes(&out->snapshot);
}

// ---- §5.6 MODULE_UPDATE ----------------------------------------------------

cbor::Value ModuleUpdateToCbor(const ModuleUpdatePayload& p) {
  return cbor::Value::Map({
      {cbor::Value::Text("newHash"), cbor::Value::Text(p.new_hash)},
      {cbor::Value::Text("spaceUri"), cbor::Value::Text(p.space_uri)},
      {cbor::Value::Text("distributionUrls"), TextArray(p.distribution_urls)},
  });
}

bool ModuleUpdateFromCbor(const cbor::Value& v, ModuleUpdatePayload* out) {
  if (!v.IsMap())
    return false;
  const cbor::Value* nh = v.Find("newHash");
  const cbor::Value* su = v.Find("spaceUri");
  const cbor::Value* du = v.Find("distributionUrls");
  if (!nh || !su || !du)
    return false;
  if (!nh->AsText(&out->new_hash) || !su->AsText(&out->space_uri))
    return false;
  return TextArrayFrom(*du, &out->distribution_urls);
}

// ---- §5.5 SIGNAL / §5.7 PEER_HELLO,PEER_BYE --------------------------------

cbor::Value SignalToCbor(const std::string& opaque_bytes) {
  return cbor::Value::Bytes(opaque_bytes);
}

bool SignalFromCbor(const cbor::Value& v, std::string* out) {
  return v.AsBytes(out);
}

cbor::Value PeerAnnounceToCbor(const PeerRef& peer) {
  return cbor::Value::Map({
      {cbor::Value::Text("peer"), PeerRefToCbor(peer)},
  });
}

bool PeerAnnounceFromCbor(const cbor::Value& v, PeerRef* out) {
  if (!v.IsMap())
    return false;
  const cbor::Value* peer = v.Find("peer");
  if (!peer)
    return false;
  return PeerRefFromCbor(*peer, out);
}

// ===========================================================================
// §6.3 primitives
// ===========================================================================

std::string X25519BasePoint() {
  std::string u(32, '\0');
  u[0] = 0x09;
  return u;
}

// ===========================================================================
// §6.3.1 — group_id from space:// URI
// ===========================================================================

bool GroupIdFromSpaceUri(const std::string& space_uri,
                         std::string* group_id_32) {
  static const std::string kScheme = "space://";
  if (space_uri.compare(0, kScheme.size(), kScheme) != 0)
    return false;
  // Authority is everything up to the first path/query/fragment delimiter.
  size_t start = kScheme.size();
  size_t end = space_uri.find_first_of("/?#", start);
  std::string authority = (end == std::string::npos)
                              ? space_uri.substr(start)
                              : space_uri.substr(start, end - start);
  if (authority.size() != 64)
    return false;
  std::string bytes;
  if (!DecodeLowerHex(authority, &bytes) || bytes.size() != 32)
    return false;
  *group_id_32 = std::move(bytes);
  return true;
}

// ===========================================================================
// §6.3.3 — did:key(Ed25519) → X25519
// ===========================================================================

std::string DeriveX25519PrivateScalar(const std::string& ed25519_seed_32,
                                      const SyncCrypto& crypto) {
  std::string h = crypto.sha512(ed25519_seed_32);  // 64 bytes
  if (h.size() < 32)
    return std::string();
  std::string x = h.substr(0, 32);
  // Clamp per RFC 7748 §5.
  x[0] = static_cast<char>(static_cast<unsigned char>(x[0]) & 0xf8);
  x[31] = static_cast<char>((static_cast<unsigned char>(x[31]) & 0x7f) | 0x40);
  return x;
}

std::string DeriveX25519Public(const std::string& x25519_private_32,
                               const SyncCrypto& crypto) {
  return crypto.x25519(x25519_private_32, X25519BasePoint());
}

// ---- curve25519 field arithmetic for the Edwards→Montgomery map ------------
//
// A compact radix-2^51 field (5 × uint64 limbs) over p = 2^255 − 19, used only
// to compute u = (1 + y) / (1 − y) mod p from a peer's Ed25519 public key. Only
// add / sub / mul / invert / (de)serialise are needed. Not constant-time — the
// inputs are public keys.
namespace {

using Fe = std::array<uint64_t, 5>;
constexpr uint64_t kMask51 = 0x7ffffffffffffULL;

uint64_t LoadLe64(const unsigned char* p) {
  uint64_t r = 0;
  for (int i = 0; i < 8; ++i)
    r |= static_cast<uint64_t>(p[i]) << (8 * i);
  return r;
}

// Loads a field element from 32 little-endian bytes, ignoring bit 255.
Fe FeFromBytes(const std::string& s32) {
  unsigned char b[32];
  std::memcpy(b, s32.data(), 32);
  b[31] &= 0x7f;
  uint64_t t0 = LoadLe64(b + 0);
  uint64_t t1 = LoadLe64(b + 8);
  uint64_t t2 = LoadLe64(b + 16);
  uint64_t t3 = LoadLe64(b + 24);
  Fe h;
  h[0] = t0 & kMask51;
  h[1] = ((t0 >> 51) | (t1 << 13)) & kMask51;
  h[2] = ((t1 >> 38) | (t2 << 26)) & kMask51;
  h[3] = ((t2 >> 25) | (t3 << 39)) & kMask51;
  h[4] = (t3 >> 12) & kMask51;
  return h;
}

// Serialises a fully-reduced field element to 32 little-endian bytes.
std::string FeToBytes(Fe h) {
  uint64_t t0 = h[0], t1 = h[1], t2 = h[2], t3 = h[3], t4 = h[4];
  uint64_t c;
  c = t0 >> 51; t0 &= kMask51; t1 += c;
  c = t1 >> 51; t1 &= kMask51; t2 += c;
  c = t2 >> 51; t2 &= kMask51; t3 += c;
  c = t3 >> 51; t3 &= kMask51; t4 += c;
  c = t4 >> 51; t4 &= kMask51; t0 += 19 * c;
  // Conditionally subtract p (compute the carry out of h + 19).
  uint64_t q = (t0 + 19) >> 51;
  q = (t1 + q) >> 51;
  q = (t2 + q) >> 51;
  q = (t3 + q) >> 51;
  q = (t4 + q) >> 51;
  t0 += 19 * q;
  c = t0 >> 51; t0 &= kMask51; t1 += c;
  c = t1 >> 51; t1 &= kMask51; t2 += c;
  c = t2 >> 51; t2 &= kMask51; t3 += c;
  c = t3 >> 51; t3 &= kMask51; t4 += c;
  t4 &= kMask51;

  unsigned char s[32];
  s[0] = static_cast<unsigned char>(t0);
  s[1] = static_cast<unsigned char>(t0 >> 8);
  s[2] = static_cast<unsigned char>(t0 >> 16);
  s[3] = static_cast<unsigned char>(t0 >> 24);
  s[4] = static_cast<unsigned char>(t0 >> 32);
  s[5] = static_cast<unsigned char>(t0 >> 40);
  s[6] = static_cast<unsigned char>((t0 >> 48) | (t1 << 3));
  s[7] = static_cast<unsigned char>(t1 >> 5);
  s[8] = static_cast<unsigned char>(t1 >> 13);
  s[9] = static_cast<unsigned char>(t1 >> 21);
  s[10] = static_cast<unsigned char>(t1 >> 29);
  s[11] = static_cast<unsigned char>(t1 >> 37);
  s[12] = static_cast<unsigned char>((t1 >> 45) | (t2 << 6));
  s[13] = static_cast<unsigned char>(t2 >> 2);
  s[14] = static_cast<unsigned char>(t2 >> 10);
  s[15] = static_cast<unsigned char>(t2 >> 18);
  s[16] = static_cast<unsigned char>(t2 >> 26);
  s[17] = static_cast<unsigned char>(t2 >> 34);
  s[18] = static_cast<unsigned char>(t2 >> 42);
  s[19] = static_cast<unsigned char>((t2 >> 50) | (t3 << 1));
  s[20] = static_cast<unsigned char>(t3 >> 7);
  s[21] = static_cast<unsigned char>(t3 >> 15);
  s[22] = static_cast<unsigned char>(t3 >> 23);
  s[23] = static_cast<unsigned char>(t3 >> 31);
  s[24] = static_cast<unsigned char>(t3 >> 39);
  s[25] = static_cast<unsigned char>((t3 >> 47) | (t4 << 4));
  s[26] = static_cast<unsigned char>(t4 >> 4);
  s[27] = static_cast<unsigned char>(t4 >> 12);
  s[28] = static_cast<unsigned char>(t4 >> 20);
  s[29] = static_cast<unsigned char>(t4 >> 28);
  s[30] = static_cast<unsigned char>(t4 >> 36);
  s[31] = static_cast<unsigned char>(t4 >> 44);
  return std::string(reinterpret_cast<char*>(s), 32);
}

Fe FeZero() { return Fe{0, 0, 0, 0, 0}; }
Fe FeOne() { return Fe{1, 0, 0, 0, 0}; }

Fe FeAdd(const Fe& f, const Fe& g) {
  return Fe{f[0] + g[0], f[1] + g[1], f[2] + g[2], f[3] + g[3], f[4] + g[4]};
}

// f − g, biased by 2p so limbs stay non-negative.
Fe FeSub(const Fe& f, const Fe& g) {
  return Fe{
      f[0] + 0xfffffffffffdaULL - g[0],
      f[1] + 0xffffffffffffeULL - g[1],
      f[2] + 0xffffffffffffeULL - g[2],
      f[3] + 0xffffffffffffeULL - g[3],
      f[4] + 0xffffffffffffeULL - g[4],
  };
}

Fe FeMul(const Fe& f, const Fe& g) {
  using u128 = unsigned __int128;
  uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
  uint64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
  uint64_t f1_19 = 19 * f1, f2_19 = 19 * f2, f3_19 = 19 * f3, f4_19 = 19 * f4;

  u128 r0 = (u128)f0 * g0 + (u128)f1_19 * g4 + (u128)f2_19 * g3 +
            (u128)f3_19 * g2 + (u128)f4_19 * g1;
  u128 r1 = (u128)f0 * g1 + (u128)f1 * g0 + (u128)f2_19 * g4 +
            (u128)f3_19 * g3 + (u128)f4_19 * g2;
  u128 r2 = (u128)f0 * g2 + (u128)f1 * g1 + (u128)f2 * g0 + (u128)f3_19 * g4 +
            (u128)f4_19 * g3;
  u128 r3 = (u128)f0 * g3 + (u128)f1 * g2 + (u128)f2 * g1 + (u128)f3 * g0 +
            (u128)f4_19 * g4;
  u128 r4 = (u128)f0 * g4 + (u128)f1 * g3 + (u128)f2 * g2 + (u128)f3 * g1 +
            (u128)f4 * g0;

  uint64_t c;
  uint64_t h0, h1, h2, h3, h4;
  c = static_cast<uint64_t>(r0 >> 51); h0 = static_cast<uint64_t>(r0) & kMask51;
  r1 += c;
  c = static_cast<uint64_t>(r1 >> 51); h1 = static_cast<uint64_t>(r1) & kMask51;
  r2 += c;
  c = static_cast<uint64_t>(r2 >> 51); h2 = static_cast<uint64_t>(r2) & kMask51;
  r3 += c;
  c = static_cast<uint64_t>(r3 >> 51); h3 = static_cast<uint64_t>(r3) & kMask51;
  r4 += c;
  c = static_cast<uint64_t>(r4 >> 51); h4 = static_cast<uint64_t>(r4) & kMask51;
  h0 += 19 * c;
  c = h0 >> 51; h0 &= kMask51; h1 += c;
  return Fe{h0, h1, h2, h3, h4};
}

// f^(p−2) mod p via square-and-multiply over the fixed exponent
// p − 2 = 2^255 − 21 = 0x7f ff…ff eb (big-endian).
Fe FeInvert(const Fe& f) {
  static const unsigned char kPminus2[32] = {
      0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xeb};
  Fe result = FeOne();
  bool started = false;
  for (int i = 0; i < 32; ++i) {
    for (int bit = 7; bit >= 0; --bit) {
      if (started)
        result = FeMul(result, result);
      if ((kPminus2[i] >> bit) & 1) {
        result = started ? FeMul(result, f) : f;
        started = true;
      }
    }
  }
  return result;
}

bool FeIsZero(const Fe& f) {
  std::string b = FeToBytes(f);
  for (char c : b) {
    if (c != 0)
      return false;
  }
  return true;
}

}  // namespace

bool Ed25519PubToX25519Pub(const std::string& ed25519_public_32,
                           std::string* x25519_public_32) {
  if (ed25519_public_32.size() != 32)
    return false;
  Fe y = FeFromBytes(ed25519_public_32);
  Fe one = FeOne();
  Fe num = FeAdd(one, y);        // 1 + y
  Fe den = FeSub(one, y);        // 1 − y
  if (FeIsZero(den))             // y == 1: excluded point
    return false;
  Fe u = FeMul(num, FeInvert(den));
  *x25519_public_32 = FeToBytes(u);
  return true;
}

bool VerifyEncryptionKeyBinding(const std::string& credential_ed25519_public_32,
                                const std::string& leaf_encryption_key_32) {
  std::string derived;
  if (!Ed25519PubToX25519Pub(credential_ed25519_public_32, &derived))
    return false;
  return derived == leaf_encryption_key_32;
}

// ===========================================================================
// §6.3.9 — Key schedule
// ===========================================================================

std::string HkdfExpandSha256(const std::string& prk,
                             const std::string& info,
                             size_t length,
                             const SyncCrypto& crypto) {
  if (length == 0)
    return std::string();
  const size_t kHashLen = 32;
  if (length > 255 * kHashLen)
    return std::string();
  std::string okm;
  std::string t;  // T(0) is empty
  uint8_t counter = 1;
  while (okm.size() < length) {
    std::string input = t + info;
    input.push_back(static_cast<char>(counter));
    t = crypto.hmac_sha256(prk, input);
    okm += t;
    ++counter;
  }
  okm.resize(length);
  return okm;
}

std::string ExpandWithLabel(const std::string& secret,
                            const std::string& label,
                            const std::string& context,
                            size_t length,
                            const SyncCrypto& crypto) {
  // KDFLabel = uint16(length) ‖ opaque<V>("MLS 1.0 "+label) ‖ opaque<V>(context)
  std::string kdf_label = I2OSP(length, 2);
  AppendOpaqueV(&kdf_label, "MLS 1.0 " + label);
  AppendOpaqueV(&kdf_label, context);
  return HkdfExpandSha256(secret, kdf_label, length, crypto);
}

std::string DeriveSecret(const std::string& secret,
                         const std::string& label,
                         const SyncCrypto& crypto) {
  return ExpandWithLabel(secret, label, std::string(), 32, crypto);
}

std::string MlsExporter(const std::string& exporter_secret,
                        const std::string& label,
                        const std::string& context,
                        size_t length,
                        const SyncCrypto& crypto) {
  // RFC 9420 §8.5.
  std::string derived = DeriveSecret(exporter_secret, label, crypto);
  std::string hashed_context = crypto.sha256(context);
  return ExpandWithLabel(derived, "exported", hashed_context, length, crypto);
}

std::string DeriveSpaceTrafficSecret(const std::string& exporter_secret,
                                     const std::string& space_uri,
                                     const SyncCrypto& crypto) {
  return MlsExporter(exporter_secret, kSpaceFrameExporterLabel, space_uri, 32,
                     crypto);
}

FrameKeys DeriveFrameKeys(const std::string& space_traffic_secret,
                          const SyncCrypto& crypto) {
  FrameKeys keys;
  keys.key =
      ExpandWithLabel(space_traffic_secret, "key", std::string(), 16, crypto);
  keys.nonce =
      ExpandWithLabel(space_traffic_secret, "nonce", std::string(), 12, crypto);
  return keys;
}

FrameKeys DeriveFrameKeysFromExporter(const std::string& exporter_secret,
                                      const std::string& space_uri,
                                      const SyncCrypto& crypto) {
  return DeriveFrameKeys(
      DeriveSpaceTrafficSecret(exporter_secret, space_uri, crypto), crypto);
}

// ===========================================================================
// §6.3.10 — Message encryption
// ===========================================================================

std::string FrameNonce(const std::string& base_nonce_12, uint64_t seq) {
  std::string n = base_nonce_12;
  if (n.size() != 12)
    n.resize(12, '\0');
  // XOR the big-endian 96-bit seq (top 4 bytes zero for a uint64) into the
  // base nonce.
  std::string seq_be = I2OSP(seq, 12);
  for (size_t i = 0; i < 12; ++i)
    n[i] = static_cast<char>(static_cast<unsigned char>(n[i]) ^
                             static_cast<unsigned char>(seq_be[i]));
  return n;
}

std::string FrameAad(FrameType type,
                     const std::string& space_uri,
                     const PeerRef& from,
                     const std::optional<PeerRef>& to,
                     uint64_t epoch,
                     uint64_t seq) {
  std::vector<cbor::Value> arr;
  arr.push_back(cbor::Value::Text(FrameTypeToToken(type)));
  arr.push_back(cbor::Value::Text(space_uri));
  arr.push_back(cbor::Value::Text(from.did));
  arr.push_back(cbor::Value::Text(from.session_id));
  if (to) {
    arr.push_back(cbor::Value::Array({cbor::Value::Text(to->did),
                                      cbor::Value::Text(to->session_id)}));
  } else {
    arr.push_back(cbor::Value::Null());
  }
  arr.push_back(cbor::Value::Uint(epoch));
  arr.push_back(cbor::Value::Uint(seq));
  return cbor::Encode(cbor::Value::Array(std::move(arr)));
}

bool SealFrame(const FrameKeys& keys,
               const WireFrame& plain,
               uint64_t epoch,
               uint64_t seq,
               const SyncCrypto& crypto,
               EncryptedFrame* out) {
  std::string p = cbor::Encode(plain.payload);
  std::string nonce = FrameNonce(keys.nonce, seq);
  std::string aad =
      FrameAad(plain.type, plain.space_uri, plain.from, plain.to, epoch, seq);
  std::string ct;
  if (!crypto.aes128gcm_seal(keys.key, nonce, aad, p, &ct))
    return false;
  out->type = plain.type;
  out->space_uri = plain.space_uri;
  out->from = plain.from;
  out->to = plain.to;
  out->epoch = epoch;
  out->seq = seq;
  out->ct = std::move(ct);
  return true;
}

bool OpenFrame(const FrameKeys& keys,
               const EncryptedFrame& enc,
               const SyncCrypto& crypto,
               WireFrame* out) {
  std::string nonce = FrameNonce(keys.nonce, enc.seq);
  std::string aad = FrameAad(enc.type, enc.space_uri, enc.from, enc.to,
                             enc.epoch, enc.seq);
  std::string p;
  if (!crypto.aes128gcm_open(keys.key, nonce, aad, enc.ct, &p))
    return false;
  cbor::Value payload;
  if (!cbor::Decode(p, &payload))
    return false;
  out->type = enc.type;
  out->space_uri = enc.space_uri;
  out->from = enc.from;
  out->to = enc.to;
  out->payload = std::move(payload);
  return true;
}

std::string EncodeEncryptedFrame(const EncryptedFrame& frame) {
  cbor::Value enc = cbor::Value::Map({
      {cbor::Value::Text("epoch"), cbor::Value::Uint(frame.epoch)},
      {cbor::Value::Text("seq"), cbor::Value::Uint(frame.seq)},
      {cbor::Value::Text("ct"), cbor::Value::Bytes(frame.ct)},
  });
  cbor::Value m = cbor::Value::Map({
      {cbor::Value::Text("type"),
       cbor::Value::Text(FrameTypeToToken(frame.type))},
      {cbor::Value::Text("spaceUri"), cbor::Value::Text(frame.space_uri)},
      {cbor::Value::Text("from"), PeerRefToCbor(frame.from)},
      {cbor::Value::Text("to"),
       frame.to ? PeerRefToCbor(*frame.to) : cbor::Value::Null()},
      {cbor::Value::Text("enc"), std::move(enc)},
  });
  return cbor::Encode(m);
}

bool DecodeEncryptedFrame(const std::string& in, EncryptedFrame* out) {
  cbor::Value m;
  if (!cbor::Decode(in, &m) || !m.IsMap())
    return false;
  const cbor::Value* type = m.Find("type");
  const cbor::Value* space = m.Find("spaceUri");
  const cbor::Value* from = m.Find("from");
  const cbor::Value* to = m.Find("to");
  const cbor::Value* enc = m.Find("enc");
  if (!type || !space || !from || !to || !enc || !enc->IsMap())
    return false;
  std::string token;
  if (!type->AsText(&token) || !FrameTypeFromToken(token, &out->type))
    return false;
  if (!space->AsText(&out->space_uri))
    return false;
  if (!PeerRefFromCbor(*from, &out->from))
    return false;
  if (to->IsNull()) {
    out->to.reset();
  } else {
    PeerRef p;
    if (!PeerRefFromCbor(*to, &p))
      return false;
    out->to = p;
  }
  const cbor::Value* epoch = enc->Find("epoch");
  const cbor::Value* seq = enc->Find("seq");
  const cbor::Value* ct = enc->Find("ct");
  if (!epoch || !seq || !ct)
    return false;
  if (!epoch->AsUint(&out->epoch) || !seq->AsUint(&out->seq))
    return false;
  return ct->AsBytes(&out->ct);
}

// ===========================================================================
// §8 — OR-Set merge semantics
// ===========================================================================

void OrSet::Add(const std::string& triple_id, const std::string& tag) {
  added_[triple_id].insert(tag);
}

void OrSet::Remove(const std::string& triple_id, const std::string& tag) {
  removed_[triple_id].insert(tag);
}

void OrSet::ApplyDiff(const DiffWire& diff) {
  for (const Triple& t : diff.additions)
    Add(SerializeTripleNt(t), diff.revision);
  for (const DiffRemoval& r : diff.removals) {
    std::string id = SerializeTripleNt(r.triple);
    for (const std::string& tag : r.removed_tags)
      Remove(id, tag);
  }
}

bool OrSet::Contains(const std::string& triple_id) const {
  auto it = added_.find(triple_id);
  if (it == added_.end())
    return false;
  auto rit = removed_.find(triple_id);
  if (rit == removed_.end())
    return !it->second.empty();
  for (const std::string& tag : it->second) {
    if (rit->second.find(tag) == rit->second.end())
      return true;  // a live (un-removed) add-tag exists
  }
  return false;
}

std::vector<std::string> OrSet::Members() const {
  std::vector<std::string> out;
  for (const auto& kv : added_) {
    if (Contains(kv.first))
      out.push_back(kv.first);
  }
  return out;  // added_ is an ordered map, so this is sorted
}

size_t OrSet::Size() const {
  size_t n = 0;
  for (const auto& kv : added_) {
    if (Contains(kv.first))
      ++n;
  }
  return n;
}

bool IsChainRoot(const DiffWire& diff) {
  return diff.dependencies.empty();
}

bool AcceptChainRoot(const DiffWire& diff, bool graph_has_unrelated_diffs) {
  if (!IsChainRoot(diff))
    return false;
  // §8.2 — a chain-root is rejected if the graph already carries unrelated
  // diffs (a probable fork / corruption signal).
  return !graph_has_unrelated_diffs;
}

int CompareReifierHash(const std::string& hash_a, const std::string& hash_b) {
  if (hash_a < hash_b)
    return -1;
  if (hash_a > hash_b)
    return 1;
  return 0;
}

const std::string& FlowStateWinner(const std::string& hash_a,
                                   const std::string& hash_b) {
  return (hash_b < hash_a) ? hash_b : hash_a;
}

// ===========================================================================
// §9 — Snapshot promotion
// ===========================================================================

bool ShouldPromote(uint32_t diffs_since_snapshot, uint32_t threshold) {
  return diffs_since_snapshot >= threshold;
}

}  // namespace default_sync
}  // namespace living_web
