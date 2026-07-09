// Living Web Standalone Library
// Shared value types with no Chromium dependencies.
//
// The base ships this header with the namespace only. Each per-spec branch adds
// the structs and enums it introduces (e.g. Spec 01 adds the DID key/proof
// types, Spec 02 adds the semantic-triple types), so every type is introduced by
// the PR that first needs it.
#ifndef LIVING_WEB_TYPES_H_
#define LIVING_WEB_TYPES_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace living_web {

// ---- Spec 01: Decentralised Identity ----

// A DID credential: an Ed25519 keypair plus its algorithmically-derived DID URI
// and metadata (§3, §4.1). |method| is the DID method whose identifier |did|
// carries: "key" for did:key (Spec 01) or "graph" for did:graph (Spec 03). The
// keypair encoding is identical across methods, so a did:graph group's initial
// key is stored as an ordinary DIDKeyPair with method = "graph". |method_id| is
// the verification-method id (DID URL) this key is referenced by inside its DID
// document: "<did>#<publicKeyMultibase>" (Spec 03 §4.4). It is empty for keys
// that are not (yet) a DID-document verification method.
struct DIDKeyPair {
  std::string id;
  std::string did;
  std::string display_name;
  std::string algorithm;
  std::string created_at;
  bool is_locked = false;
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> private_key;
  std::string method = "key";
  std::string method_id;
};

// Result of sign()/signCapability() (§6.1, §6.3, §6.4). The proof is carried as
// flat fields; the renderer/mojo surface reassembles it into a ContentProof
// { method, signature, type } object.
struct SignedContentResult {
  std::string author;
  std::string timestamp;
  std::string data_json;
  std::string proof_method;  // verification method id (DID URI + fragment)
  std::string proof_sig;     // multibase(base58btc, 'z') Ed25519 signature
  std::string proof_type;    // "Ed25519Signature2020"
};

}  // namespace living_web

#endif  // LIVING_WEB_TYPES_H_
