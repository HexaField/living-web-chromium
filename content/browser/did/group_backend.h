// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GroupBackend — the browser-process port of the §8.1 `Group` API of Spec 03
// (Decentralised Group Identity). A faithful C++ port of living_web::Group
// (standalone/group_provider.h) onto the browser cores content::GraphBackend
// (the Spec 02 host graph the group lives inside) and content::DIDKeyProvider
// (which stores the group's initial key so group-authored writes resolve
// through the ordinary SignRaw path). The two ports share the Chromium-
// independent did:graph codec + DID-document model (content/browser/did/
// did_graph.*), so the standalone conformance harness and the browser never
// diverge on the triples written, signed, or projected.
//
// A "group" is a groupified Graph: a fresh Ed25519 keypair is minted, a
// `did:graph:...` is derived from it, and the binding + seed DID-document
// triples are written into the host graph (§4.2). The DID document *is* triples
// in the host graph — adding a delegate authors `did://verificationMethod` +
// `did://<section>` triples; resolving the DID projects them back
// (group_detail::ProjectDidDocument). Signing authority (DID-document
// delegates, §5/§7.2) and participation (context://participates_in /
// accepts_participation, §6.2/§7.1) are kept structurally separate exactly as
// §7 requires.
//
// The group_detail helpers here are shared by both group_backend.cc and
// group_backend_manager.cc, so they live in the header rather than either .cc.

#ifndef CONTENT_BROWSER_DID_GROUP_BACKEND_H_
#define CONTENT_BROWSER_DID_GROUP_BACKEND_H_

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/rdf_serialization.h"

namespace content {

class GroupBackend;
class GroupBackendManager;

// A DID-document verification method as accepted by the delegate-management API
// (§5.4 `DIDDocumentMethod`). The projected-document type carries exactly these
// fields, so we reuse it verbatim.
using DIDDocumentMethod = living_web::VerificationMethod;

// ---- Spec 03 API option types (§8.2) --------------------------------------

// §8.2 createGroup / GroupCreationOptions. `sync_module` is REQUIRED (§4.5).
struct GroupCreationOptions {
  std::string sync_module;                     // REQUIRED — content hash (§4.5)
  std::optional<std::string> display_name;
  std::optional<std::string> description;
  std::vector<std::string> initial_delegates;  // extra capabilityInvocation DIDs
  std::optional<std::string> participates_in;  // parent IRI or did:graph
};

// §8.2 groupify / GroupifyOptions. `sync_module` is REQUIRED (§4.5).
struct GroupifyOptions {
  std::string sync_module;                     // REQUIRED — content hash (§4.5)
  std::optional<std::string> display_name;
  std::optional<std::string> description;
  std::vector<std::string> initial_delegates;
};

// §8.2 forkGroup / ForkOptions. `sync_module` is REQUIRED (MAY equal parent's).
struct ForkOptions {
  std::string sync_module;                    // REQUIRED (§4.8.1)
  std::optional<std::string> fork_revision;   // defaults to parent's current IRI
  bool announce_fork = true;                  // write group://forkedTo on parent
  std::vector<std::string> initial_delegates;
  std::optional<std::string> display_name;
  std::optional<std::string> description;
};

// §8.1 Participant.
struct Participant {
  Participant();
  ~Participant();
  Participant(const Participant&);
  Participant& operator=(const Participant&);
  Participant(Participant&&);
  Participant& operator=(Participant&&);

  std::string did;                   // participant IRI or did:graph
  bool is_group = false;             // true iff a did:graph
  std::string joined_at;             // RFC 3339, from accepts_participation reifier
  std::optional<std::string> name;   // group://name of the participant, if resolvable
};

namespace group_detail {

// XSD datatype IRIs used by the seed/metadata literals not already exposed by
// rdf_serialization.h (which supplies kXsdString and kXsdDateTime).
inline constexpr char kXsdBoolean[] = "http://www.w3.org/2001/XMLSchema#boolean";

// ---- triple builders ------------------------------------------------------

inline living_web::Triple T_iri(const std::string& s,
                                const std::string& p,
                                const std::string& iri) {
  return living_web::Triple{s, p, living_web::ObjectTerm::Iri(iri)};
}

inline living_web::Triple T_lit(
    const std::string& s,
    const std::string& p,
    const std::string& lex,
    const std::string& datatype = living_web::kXsdString) {
  living_web::LiteralValue lv;
  lv.lexical = lex;
  lv.datatype = datatype;
  return living_web::Triple{s, p, living_web::ObjectTerm::Literal(lv)};
}

// The verification-method id for |public_key| under |did|: "<did>#<multibase>"
// (SPEC_COMPLIANCE amendment 03/§4.4 — the fragment is the method's own key).
inline std::string MethodId(const std::string& did,
                            const std::vector<uint8_t>& public_key) {
  return did + "#" + *living_web::did_key::Ed25519PublicKeyMultibase(public_key);
}

// Builds the group's DID-document verification method for a delegate identified
// by |delegate_did| (a did:key or did:graph). The method is controlled by the
// group DID (§4.4: every method's controller is the group). nullopt if the DID
// does not carry a 32-byte Ed25519 key.
inline std::optional<living_web::VerificationMethod> MethodFromDelegateDid(
    const std::string& group_did,
    const std::string& delegate_did) {
  auto pk = living_web::ParseAnyDidEd25519(delegate_did);
  if (!pk || pk->size() != 32)
    return std::nullopt;
  auto mb = living_web::did_key::Ed25519PublicKeyMultibase(*pk);
  if (!mb)
    return std::nullopt;
  living_web::VerificationMethod vm;
  vm.id = group_did + "#" + *mb;
  vm.type = living_web::kEd25519VerificationKey2020;
  vm.controller = group_did;
  vm.public_key_multibase = *mb;
  return vm;
}

// Appends the four triples that introduce |vm| into the DID document of |did|:
// the verificationMethod membership plus the type/controller/publicKeyMultibase
// attributes (§4.4).
inline void AppendMethod(const std::string& did,
                         const living_web::VerificationMethod& vm,
                         std::vector<living_web::Triple>* out) {
  out->push_back(T_iri(did, living_web::kDidVerificationMethod, vm.id));
  out->push_back(T_lit(vm.id, living_web::kDidVmType, vm.type));
  out->push_back(T_iri(vm.id, living_web::kDidVmController, vm.controller));
  out->push_back(
      T_lit(vm.id, living_web::kDidVmPublicKeyMultibase, vm.public_key_multibase));
}

// RAII: make |cred_id| the provider's active credential for the duration of a
// write batch, restoring the previous active credential on scope exit. Graph
// mutations sign their reifiers with the active credential, so this is how a
// specific delegate's key is bound as the author of a DID-document write.
class ScopedActive {
 public:
  ScopedActive(DIDKeyProvider* identity, const std::string& cred_id)
      : identity_(identity) {
    if (const DIDKeyPair* prev = identity_->GetActiveCredential()) {
      had_prev_ = true;
      prev_id_ = prev->id;
    }
    identity_->SetActiveCredential(cred_id);
  }
  ~ScopedActive() {
    if (had_prev_)
      identity_->SetActiveCredential(prev_id_);
  }
  ScopedActive(const ScopedActive&) = delete;
  ScopedActive& operator=(const ScopedActive&) = delete;

 private:
  raw_ptr<DIDKeyProvider> identity_;
  bool had_prev_ = false;
  std::string prev_id_;
};

// ---- DID-document projection (§4.4, §4.7 local resolution) -----------------

// Every distinct object term of (subject, predicate) in |g|, de-duplicated. The
// reifier join in GraphBackend::QueryTriples can surface the same data triple
// once per reifier, so callers that count or list MUST dedupe — done here.
inline std::vector<living_web::ObjectTerm> QueryObjects(
    GraphBackend* g,
    const std::string& subject,
    const std::string& predicate) {
  TripleQuery q;
  q.subject = subject;
  q.predicate = predicate;
  std::vector<living_web::Triple> ts;
  std::vector<living_web::ObjectTerm> out;
  if (!g->QueryTriples(q, &ts))
    return out;
  std::set<std::string> seen;
  for (const auto& t : ts) {
    std::string key = t.object.is_literal()
                          ? "L\x1f" + t.object.literal->lexical + "\x1f" +
                                t.object.literal->datatype
                          : "I\x1f" + t.object.iri_or_bnode;
    if (seen.insert(key).second)
      out.push_back(t.object);
  }
  return out;
}

inline std::optional<std::string> FirstLiteralOf(GraphBackend* g,
                                                 const std::string& subject,
                                                 const std::string& predicate) {
  for (const auto& o : QueryObjects(g, subject, predicate))
    if (o.is_literal())
      return o.literal->lexical;
  return std::nullopt;
}

inline std::optional<std::string> FirstIriOf(GraphBackend* g,
                                             const std::string& subject,
                                             const std::string& predicate) {
  for (const auto& o : QueryObjects(g, subject, predicate))
    if (!o.is_literal())
      return o.iri_or_bnode;
  return std::nullopt;
}

// Projects the §4.4 did://* triples for |did| out of host graph |g| into a
// DidDocument, with trustLevel "local" (§4.7 step 1 — a local mount). Section
// membership and verificationMethod ids are de-duplicated.
inline bool ProjectDidDocument(GraphBackend* g,
                               const std::string& did,
                               living_web::DidDocument* out) {
  out->id = did;
  out->trust_level = "local";
  out->deactivated = false;
  out->verification_method.clear();
  out->capability_invocation.clear();
  out->capability_delegation.clear();
  out->assertion_method.clear();
  out->authentication.clear();

  auto section = [&](living_web::DIDCapabilitySection s,
                     std::vector<std::string>* dst) {
    for (const auto& o : QueryObjects(g, did, living_web::SectionPredicate(s)))
      if (!o.is_literal())
        dst->push_back(o.iri_or_bnode);
  };
  section(living_web::DIDCapabilitySection::kCapabilityInvocation,
          &out->capability_invocation);
  section(living_web::DIDCapabilitySection::kCapabilityDelegation,
          &out->capability_delegation);
  section(living_web::DIDCapabilitySection::kAssertionMethod,
          &out->assertion_method);
  section(living_web::DIDCapabilitySection::kAuthentication,
          &out->authentication);

  for (const auto& o :
       QueryObjects(g, did, living_web::kDidVerificationMethod)) {
    if (o.is_literal())
      continue;
    living_web::VerificationMethod vm;
    vm.id = o.iri_or_bnode;
    if (auto t = FirstLiteralOf(g, vm.id, living_web::kDidVmType))
      vm.type = *t;
    if (auto c = FirstIriOf(g, vm.id, living_web::kDidVmController))
      vm.controller = *c;
    if (auto pk = FirstLiteralOf(g, vm.id, living_web::kDidVmPublicKeyMultibase))
      vm.public_key_multibase = *pk;
    out->verification_method.push_back(std::move(vm));
  }

  if (auto d = FirstLiteralOf(g, did, living_web::kDidDeactivated))
    out->deactivated = (*d == "true");
  return true;
}

// A minimal JSON object serialisation of signGraph's payload (§5.4 step 3),
// `{ graphDid, graphIri, timestamp }`. sign() re-canonicalises via JCS, so key
// order here is irrelevant; strings are RFC 8259 escaped. |graph_did| absent
// serialises to a JSON null (a graph without a DID).
inline std::string SignGraphPayload(const std::optional<std::string>& graph_did,
                                    const std::string& graph_iri,
                                    const std::string& timestamp) {
  auto esc = [](const std::string& s) {
    std::string o;
    o.reserve(s.size() + 2);
    for (char c : s) {
      switch (c) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
          if (static_cast<unsigned char>(c) < 0x20) {
            static const char kHex[] = "0123456789abcdef";
            o += "\\u00";
            o += kHex[(c >> 4) & 0xf];
            o += kHex[c & 0xf];
          } else {
            o += c;
          }
      }
    }
    return o;
  };
  std::string did_field =
      graph_did ? "\"" + esc(*graph_did) + "\"" : std::string("null");
  return "{\"graphDid\":" + did_field + ",\"graphIri\":\"" + esc(graph_iri) +
         "\",\"timestamp\":\"" + esc(timestamp) + "\"}";
}

}  // namespace group_detail

// ---- GroupBackend (§8.1) ---------------------------------------------------

// The §8.1 convenience handle over a groupified GraphBackend + its did:graph
// identity. It is a *non-owning* view: the host GraphBackend is owned by the
// GraphBackendManager, and the GroupBackendManager indexes it. Every operation
// is expressible directly on the underlying GraphBackend + DIDKeyProvider; this
// class just packages the common flows.
//
// The "acting credential" is the delegate key whose signature authors writes
// and signs assertions. It defaults to the group's own initial-key credential
// (which holds all four sections, so a group-of-one works out of the box, §11);
// callers hand off to another delegate via SetActingCredential().
class GroupBackend {
 public:
  GroupBackend(DIDKeyProvider* identity,
               GroupBackendManager* manager,
               GraphBackend* graph,
               std::string did,
               std::string group_credential_id);

  GroupBackend(const GroupBackend&) = delete;
  GroupBackend& operator=(const GroupBackend&) = delete;

  ~GroupBackend();

  // ---- attributes (§8.1) ----
  const std::string& did() const { return did_; }
  GraphBackend* graph() const { return graph_; }
  const std::string& last_error() const { return last_error_; }

  // The group's own constitutional credential (its DID == did()): the initial-key
  // delegate seeded into all four capability sections at groupification (§4.2).
  // This is the constitutional signer that mints the group's root capability
  // (Spec 04 §4.3) — its DID becomes the root invoker, so any capabilityDelegation
  // delegate can delegate from the root (§7 / Spec 04 §8.1.5).
  const std::string& own_credential_id() const { return group_credential_id_; }

  // The delegate credential currently authoring writes / signing delegations
  // (§8.1.5). Defaults to own_credential_id(); SetActingCredential() overrides.
  std::string acting_credential_id() const { return ActingCredId(); }

  bool GetIri(std::string* out);

  std::optional<std::string> name() {
    return group_detail::FirstLiteralOf(graph_, did_, living_web::kGroupName);
  }
  std::optional<std::string> description() {
    return group_detail::FirstLiteralOf(graph_, did_,
                                        living_web::kGroupDescription);
  }
  std::optional<std::string> created() {
    return group_detail::FirstLiteralOf(graph_, did_, living_web::kGroupCreated);
  }
  std::optional<std::string> creator() {
    return group_detail::FirstIriOf(graph_, did_, living_web::kGroupCreator);
  }

  // The delegate credential authoring writes / signing assertions. Empty ==
  // fall back to the provider's currently-active credential.
  void SetActingCredential(std::string credential_id) {
    acting_credential_id_ = std::move(credential_id);
  }

  // ---- participation (§6.2, §7.1, §8.1.1-8.1.3) ----

  // §8.1.1 invite: write the group's acceptance triple. §6.2 requires it to be
  // authored by a capabilityDelegation delegate of the group.
  bool Invite(const std::string& participant) {
    if (!RequireDelegate(living_web::DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Write({group_detail::T_iri(
        did_, living_web::kContextAcceptsParticipation, participant)});
  }

  // §8.1.2 revokeParticipation: remove the group's acceptance triple.
  bool RevokeParticipation(const std::string& participant) {
    if (!RequireDelegate(living_web::DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Remove(group_detail::T_iri(
        did_, living_web::kContextAcceptsParticipation, participant));
  }

  bool HasParticipant(const std::string& participant) {
    for (const auto& o : group_detail::QueryObjects(
             graph_, did_, living_web::kContextAcceptsParticipation))
      if (!o.is_literal() && o.iri_or_bnode == participant)
        return true;
    return false;
  }

  // §8.1.3 participants: the direct participant set (accepts_participation
  // objects), each tagged group/individual with its join timestamp.
  std::vector<Participant> Participants() {
    std::vector<Participant> out;
    for (const auto& o : group_detail::QueryObjects(
             graph_, did_, living_web::kContextAcceptsParticipation)) {
      if (o.is_literal())
        continue;
      out.push_back(MakeParticipant(o.iri_or_bnode));
    }
    return out;
  }

  // §8.1.3 transitiveParticipants: every individual (non-group) participant
  // reachable by recursively descending into participating sub-groups. Cycle
  // detection + a depth cap of 16 per §6.3 / §13.7.
  std::vector<Participant> TransitiveParticipants();

  // §8.1 parentGroups: the groups this group participates in (named by this
  // group's own context://participates_in triples). Only locally-resolvable
  // ones are returned (resolution is bounded by local mounts, §4.7).
  std::vector<std::unique_ptr<GroupBackend>> ParentGroups();

  // §8.1 childGroups: the participants of this group that are themselves groups.
  std::vector<std::unique_ptr<GroupBackend>> ChildGroups();

  // ---- signing authority / delegate management (§5, §7.2, §8.1.4) ----

  // §8.1 signers: the DID-document methods, optionally filtered to one section.
  std::vector<living_web::VerificationMethod> Signers(
      std::optional<living_web::DIDCapabilitySection> section = std::nullopt) {
    living_web::DidDocument doc;
    group_detail::ProjectDidDocument(graph_, did_, &doc);
    if (!section)
      return doc.verification_method;
    std::vector<living_web::VerificationMethod> out;
    for (const auto& vm : doc.verification_method)
      if (doc.InSection(*section, vm.id))
        out.push_back(vm);
    return out;
  }

  // §8.1.4 / §5.4 addSigner (== addDelegate): introduce |method| and grant it
  // |sections|. Requires a capabilityDelegation delegate (§5.4 -> NotAllowedError).
  bool AddSigner(const living_web::VerificationMethod& method,
                 const std::vector<living_web::DIDCapabilitySection>& sections) {
    if (!RequireDelegate(living_web::DIDCapabilitySection::kCapabilityDelegation))
      return false;
    std::vector<living_web::Triple> batch;
    group_detail::AppendMethod(did_, method, &batch);
    for (living_web::DIDCapabilitySection s : sections)
      batch.push_back(
          group_detail::T_iri(did_, living_web::SectionPredicate(s), method.id));
    return Write(batch);
  }
  bool AddDelegate(
      const living_web::VerificationMethod& method,
      const std::vector<living_web::DIDCapabilitySection>& sections) {
    return AddSigner(method, sections);
  }

  // §8.1.4 / §5.4 removeSigner (== removeDelegate): remove |method_id| entirely.
  // Refuses with "InvalidStateError" if it is the sole capabilityDelegation
  // member (§5.4 brick-state guard); requires a capabilityDelegation delegate.
  bool RemoveSigner(const std::string& method_id) {
    if (!RequireDelegate(living_web::DIDCapabilitySection::kCapabilityDelegation))
      return false;
    living_web::DidDocument doc;
    group_detail::ProjectDidDocument(graph_, did_, &doc);
    if (doc.InSection(living_web::DIDCapabilitySection::kCapabilityDelegation,
                      method_id) &&
        doc.SectionSize(
            living_web::DIDCapabilitySection::kCapabilityDelegation) == 1) {
      last_error_ = "InvalidStateError";
      return false;
    }
    return RemoveMethod(method_id);
  }
  bool RemoveDelegate(const std::string& method_id) {
    return RemoveSigner(method_id);
  }

  // §5.4 grantSection: add |method_id| to |section|. capabilityDelegation gated.
  bool GrantSection(const std::string& method_id,
                    living_web::DIDCapabilitySection section) {
    if (!RequireDelegate(living_web::DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Write({group_detail::T_iri(
        did_, living_web::SectionPredicate(section), method_id)});
  }

  // §5.4 revokeSection: remove |method_id| from |section| (the method stays in
  // verificationMethod). Refuses with "InvalidStateError" if |section| is
  // capabilityDelegation and |method_id| is its only member (brick-state).
  bool RevokeSection(const std::string& method_id,
                     living_web::DIDCapabilitySection section) {
    if (!RequireDelegate(living_web::DIDCapabilitySection::kCapabilityDelegation))
      return false;
    if (section == living_web::DIDCapabilitySection::kCapabilityDelegation) {
      living_web::DidDocument doc;
      group_detail::ProjectDidDocument(graph_, did_, &doc);
      if (doc.InSection(section, method_id) && doc.SectionSize(section) == 1) {
        last_error_ = "InvalidStateError";
        return false;
      }
    }
    return Remove(group_detail::T_iri(
        did_, living_web::SectionPredicate(section), method_id));
  }

  // §8.1 isSigner: is |delegate_did|'s key currently a signer (optionally in a
  // specific section)? The method id is "<group-did>#<delegate-key-multibase>".
  bool IsSigner(
      const std::string& delegate_did,
      std::optional<living_web::DIDCapabilitySection> section = std::nullopt) {
    auto vm = group_detail::MethodFromDelegateDid(did_, delegate_did);
    if (!vm)
      return false;
    living_web::DidDocument doc;
    group_detail::ProjectDidDocument(graph_, did_, &doc);
    if (section)
      return doc.InSection(*section, vm->id);
    return doc.FindMethod(vm->id) != nullptr;
  }

  // ---- assertion + resolution + deactivation (§5.4, §4.7, §4.9) ----

  // §5.4 signGraph over a target graph IRI or did:graph. Requires the acting
  // credential to hold an assertionMethod delegate (§5.4 -> NotAllowedError).
  bool SignGraph(const std::string& target, SignedContentResult* out);

  // §4.7 resolve (local): project this group's current DID document.
  bool Resolve(living_web::DidDocument* out) {
    return group_detail::ProjectDidDocument(graph_, did_, out);
  }

  // §4.9 deactivate: write `<did> did://deactivated true` via governance.
  bool Deactivate() {
    if (!RequireDelegate(living_web::DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Write({group_detail::T_lit(did_, living_web::kDidDeactivated, "true",
                                      group_detail::kXsdBoolean)});
  }

 private:
  friend class GroupBackendManager;

  std::string ActingCredId() const {
    if (!acting_credential_id_.empty())
      return acting_credential_id_;
    const DIDKeyPair* a = identity_->GetActiveCredential();
    return a ? a->id : std::string();
  }

  // Is the acting credential a delegate of this group in |section|?
  bool ActingIsDelegate(living_web::DIDCapabilitySection section) {
    const DIDKeyPair* c = identity_->GetCredential(ActingCredId());
    if (!c)
      return false;
    auto mb = living_web::did_key::Ed25519PublicKeyMultibase(c->public_key);
    if (!mb)
      return false;
    living_web::DidDocument doc;
    group_detail::ProjectDidDocument(graph_, did_, &doc);
    return doc.InSection(section, did_ + "#" + *mb);
  }

  bool RequireDelegate(living_web::DIDCapabilitySection section) {
    if (!ActingIsDelegate(section)) {
      last_error_ = "NotAllowedError";
      return false;
    }
    return true;
  }

  // Commit |batch| as the acting delegate (its key signs the reifiers).
  bool Write(const std::vector<living_web::Triple>& batch) {
    group_detail::ScopedActive scoped(identity_, ActingCredId());
    if (!graph_->AddTriples(batch)) {
      last_error_ = graph_->last_error();
      return false;
    }
    return true;
  }

  bool Remove(const living_web::Triple& t) {
    group_detail::ScopedActive scoped(identity_, ActingCredId());
    bool removed = false;
    if (!graph_->RemoveTriple(t, &removed)) {
      last_error_ = graph_->last_error();
      return false;
    }
    return true;
  }

  // Remove |method_id| from the document: its attribute triples, its
  // verificationMethod membership, and any capability-section memberships.
  bool RemoveMethod(const std::string& method_id);

  // Build a Participant record for |participant| (an IRI or did:graph), resolving
  // its join timestamp from the accepts_participation reifier and, if the
  // participant graph is locally mounted, its group://name.
  Participant MakeParticipant(const std::string& participant);

  raw_ptr<DIDKeyProvider> identity_;             // Not owned.
  raw_ptr<GroupBackendManager> manager_;         // Not owned.
  raw_ptr<GraphBackend> graph_;                  // Not owned.
  std::string did_;
  std::string acting_credential_id_;
  std::string group_credential_id_;  // constitutional key (DID == did_)
  std::string last_error_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_GROUP_BACKEND_H_
