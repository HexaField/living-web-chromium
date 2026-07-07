// Living Web Standalone Library
// Decentralised Group Identity (Spec 03) — the did:graph group runtime.
//
// A "group" is a Graph (Spec 02) that has been *groupified*: a fresh Ed25519
// keypair is minted, a `did:graph:...` is derived from it, and the binding +
// seed DID-document triples are written into the host graph (§4.2). This header
// implements the §8 `Group` and `GraphManager`-extension (`GroupManager`) API on
// top of the Chromium-independent cores:
//   * content/browser/did/did_graph.*  — the did:graph codec, the DID-document
//     predicate vocabulary (§4.4/§16), and the projected DidDocument model;
//   * standalone/graph_provider.h       — the Spec 02 evolving Graph the group
//     lives inside; every DID-document read/write is an ordinary triple op.
//
// The DID document *is* triples in the host graph, so there is no separate wire
// format: adding a delegate is authoring `did://verificationMethod` +
// `did://<section>` triples; resolving the DID is projecting them back
// (group_detail::ProjectDidDocument). Signing authority (DID-document delegates,
// §5/§7.2) and participation (context://participates_in / accepts_participation,
// §6.2/§7.1) are kept structurally separate exactly as §7 requires.
//
// Nothing here is a stub. ZCAP structural verification is the Capability
// Framework's concern (Spec 04); Spec 03 enforces the invariants it owns — the
// capabilityDelegation authorship rule (§6.2), the assertionMethod rule for
// signGraph (§5.4), and the capabilityDelegation brick-state guards (§5.4) — and
// implements the full did:graph method, delegate model, participation model,
// forking (§4.8), resolution (§4.7 local), and deactivation (§4.9).
#ifndef LIVING_WEB_GROUP_PROVIDER_H_
#define LIVING_WEB_GROUP_PROVIDER_H_

#include "types.h"
#include "base_shim.h"
#include "graph_provider.h"
#include "did_key_provider.h"
#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_codec.h"
#include "content/browser/graph/rdf_serialization.h"
#include "third_party/ed25519/ed25519.h"

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace living_web {

class Group;
class GroupManager;

// A DID-document verification method as accepted by the delegate-management API
// (§5.4 `DIDDocumentMethod`). The projected-document type carries exactly these
// fields, so we reuse it verbatim.
using DIDDocumentMethod = VerificationMethod;

// ---- Spec 03 API option types (§8.2) --------------------------------------

// §8.2 createGroup / GroupCreationOptions. `sync_module` is REQUIRED (§4.5).
struct GroupCreationOptions {
  std::string sync_module;                    // REQUIRED — content hash (§4.5)
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
  std::string sync_module;                     // REQUIRED (§4.8.1)
  std::optional<std::string> fork_revision;    // defaults to parent's current IRI
  bool announce_fork = true;                   // write group://forkedTo on parent
  std::vector<std::string> initial_delegates;
  std::optional<std::string> display_name;
  std::optional<std::string> description;
};

// §8.1 Participant.
struct Participant {
  std::string did;                   // participant IRI or did:graph
  bool is_group = false;             // true iff a did:graph
  std::string joined_at;             // RFC 3339, from the accepts_participation reifier
  std::optional<std::string> name;   // group://name of the participant, if resolvable
};

namespace group_detail {

// XSD datatype IRIs used by the seed/metadata literals not already exposed by
// rdf_serialization.h (which supplies kXsdString and kXsdDateTime).
inline constexpr char kXsdBoolean[] = "http://www.w3.org/2001/XMLSchema#boolean";

// ---- triple builders ------------------------------------------------------

inline Triple T_iri(const std::string& s,
                    const std::string& p,
                    const std::string& iri) {
  return Triple{s, p, ObjectTerm::Iri(iri)};
}

inline Triple T_lit(const std::string& s,
                    const std::string& p,
                    const std::string& lex,
                    const std::string& datatype = kXsdString) {
  LiteralValue lv;
  lv.lexical = lex;
  lv.datatype = datatype;
  return Triple{s, p, ObjectTerm::Literal(lv)};
}

// The verification-method id for |public_key| under |did|: "<did>#<multibase>"
// (SPEC_COMPLIANCE amendment 03/§4.4 — the fragment is the method's own key).
inline std::string MethodId(const std::string& did,
                            const std::vector<uint8_t>& public_key) {
  return did + "#" + *did_key::Ed25519PublicKeyMultibase(public_key);
}

// Builds the group's DID-document verification method for a delegate identified
// by |delegate_did| (a did:key or did:graph). The method is controlled by the
// group DID (§4.4: every method's controller is the group). nullopt if the DID
// does not carry a 32-byte Ed25519 key.
inline std::optional<VerificationMethod> MethodFromDelegateDid(
    const std::string& group_did,
    const std::string& delegate_did) {
  auto pk = ParseAnyDidEd25519(delegate_did);
  if (!pk || pk->size() != 32)
    return std::nullopt;
  auto mb = did_key::Ed25519PublicKeyMultibase(*pk);
  if (!mb)
    return std::nullopt;
  VerificationMethod vm;
  vm.id = group_did + "#" + *mb;
  vm.type = kEd25519VerificationKey2020;
  vm.controller = group_did;
  vm.public_key_multibase = *mb;
  return vm;
}

// Appends the four triples that introduce |vm| into the DID document of |did|:
// the verificationMethod membership plus the type/controller/publicKeyMultibase
// attributes (§4.4).
inline void AppendMethod(const std::string& did,
                         const VerificationMethod& vm,
                         std::vector<Triple>* out) {
  out->push_back(T_iri(did, kDidVerificationMethod, vm.id));
  out->push_back(T_lit(vm.id, kDidVmType, vm.type));
  out->push_back(T_iri(vm.id, kDidVmController, vm.controller));
  out->push_back(T_lit(vm.id, kDidVmPublicKeyMultibase, vm.public_key_multibase));
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
  DIDKeyProvider* identity_;
  bool had_prev_ = false;
  std::string prev_id_;
};

// ---- DID-document projection (§4.4, §4.7 local resolution) -----------------

// Every distinct object term of (subject, predicate) in |g|, de-duplicated. The
// reifier join in Graph::QueryTriples can surface the same data triple once per
// reifier, so callers that count or list MUST dedupe — done here.
inline std::vector<ObjectTerm> QueryObjects(Graph* g,
                                            const std::string& subject,
                                            const std::string& predicate) {
  TripleQuery q;
  q.subject = subject;
  q.predicate = predicate;
  std::vector<Triple> ts;
  std::vector<ObjectTerm> out;
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

inline std::optional<std::string> FirstLiteralOf(Graph* g,
                                                 const std::string& subject,
                                                 const std::string& predicate) {
  for (const auto& o : QueryObjects(g, subject, predicate))
    if (o.is_literal())
      return o.literal->lexical;
  return std::nullopt;
}

inline std::optional<std::string> FirstIriOf(Graph* g,
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
inline bool ProjectDidDocument(Graph* g,
                               const std::string& did,
                               DidDocument* out) {
  out->id = did;
  out->trust_level = "local";
  out->deactivated = false;
  out->verification_method.clear();
  out->capability_invocation.clear();
  out->capability_delegation.clear();
  out->assertion_method.clear();
  out->authentication.clear();

  auto section = [&](DIDCapabilitySection s, std::vector<std::string>* dst) {
    for (const auto& o : QueryObjects(g, did, SectionPredicate(s)))
      if (!o.is_literal())
        dst->push_back(o.iri_or_bnode);
  };
  section(DIDCapabilitySection::kCapabilityInvocation,
          &out->capability_invocation);
  section(DIDCapabilitySection::kCapabilityDelegation,
          &out->capability_delegation);
  section(DIDCapabilitySection::kAssertionMethod, &out->assertion_method);
  section(DIDCapabilitySection::kAuthentication, &out->authentication);

  for (const auto& o : QueryObjects(g, did, kDidVerificationMethod)) {
    if (o.is_literal())
      continue;
    VerificationMethod vm;
    vm.id = o.iri_or_bnode;
    if (auto t = FirstLiteralOf(g, vm.id, kDidVmType))
      vm.type = *t;
    if (auto c = FirstIriOf(g, vm.id, kDidVmController))
      vm.controller = *c;
    if (auto pk = FirstLiteralOf(g, vm.id, kDidVmPublicKeyMultibase))
      vm.public_key_multibase = *pk;
    out->verification_method.push_back(std::move(vm));
  }

  if (auto d = FirstLiteralOf(g, did, kDidDeactivated))
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

// ---- Group (§8.1) ----------------------------------------------------------

// The §8.1 convenience handle over a groupified Graph + its did:graph identity.
// It is a *non-owning* view: the host Graph is owned by the GraphManager /
// GroupManager. Every operation is expressible directly on the underlying Graph
// + DIDKeyProvider; this class just packages the common flows ergonomically.
//
// The "acting credential" is the delegate key whose signature authors writes and
// signs assertions. It defaults to the group's own initial-key credential (which
// holds all four sections, so a group-of-one works out of the box); callers hand
// off to another delegate via SetActingCredential().
class Group {
 public:
  Group(DIDKeyProvider* identity,
        GroupManager* manager,
        Graph* graph,
        std::string did,
        std::string group_credential_id)
      : identity_(identity),
        manager_(manager),
        graph_(graph),
        did_(std::move(did)),
        acting_credential_id_(std::move(group_credential_id)) {}

  Group(const Group&) = delete;
  Group& operator=(const Group&) = delete;

  // ---- attributes (§8.1) ----
  const std::string& did() const { return did_; }
  Graph* graph() const { return graph_; }
  const std::string& last_error() const { return last_error_; }

  bool iri(std::string* out) {
    if (!graph_->GetIri(out)) {
      last_error_ = graph_->last_error();
      return false;
    }
    return true;
  }

  std::optional<std::string> name() {
    return group_detail::FirstLiteralOf(graph_, did_, kGroupName);
  }
  std::optional<std::string> description() {
    return group_detail::FirstLiteralOf(graph_, did_, kGroupDescription);
  }
  std::optional<std::string> created() {
    return group_detail::FirstLiteralOf(graph_, did_, kGroupCreated);
  }
  std::optional<std::string> creator() {
    return group_detail::FirstIriOf(graph_, did_, kGroupCreator);
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
    if (!RequireDelegate(DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Write({group_detail::T_iri(did_, kContextAcceptsParticipation,
                                      participant)});
  }

  // §8.1.2 revokeParticipation: remove the group's acceptance triple.
  bool RevokeParticipation(const std::string& participant) {
    if (!RequireDelegate(DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Remove(group_detail::T_iri(did_, kContextAcceptsParticipation,
                                      participant));
  }

  bool HasParticipant(const std::string& participant) {
    for (const auto& o :
         group_detail::QueryObjects(graph_, did_, kContextAcceptsParticipation))
      if (!o.is_literal() && o.iri_or_bnode == participant)
        return true;
    return false;
  }

  // §8.1.3 participants: the direct participant set (accepts_participation
  // objects), each tagged group/individual with its join timestamp.
  std::vector<Participant> Participants() {
    std::vector<Participant> out;
    for (const auto& o :
         group_detail::QueryObjects(graph_, did_, kContextAcceptsParticipation)) {
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
  std::vector<std::unique_ptr<Group>> ParentGroups();

  // §8.1 childGroups: the participants of this group that are themselves groups.
  std::vector<std::unique_ptr<Group>> ChildGroups();

  // ---- signing authority / delegate management (§5, §7.2, §8.1.4) ----

  // §8.1 signers: the DID-document methods, optionally filtered to one section.
  std::vector<VerificationMethod> Signers(
      std::optional<DIDCapabilitySection> section = std::nullopt) {
    DidDocument doc;
    group_detail::ProjectDidDocument(graph_, did_, &doc);
    if (!section)
      return doc.verification_method;
    std::vector<VerificationMethod> out;
    for (const auto& vm : doc.verification_method)
      if (doc.InSection(*section, vm.id))
        out.push_back(vm);
    return out;
  }

  // §8.1.4 / §5.4 addSigner (== addDelegate): introduce |method| and grant it
  // |sections|. Requires a capabilityDelegation delegate (§5.4 -> NotAllowedError).
  bool AddSigner(const VerificationMethod& method,
                 const std::vector<DIDCapabilitySection>& sections) {
    if (!RequireDelegate(DIDCapabilitySection::kCapabilityDelegation))
      return false;
    std::vector<Triple> batch;
    group_detail::AppendMethod(did_, method, &batch);
    for (DIDCapabilitySection s : sections)
      batch.push_back(group_detail::T_iri(did_, SectionPredicate(s), method.id));
    return Write(batch);
  }
  bool AddDelegate(const VerificationMethod& method,
                   const std::vector<DIDCapabilitySection>& sections) {
    return AddSigner(method, sections);
  }

  // §8.1.4 / §5.4 removeSigner (== removeDelegate): remove |method_id| entirely.
  // Refuses with "InvalidStateError" if it is the sole capabilityDelegation
  // member (§5.4 brick-state guard); requires a capabilityDelegation delegate.
  bool RemoveSigner(const std::string& method_id) {
    if (!RequireDelegate(DIDCapabilitySection::kCapabilityDelegation))
      return false;
    DidDocument doc;
    group_detail::ProjectDidDocument(graph_, did_, &doc);
    if (doc.InSection(DIDCapabilitySection::kCapabilityDelegation, method_id) &&
        doc.SectionSize(DIDCapabilitySection::kCapabilityDelegation) == 1) {
      last_error_ = "InvalidStateError";
      return false;
    }
    return RemoveMethod(method_id);
  }
  bool RemoveDelegate(const std::string& method_id) {
    return RemoveSigner(method_id);
  }

  // §5.4 grantSection: add |method_id| to |section|. capabilityDelegation gated.
  bool GrantSection(const std::string& method_id, DIDCapabilitySection section) {
    if (!RequireDelegate(DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Write(
        {group_detail::T_iri(did_, SectionPredicate(section), method_id)});
  }

  // §5.4 revokeSection: remove |method_id| from |section| (the method stays in
  // verificationMethod). Refuses with "InvalidStateError" if |section| is
  // capabilityDelegation and |method_id| is its only member (brick-state).
  bool RevokeSection(const std::string& method_id,
                     DIDCapabilitySection section) {
    if (!RequireDelegate(DIDCapabilitySection::kCapabilityDelegation))
      return false;
    if (section == DIDCapabilitySection::kCapabilityDelegation) {
      DidDocument doc;
      group_detail::ProjectDidDocument(graph_, did_, &doc);
      if (doc.InSection(section, method_id) && doc.SectionSize(section) == 1) {
        last_error_ = "InvalidStateError";
        return false;
      }
    }
    return Remove(group_detail::T_iri(did_, SectionPredicate(section), method_id));
  }

  // §8.1 isSigner: is |delegate_did|'s key currently a signer (optionally in a
  // specific section)? The method id is "<group-did>#<delegate-key-multibase>".
  bool IsSigner(const std::string& delegate_did,
                std::optional<DIDCapabilitySection> section = std::nullopt) {
    auto vm = group_detail::MethodFromDelegateDid(did_, delegate_did);
    if (!vm)
      return false;
    DidDocument doc;
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
  bool Resolve(DidDocument* out) {
    return group_detail::ProjectDidDocument(graph_, did_, out);
  }

  // §4.9 deactivate: write `<did> did://deactivated true` via governance.
  bool Deactivate() {
    if (!RequireDelegate(DIDCapabilitySection::kCapabilityDelegation))
      return false;
    return Write({group_detail::T_lit(did_, kDidDeactivated, "true",
                                      group_detail::kXsdBoolean)});
  }

 private:
  friend class GroupManager;

  std::string ActingCredId() const {
    if (!acting_credential_id_.empty())
      return acting_credential_id_;
    const DIDKeyPair* a = identity_->GetActiveCredential();
    return a ? a->id : std::string();
  }

  // Is the acting credential a delegate of this group in |section|?
  bool ActingIsDelegate(DIDCapabilitySection section) {
    const DIDKeyPair* c = identity_->GetCredential(ActingCredId());
    if (!c)
      return false;
    auto mb = did_key::Ed25519PublicKeyMultibase(c->public_key);
    if (!mb)
      return false;
    DidDocument doc;
    group_detail::ProjectDidDocument(graph_, did_, &doc);
    return doc.InSection(section, did_ + "#" + *mb);
  }

  bool RequireDelegate(DIDCapabilitySection section) {
    if (!ActingIsDelegate(section)) {
      last_error_ = "NotAllowedError";
      return false;
    }
    return true;
  }

  // Commit |batch| as the acting delegate (its key signs the reifiers).
  bool Write(const std::vector<Triple>& batch) {
    group_detail::ScopedActive scoped(identity_, ActingCredId());
    if (!graph_->AddTriples(batch)) {
      last_error_ = graph_->last_error();
      return false;
    }
    return true;
  }

  bool Remove(const Triple& t) {
    group_detail::ScopedActive scoped(identity_, ActingCredId());
    bool removed = false;
    if (!graph_->RemoveTriple(t, &removed)) {
      last_error_ = graph_->last_error();
      return false;
    }
    return true;
  }

  // Remove |method_id| from the document: its three attribute triples, its
  // verificationMethod membership, and any capability-section memberships.
  bool RemoveMethod(const std::string& method_id) {
    group_detail::ScopedActive scoped(identity_, ActingCredId());
    // Attribute triples (subject == method_id).
    TripleQuery q;
    q.subject = method_id;
    std::vector<Triple> attrs;
    if (!graph_->QueryTriples(q, &attrs)) {
      last_error_ = graph_->last_error();
      return false;
    }
    for (const auto& t : attrs) {
      bool r = false;
      if (!graph_->RemoveTriple(t, &r)) {
        last_error_ = graph_->last_error();
        return false;
      }
    }
    // Membership triples (subject == did_, object == method_id): the
    // verificationMethod list plus every capability section.
    const char* preds[] = {
        kDidVerificationMethod,
        SectionPredicate(DIDCapabilitySection::kCapabilityInvocation),
        SectionPredicate(DIDCapabilitySection::kCapabilityDelegation),
        SectionPredicate(DIDCapabilitySection::kAssertionMethod),
        SectionPredicate(DIDCapabilitySection::kAuthentication)};
    for (const char* p : preds) {
      bool r = false;
      if (!graph_->RemoveTriple(group_detail::T_iri(did_, p, method_id), &r)) {
        last_error_ = graph_->last_error();
        return false;
      }
    }
    return true;
  }

  // Build a Participant record for |participant| (an IRI or did:graph), resolving
  // its join timestamp from the accepts_participation reifier and, if the
  // participant graph is locally mounted, its group://name.
  Participant MakeParticipant(const std::string& participant);

  DIDKeyProvider* identity_;
  GroupManager* manager_;
  Graph* graph_;
  std::string did_;
  std::string acting_credential_id_;
  std::string last_error_;
};

// ---- GroupManager (§8.2) ---------------------------------------------------

// The navigator.graph extension that mints and materialises groups (§8.2). A
// group's DID document *is* triples in a host Graph, so GroupManager owns the
// host graphs it creates and indexes every group it knows by did:graph, so that
// participation edges between locally-mounted groups resolve (§4.7). Groupifying
// a caller-owned Graph leaves ownership with the caller but still indexes it.
//
// It holds non-owning pointers to the identity provider (which stores every
// group's initial key, so group-authored writes resolve through the ordinary
// SignRaw path) and to the GraphManager that allocates host graphs.
class GroupManager {
 public:
  GroupManager(DIDKeyProvider* identity, GraphManager* graphs)
      : identity_(identity), graphs_(graphs) {}

  GroupManager(const GroupManager&) = delete;
  GroupManager& operator=(const GroupManager&) = delete;

  const std::string& last_error() const { return last_error_; }

  // §8.2 createGroup: allocate a fresh host graph and groupify it. The initial
  // key holds all four capability sections (a group-of-one works out of the box,
  // §11); extra |initial_delegates| are granted capabilityInvocation. When
  // |participates_in| is set the group authors its own context://participates_in
  // edge (§7.1) — the parent must still accept it via Group::Invite (§6.2).
  std::unique_ptr<Group> CreateGroup(const GroupCreationOptions& opts) {
    if (opts.sync_module.empty()) {  // §4.5 syncModule REQUIRED
      last_error_ = "SyntaxError";
      return nullptr;
    }
    std::unique_ptr<Graph> owned = graphs_->Create(opts.display_name);
    Graph* g = owned.get();
    const DIDKeyPair* cred =
        DoGroupify(g, opts.sync_module, opts.display_name, opts.description,
                   opts.initial_delegates, /*forked_from=*/std::nullopt,
                   /*forked_at=*/std::nullopt);
    if (!cred)
      return nullptr;  // last_error_ set by DoGroupify
    const std::string did = cred->did;
    if (opts.participates_in) {
      group_detail::ScopedActive scoped(identity_, cred->id);
      if (!g->AddTriples({group_detail::T_iri(did, kContextParticipatesIn,
                                              *opts.participates_in)})) {
        last_error_ = g->last_error();
        return nullptr;
      }
    }
    did_index_[did] = g;
    owned_graphs_.push_back(std::move(owned));
    return MakeHandle(g);
  }

  // §8.2 groupify: turn an existing, caller-owned Graph into a group. Rejects
  // with "InvalidStateError" if it already carries a group://didIdentity binding
  // — groupification is one-way (§4.2). The caller keeps ownership of |existing|;
  // the manager indexes it by DID so participation resolves.
  std::unique_ptr<Group> Groupify(Graph* existing, const GroupifyOptions& opts) {
    if (opts.sync_module.empty()) {
      last_error_ = "SyntaxError";
      return nullptr;
    }
    if (!existing) {
      last_error_ = "InvalidStateError";
      return nullptr;
    }
    if (HasBinding(existing)) {  // §4.2: already a group
      last_error_ = "InvalidStateError";
      return nullptr;
    }
    const DIDKeyPair* cred =
        DoGroupify(existing, opts.sync_module, opts.display_name,
                   opts.description, opts.initial_delegates,
                   /*forked_from=*/std::nullopt, /*forked_at=*/std::nullopt);
    if (!cred)
      return nullptr;
    did_index_[cred->did] = existing;  // manager indexes, caller owns
    return MakeHandle(existing);
  }

  // §8.2 forkGroup (§4.8): mint a fresh identity, copy the parent's graph state,
  // strip the parent identity, and write the child seed with forkedFrom/
  // forkedAtRevision. |parent| is a did:graph or a current IRI of a locally
  // mounted group. Announces `<parent> group://forkedTo <child>` on the parent
  // when |announce_fork| (§4.8 step 6). The root-capability mint (§4.8 step 5)
  // and the constraint-kind superset check (§4.8.1 → NotSupportedError) belong to
  // the Capability Framework (Spec 04) and Constraint Vocabulary (Spec 08).
  std::unique_ptr<Group> ForkGroup(const std::string& parent,
                                   const ForkOptions& opts) {
    if (opts.sync_module.empty()) {
      last_error_ = "SyntaxError";
      return nullptr;
    }
    Graph* parent_host = LookupHost(parent);
    if (!parent_host) {
      last_error_ = "NotFoundError";
      return nullptr;
    }
    if (!parent_host->did()) {  // not a group
      last_error_ = "InvalidStateError";
      return nullptr;
    }
    const std::string parent_did = *parent_host->did();

    // §4.8 step: the fork revision defaults to the parent's current IRI.
    std::string revision;
    if (opts.fork_revision) {
      revision = *opts.fork_revision;
    } else if (!parent_host->GetIri(&revision)) {
      last_error_ = parent_host->last_error();
      return nullptr;
    }

    // §4.8 step 2: copy the parent's full graph state (data + reifiers, so the
    // inherited history stays verifiable) into a fresh host graph.
    std::unique_ptr<Graph> owned = graphs_->Create(opts.display_name);
    Graph* child = owned.get();
    std::string nq;
    if (!parent_host->store_.DumpNquads(&nq)) {
      last_error_ = parent_host->store_.last_error();
      return nullptr;
    }
    if (!nq.empty() && !child->store_.LoadNquads(nq)) {
      last_error_ = child->store_.last_error();
      return nullptr;
    }

    // §4.8 step 3: strip the parent identity from the copy.
    StripIdentity(child, parent_did);

    // §4.8 step 4: write the child seed, recording its lineage.
    const DIDKeyPair* cred =
        DoGroupify(child, opts.sync_module, opts.display_name, opts.description,
                   opts.initial_delegates, /*forked_from=*/parent_did,
                   /*forked_at=*/revision);
    if (!cred)
      return nullptr;
    const std::string child_did = cred->did;

    // §4.8 step 6: announce the fork on the parent (governed write authored by a
    // parent delegate), gated by announceFork.
    if (opts.announce_fork) {
      std::string parent_cred = GroupCredentialId(parent_did);
      if (!parent_cred.empty()) {
        group_detail::ScopedActive scoped(identity_, parent_cred);
        parent_host->AddTriples(
            {group_detail::T_iri(parent_did, kGroupForkedTo, child_did)});
      }
    }

    did_index_[child_did] = child;
    owned_graphs_.push_back(std::move(owned));
    return MakeHandle(child);
  }

  // §8.2 openGroup: a handle over an already-known group named by did:graph or by
  // current IRI. Only locally-mounted groups resolve (§4.7). nullptr +
  // "NotFoundError" otherwise.
  std::unique_ptr<Group> OpenGroup(const std::string& iri_or_did) {
    Graph* g = LookupHost(iri_or_did);
    if (!g) {
      last_error_ = "NotFoundError";
      return nullptr;
    }
    return MakeHandle(g);
  }

  // Every group this manager currently mounts.
  std::vector<std::unique_ptr<Group>> ListGroups() {
    std::vector<std::unique_ptr<Group>> out;
    out.reserve(did_index_.size());
    for (const auto& [did, g] : did_index_)
      out.push_back(MakeHandle(g));
    return out;
  }

  // Resolve a did:graph or a current graph IRI to the host Graph, or nullptr.
  Graph* LookupHost(const std::string& key) {
    auto it = did_index_.find(key);
    if (it != did_index_.end())
      return it->second;
    for (const auto& [did, g] : did_index_) {
      std::string iri;
      if (g->GetIri(&iri) && iri == key)
        return g;
    }
    return nullptr;
  }

 private:
  friend class Group;

  // A Group view over a mounted host graph, acting as the group's own key by
  // default (it holds every section, §11).
  std::unique_ptr<Group> MakeHandle(Graph* g) {
    std::string did = g->GraphIdentifier();  // == did_ for a groupified graph
    return std::make_unique<Group>(identity_, this, g, did,
                                   GroupCredentialId(did));
  }

  // The provider credential id of the group's own initial key (method "graph",
  // did == |group_did|), or empty if the caller never held it.
  std::string GroupCredentialId(const std::string& group_did) const {
    for (const DIDKeyPair* c : identity_->ListCredentials())
      if (c->method == "graph" && c->did == group_did)
        return c->id;
    return std::string();
  }

  static bool HasBinding(Graph* g) {
    TripleQuery q;
    q.predicate = kGroupDidIdentity;
    std::vector<Triple> ts;
    return g->QueryTriples(q, &ts) && !ts.empty();
  }

  // The one-way groupification bootstrap (§4.2). Mints the initial Ed25519
  // keypair, derives the did:graph, adopts the key into the provider, binds it to
  // |g|, and writes the seed (binding + syncModule + the creator method in all
  // four sections + metadata + optional fork lineage) followed by the governed
  // initial-delegate grants (capabilityInvocation). Returns the adopted group
  // credential (its ->did is the group DID, ->id the provider credential id), or
  // nullptr with last_error_ set. The creator DID is captured BEFORE adoption,
  // because adopting into an empty provider would make the group key active and
  // corrupt the read.
  const DIDKeyPair* DoGroupify(
      Graph* g,
      const std::string& sync_module,
      const std::optional<std::string>& display_name,
      const std::optional<std::string>& description,
      const std::vector<std::string>& initial_delegates,
      const std::optional<std::string>& forked_from,
      const std::optional<std::string>& forked_at) {
    // §4.2: creator = the human's prior-active DID, captured before adoption.
    std::string creator_did;
    if (const DIDKeyPair* prior = identity_->GetActiveCredential())
      creator_did = prior->did;

    // §4.2 step 4: the binding subject is the host IRI as it stands NOW.
    std::string pre_iri;
    if (!g->GetIri(&pre_iri)) {
      last_error_ = g->last_error();
      return nullptr;
    }

    // §4.1/§4.3: mint the group's initial keypair + did:graph.
    auto key = std::make_unique<DIDKeyPair>();
    key->id = base::Uuid::GenerateRandomV4().AsLowercaseString();
    key->display_name = display_name.value_or("");
    key->algorithm = "Ed25519";
    key->created_at = graph_detail::NowRfc3339();
    key->is_locked = false;
    key->public_key.resize(32);
    key->private_key.resize(64);
    ed25519_create_keypair(key->public_key.data(), key->private_key.data());
    auto did_opt = did_graph::DeriveDidGraphEd25519(key->public_key);
    if (!did_opt) {
      last_error_ = "DataError";
      return nullptr;
    }
    const std::string did = *did_opt;
    key->did = did;
    key->method = "graph";
    key->method_id = group_detail::MethodId(did, key->public_key);

    const DIDKeyPair* group_cred = identity_->AdoptCredential(std::move(key));
    if (!group_cred) {
      last_error_ = "DataError";
      return nullptr;
    }
    if (creator_did.empty())  // no prior identity: the group is its own creator
      creator_did = did;

    // Bind the host graph to the group DID (friend access), so every seed write's
    // reifier is signed in the did:graph's graphIdentifier context (§3.2.1).
    g->did_ = did;

    // ---- seed batch (§4.2 steps 4-5): privileged, ungoverned ----
    auto mb = did_key::Ed25519PublicKeyMultibase(group_cred->public_key);
    VerificationMethod creator_method;
    creator_method.id = group_cred->method_id;
    creator_method.type = kEd25519VerificationKey2020;
    creator_method.controller = did;
    creator_method.public_key_multibase = mb ? *mb : std::string();

    std::vector<Triple> seed;
    seed.push_back(group_detail::T_iri(pre_iri, kGroupDidIdentity, did));
    seed.push_back(group_detail::T_lit(did, kGroupSyncModule, sync_module));
    group_detail::AppendMethod(did, creator_method, &seed);
    for (DIDCapabilitySection s :
         {DIDCapabilitySection::kCapabilityInvocation,
          DIDCapabilitySection::kCapabilityDelegation,
          DIDCapabilitySection::kAssertionMethod,
          DIDCapabilitySection::kAuthentication}) {
      seed.push_back(
          group_detail::T_iri(did, SectionPredicate(s), creator_method.id));
    }
    if (display_name)
      seed.push_back(group_detail::T_lit(did, kGroupName, *display_name));
    if (description)
      seed.push_back(group_detail::T_lit(did, kGroupDescription, *description));
    seed.push_back(group_detail::T_lit(did, kGroupCreated,
                                       graph_detail::NowRfc3339(),
                                       kXsdDateTime));
    seed.push_back(group_detail::T_iri(did, kGroupCreator, creator_did));
    if (forked_from)
      seed.push_back(group_detail::T_iri(did, kGroupForkedFrom, *forked_from));
    if (forked_at)
      seed.push_back(
          group_detail::T_lit(did, kGroupForkedAtRevision, *forked_at));
    {
      group_detail::ScopedActive scoped(identity_, group_cred->id);
      if (!g->AddTriples(seed)) {
        last_error_ = g->last_error();
        return nullptr;
      }
    }

    // ---- initial delegates (§4.2 step 6): governed writes ----
    // Granted capabilityInvocation only; capabilityDelegation stays with the
    // creator key until explicitly granted. Non-Ed25519 DIDs are skipped.
    std::vector<Triple> delegates_batch;
    for (const std::string& delegate_did : initial_delegates) {
      auto vm = group_detail::MethodFromDelegateDid(did, delegate_did);
      if (!vm)
        continue;
      group_detail::AppendMethod(did, *vm, &delegates_batch);
      delegates_batch.push_back(group_detail::T_iri(
          did, SectionPredicate(DIDCapabilitySection::kCapabilityInvocation),
          vm->id));
    }
    if (!delegates_batch.empty()) {
      group_detail::ScopedActive scoped(identity_, group_cred->id);
      if (!g->AddTriples(delegates_batch)) {
        last_error_ = g->last_error();
        return nullptr;
      }
    }
    return group_cred;
  }

  // §4.8 step 3: remove every triple that identifies |parent_did| as a group
  // from a freshly-copied |child| — the binding, the DID document (section
  // memberships + verificationMethod list + the per-method attribute triples),
  // the group metadata, and the participation edges the parent declared. The
  // group's actual content triples (subject != the parent identity) are left
  // intact, together with their reifiers: fork inherits the verifiable history.
  void StripIdentity(Graph* child, const std::string& parent_did) {
    std::vector<Triple> victims;
    auto add_subject = [&](const std::string& subject) {
      TripleQuery q;
      q.subject = subject;
      std::vector<Triple> ts;
      if (child->QueryTriples(q, &ts))
        victims.insert(victims.end(), ts.begin(), ts.end());
    };
    add_subject(parent_did);  // DID-doc membership, metadata, participation
    DidDocument pdoc;
    group_detail::ProjectDidDocument(child, parent_did, &pdoc);
    for (const auto& vm : pdoc.verification_method)
      add_subject(vm.id);  // per-method type/controller/publicKeyMultibase
    {
      TripleQuery q;
      q.predicate = kGroupDidIdentity;
      std::vector<Triple> ts;
      if (child->QueryTriples(q, &ts))
        for (const auto& t : ts)
          if (!t.object.is_literal() && t.object.iri_or_bnode == parent_did)
            victims.push_back(t);  // the binding triple
    }
    for (const auto& t : victims) {
      bool removed = false;
      child->RemoveTriple(t, &removed);
    }
  }

  DIDKeyProvider* identity_;
  GraphManager* graphs_;
  std::vector<std::unique_ptr<Graph>> owned_graphs_;
  std::unordered_map<std::string, Graph*> did_index_;
  std::string last_error_;
};

// ---- Group out-of-line methods (need the complete GroupManager type) -------

// §8.1.3 transitiveParticipants: every individual (non-group) participant
// reachable by descending into participating sub-groups, with cycle detection
// and a depth cap of 16 (§6.3 / §13.7). A participating group is NOT itself an
// individual and is not emitted — only its individual members flow up
// (membership is not transitive for authority, §6.3).
inline std::vector<Participant> Group::TransitiveParticipants() {
  std::vector<Participant> out;
  std::unordered_set<std::string> visited;
  std::function<void(Group*, int)> descend = [&](Group* grp, int depth) {
    if (depth > 16)
      return;
    for (const auto& o : group_detail::QueryObjects(
             grp->graph_, grp->did_, kContextAcceptsParticipation)) {
      if (o.is_literal())
        continue;
      const std::string& pid = o.iri_or_bnode;
      if (!visited.insert(pid).second)
        continue;  // cycle or already collected
      Participant p = grp->MakeParticipant(pid);
      if (p.is_group) {
        if (Graph* sub = manager_->LookupHost(pid)) {
          Group child(identity_, manager_, sub, pid,
                      manager_->GroupCredentialId(pid));
          descend(&child, depth + 1);
        }
      } else {
        out.push_back(std::move(p));
      }
    }
  };
  descend(this, 0);
  return out;
}

// §8.1 parentGroups: the locally-mounted groups this group participates in,
// named by this group's own context://participates_in edges (§7.1).
inline std::vector<std::unique_ptr<Group>> Group::ParentGroups() {
  std::vector<std::unique_ptr<Group>> out;
  for (const auto& o :
       group_detail::QueryObjects(graph_, did_, kContextParticipatesIn)) {
    if (o.is_literal())
      continue;
    if (Graph* host = manager_->LookupHost(o.iri_or_bnode))
      out.push_back(manager_->MakeHandle(host));
  }
  return out;
}

// §8.1 childGroups: the direct participants that are themselves groups
// (did:graph accepts_participation objects) and are locally mounted.
inline std::vector<std::unique_ptr<Group>> Group::ChildGroups() {
  std::vector<std::unique_ptr<Group>> out;
  for (const auto& o :
       group_detail::QueryObjects(graph_, did_, kContextAcceptsParticipation)) {
    if (o.is_literal())
      continue;
    if (!did_graph::IsDidGraph(o.iri_or_bnode))
      continue;
    if (Graph* host = manager_->LookupHost(o.iri_or_bnode))
      out.push_back(manager_->MakeHandle(host));
  }
  return out;
}

// §5.4 signGraph: resolve |target| (a did:graph or a graph IRI) to
// {graphDid, graphIri, timestamp} and sign that structure with the acting
// credential via Spec 01 sign(). Requires the acting credential to hold an
// assertionMethod delegate (§5.4 → "NotAllowedError"). A target that is not
// locally mounted is signed as an opaque IRI with a null graphDid.
inline bool Group::SignGraph(const std::string& target,
                             SignedContentResult* out) {
  if (!RequireDelegate(DIDCapabilitySection::kAssertionMethod))
    return false;
  std::optional<std::string> graph_did;
  std::string graph_iri;
  if (Graph* host = manager_->LookupHost(target)) {
    if (host->did())
      graph_did = *host->did();
    if (!host->GetIri(&graph_iri)) {
      last_error_ = host->last_error();
      return false;
    }
  } else {
    graph_iri = target;
  }
  std::string timestamp = graph_detail::NowRfc3339();
  std::string payload =
      group_detail::SignGraphPayload(graph_did, graph_iri, timestamp);
  auto signed_result = identity_->Sign(ActingCredId(), payload);
  if (!signed_result) {
    last_error_ = "InvalidStateError";
    return false;
  }
  *out = *signed_result;
  return true;
}

// Build a Participant for |participant| (an IRI or did:graph): its join time is
// the earliest timestamp on the group's accepts_participation reifier, and its
// name is the participant graph's group://name when that graph is locally
// mounted (§8.1.3).
inline Participant Group::MakeParticipant(const std::string& participant) {
  Participant p;
  p.did = participant;
  p.is_group = did_graph::IsDidGraph(participant);
  Triple accept =
      group_detail::T_iri(did_, kContextAcceptsParticipation, participant);
  std::vector<Reifier> reifs;
  if (graph_->Provenance(accept, &reifs) && !reifs.empty()) {
    std::string earliest = reifs.front().timestamp;
    for (const auto& r : reifs)
      if (r.timestamp < earliest)
        earliest = r.timestamp;
    p.joined_at = std::move(earliest);
  }
  if (Graph* host = manager_->LookupHost(participant)) {
    std::string subject = host->did().value_or(participant);
    p.name = group_detail::FirstLiteralOf(host, subject, kGroupName);
  }
  return p;
}

}  // namespace living_web

#endif  // LIVING_WEB_GROUP_PROVIDER_H_
