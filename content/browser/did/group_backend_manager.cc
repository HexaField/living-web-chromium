// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/group_backend_manager.h"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>

#include "base/uuid.h"
#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_codec.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"

namespace content {

namespace {

// RFC 3339 UTC timestamp, matching the file-local helper in graph_backend.cc so
// group writes and graph writes stamp identically.
std::string NowRfc3339() {
  auto now = std::time(nullptr);
  auto* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

}  // namespace

GroupBackendManager::GroupBackendManager(DIDKeyProvider* identity,
                                         GraphBackendManager* graphs)
    : identity_(identity), graphs_(graphs) {}

GroupBackendManager::~GroupBackendManager() = default;

std::unique_ptr<GroupBackend> GroupBackendManager::CreateGroup(
    const GroupCreationOptions& opts) {
  if (opts.sync_module.empty()) {  // §4.5 syncModule REQUIRED
    last_error_ = "SyntaxError";
    return nullptr;
  }
  GraphBackend* g = graphs_->Create(opts.display_name);
  const DIDKeyPair* cred =
      DoGroupify(g, opts.sync_module, opts.display_name, opts.description,
                 opts.initial_delegates, /*forked_from=*/std::nullopt,
                 /*forked_at=*/std::nullopt);
  if (!cred) {
    graphs_->Remove(g->id());  // roll back the empty host graph
    return nullptr;            // last_error_ set by DoGroupify
  }
  const std::string did = cred->did;
  if (opts.participates_in) {
    group_detail::ScopedActive scoped(identity_, cred->id);
    if (!g->AddTriples({group_detail::T_iri(
            did, living_web::kContextParticipatesIn, *opts.participates_in)})) {
      last_error_ = g->last_error();
      graphs_->Remove(g->id());
      return nullptr;
    }
  }
  did_index_[did] = g;
  return MakeHandle(g);
}

std::unique_ptr<GroupBackend> GroupBackendManager::Groupify(
    GraphBackend* existing,
    const GroupifyOptions& opts) {
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
      DoGroupify(existing, opts.sync_module, opts.display_name, opts.description,
                 opts.initial_delegates, /*forked_from=*/std::nullopt,
                 /*forked_at=*/std::nullopt);
  if (!cred)
    return nullptr;
  did_index_[cred->did] = existing;  // manager indexes, GraphBackendManager owns
  return MakeHandle(existing);
}

std::unique_ptr<GroupBackend> GroupBackendManager::ForkGroup(
    const std::string& parent,
    const ForkOptions& opts) {
  if (opts.sync_module.empty()) {
    last_error_ = "SyntaxError";
    return nullptr;
  }
  GraphBackend* parent_host = LookupHost(parent);
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
  GraphBackend* child = graphs_->Create(opts.display_name);
  std::string nq;
  if (!parent_host->DumpNquads(&nq)) {
    last_error_ = parent_host->last_error();
    graphs_->Remove(child->id());
    return nullptr;
  }
  if (!nq.empty() && !child->LoadVerifiedNquads(nq)) {
    last_error_ = child->last_error();
    graphs_->Remove(child->id());
    return nullptr;
  }

  // §4.8 step 3: strip the parent identity from the copy.
  StripIdentity(child, parent_did);

  // §4.8 step 4: write the child seed, recording its lineage.
  const DIDKeyPair* cred =
      DoGroupify(child, opts.sync_module, opts.display_name, opts.description,
                 opts.initial_delegates, /*forked_from=*/parent_did,
                 /*forked_at=*/revision);
  if (!cred) {
    graphs_->Remove(child->id());
    return nullptr;
  }
  const std::string child_did = cred->did;

  // §4.8 step 6: announce the fork on the parent (governed write authored by a
  // parent delegate), gated by announceFork.
  if (opts.announce_fork) {
    std::string parent_cred = GroupCredentialId(parent_did);
    if (!parent_cred.empty()) {
      group_detail::ScopedActive scoped(identity_, parent_cred);
      parent_host->AddTriples(
          {group_detail::T_iri(parent_did, living_web::kGroupForkedTo,
                               child_did)});
    }
  }

  did_index_[child_did] = child;
  return MakeHandle(child);
}

std::unique_ptr<GroupBackend> GroupBackendManager::OpenGroup(
    const std::string& iri_or_did) {
  GraphBackend* g = LookupHost(iri_or_did);
  if (!g) {
    last_error_ = "NotFoundError";
    return nullptr;
  }
  return MakeHandle(g);
}

std::vector<std::unique_ptr<GroupBackend>> GroupBackendManager::ListGroups() {
  std::vector<std::unique_ptr<GroupBackend>> out;
  out.reserve(did_index_.size());
  for (const auto& [did, g] : did_index_)
    out.push_back(MakeHandle(g));
  return out;
}

GraphBackend* GroupBackendManager::LookupHost(const std::string& key) {
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

std::unique_ptr<GroupBackend> GroupBackendManager::MakeHandle(GraphBackend* g) {
  std::string did = g->did().value_or(g->id());  // == did_ for a group
  return std::make_unique<GroupBackend>(identity_, this, g, did,
                                        GroupCredentialId(did));
}

std::string GroupBackendManager::GroupCredentialId(
    const std::string& group_did) const {
  for (const DIDKeyPair* c : identity_->ListCredentials())
    if (c->method == "graph" && c->did == group_did)
      return c->id;
  return std::string();
}

bool GroupBackendManager::HasBinding(GraphBackend* g) {
  TripleQuery q;
  q.predicate = living_web::kGroupDidIdentity;
  std::vector<living_web::Triple> ts;
  return g->QueryTriples(q, &ts) && !ts.empty();
}

const DIDKeyPair* GroupBackendManager::DoGroupify(
    GraphBackend* g,
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
  key->created_at = NowRfc3339();
  key->is_locked = false;
  key->public_key.resize(32);
  key->private_key.resize(64);
  ED25519_keypair(key->public_key.data(), key->private_key.data());
  auto did_opt = living_web::did_graph::DeriveDidGraphEd25519(key->public_key);
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

  // Bind the host graph to the group DID, so every seed write's reifier is
  // signed in the did:graph's graphIdentifier context (§3.2.1).
  g->set_did(did);

  // ---- seed batch (§4.2 steps 4-5): privileged, ungoverned ----
  auto mb =
      living_web::did_key::Ed25519PublicKeyMultibase(group_cred->public_key);
  living_web::VerificationMethod creator_method;
  creator_method.id = group_cred->method_id;
  creator_method.type = living_web::kEd25519VerificationKey2020;
  creator_method.controller = did;
  creator_method.public_key_multibase = mb ? *mb : std::string();

  std::vector<living_web::Triple> seed;
  seed.push_back(
      group_detail::T_iri(pre_iri, living_web::kGroupDidIdentity, did));
  seed.push_back(
      group_detail::T_lit(did, living_web::kGroupSyncModule, sync_module));
  group_detail::AppendMethod(did, creator_method, &seed);
  for (living_web::DIDCapabilitySection s :
       {living_web::DIDCapabilitySection::kCapabilityInvocation,
        living_web::DIDCapabilitySection::kCapabilityDelegation,
        living_web::DIDCapabilitySection::kAssertionMethod,
        living_web::DIDCapabilitySection::kAuthentication}) {
    seed.push_back(group_detail::T_iri(did, living_web::SectionPredicate(s),
                                       creator_method.id));
  }
  if (display_name)
    seed.push_back(
        group_detail::T_lit(did, living_web::kGroupName, *display_name));
  if (description)
    seed.push_back(
        group_detail::T_lit(did, living_web::kGroupDescription, *description));
  seed.push_back(group_detail::T_lit(did, living_web::kGroupCreated,
                                     NowRfc3339(), living_web::kXsdDateTime));
  seed.push_back(group_detail::T_iri(did, living_web::kGroupCreator, creator_did));
  if (forked_from)
    seed.push_back(
        group_detail::T_iri(did, living_web::kGroupForkedFrom, *forked_from));
  if (forked_at)
    seed.push_back(
        group_detail::T_lit(did, living_web::kGroupForkedAtRevision, *forked_at));
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
  std::vector<living_web::Triple> delegates_batch;
  for (const std::string& delegate_did : initial_delegates) {
    auto vm = group_detail::MethodFromDelegateDid(did, delegate_did);
    if (!vm)
      continue;
    group_detail::AppendMethod(did, *vm, &delegates_batch);
    delegates_batch.push_back(group_detail::T_iri(
        did,
        living_web::SectionPredicate(
            living_web::DIDCapabilitySection::kCapabilityInvocation),
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

void GroupBackendManager::StripIdentity(GraphBackend* child,
                                        const std::string& parent_did) {
  std::vector<living_web::Triple> victims;
  auto add_subject = [&](const std::string& subject) {
    TripleQuery q;
    q.subject = subject;
    std::vector<living_web::Triple> ts;
    if (child->QueryTriples(q, &ts))
      victims.insert(victims.end(), ts.begin(), ts.end());
  };
  add_subject(parent_did);  // DID-doc membership, metadata, participation
  living_web::DidDocument pdoc;
  group_detail::ProjectDidDocument(child, parent_did, &pdoc);
  for (const auto& vm : pdoc.verification_method)
    add_subject(vm.id);  // per-method type/controller/publicKeyMultibase
  {
    TripleQuery q;
    q.predicate = living_web::kGroupDidIdentity;
    std::vector<living_web::Triple> ts;
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

}  // namespace content
