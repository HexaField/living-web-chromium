// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/group_backend.h"

#include <ctime>
#include <iomanip>
#include <sstream>

#include "content/browser/did/group_backend_manager.h"

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

Participant::Participant() = default;
Participant::~Participant() = default;
Participant::Participant(const Participant&) = default;
Participant& Participant::operator=(const Participant&) = default;
Participant::Participant(Participant&&) = default;
Participant& Participant::operator=(Participant&&) = default;

GroupBackend::GroupBackend(DIDKeyProvider* identity,
                           GroupBackendManager* manager,
                           GraphBackend* graph,
                           std::string did,
                           std::string group_credential_id)
    : identity_(identity),
      manager_(manager),
      graph_(graph),
      did_(std::move(did)),
      acting_credential_id_(group_credential_id),
      group_credential_id_(std::move(group_credential_id)) {}

GroupBackend::~GroupBackend() = default;

bool GroupBackend::GetIri(std::string* out) {
  if (!graph_->GetIri(out)) {
    last_error_ = graph_->last_error();
    return false;
  }
  return true;
}

bool GroupBackend::RemoveMethod(const std::string& method_id) {
  group_detail::ScopedActive scoped(identity_, ActingCredId());
  // Attribute triples (subject == method_id).
  TripleQuery q;
  q.subject = method_id;
  std::vector<living_web::Triple> attrs;
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
      living_web::kDidVerificationMethod,
      living_web::SectionPredicate(
          living_web::DIDCapabilitySection::kCapabilityInvocation),
      living_web::SectionPredicate(
          living_web::DIDCapabilitySection::kCapabilityDelegation),
      living_web::SectionPredicate(
          living_web::DIDCapabilitySection::kAssertionMethod),
      living_web::SectionPredicate(
          living_web::DIDCapabilitySection::kAuthentication)};
  for (const char* p : preds) {
    bool r = false;
    if (!graph_->RemoveTriple(group_detail::T_iri(did_, p, method_id), &r)) {
      last_error_ = graph_->last_error();
      return false;
    }
  }
  return true;
}

// §8.1.3 transitiveParticipants: every individual (non-group) participant
// reachable by descending into participating sub-groups, with cycle detection
// and a depth cap of 16 (§6.3 / §13.7). A participating group is NOT itself an
// individual and is not emitted — only its individual members flow up
// (membership is not transitive for authority, §6.3).
std::vector<Participant> GroupBackend::TransitiveParticipants() {
  std::vector<Participant> out;
  std::unordered_set<std::string> visited;
  std::function<void(GroupBackend*, int)> descend = [&](GroupBackend* grp,
                                                        int depth) {
    if (depth > 16)
      return;
    for (const auto& o : group_detail::QueryObjects(
             grp->graph_, grp->did_,
             living_web::kContextAcceptsParticipation)) {
      if (o.is_literal())
        continue;
      const std::string& pid = o.iri_or_bnode;
      if (!visited.insert(pid).second)
        continue;  // cycle or already collected
      Participant p = grp->MakeParticipant(pid);
      if (p.is_group) {
        if (GraphBackend* sub = manager_->LookupHost(pid)) {
          GroupBackend child(identity_, manager_, sub, pid,
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
std::vector<std::unique_ptr<GroupBackend>> GroupBackend::ParentGroups() {
  std::vector<std::unique_ptr<GroupBackend>> out;
  for (const auto& o : group_detail::QueryObjects(
           graph_, did_, living_web::kContextParticipatesIn)) {
    if (o.is_literal())
      continue;
    if (GraphBackend* host = manager_->LookupHost(o.iri_or_bnode))
      out.push_back(manager_->MakeHandle(host));
  }
  return out;
}

// §8.1 childGroups: the direct participants that are themselves groups
// (did:graph accepts_participation objects) and are locally mounted.
std::vector<std::unique_ptr<GroupBackend>> GroupBackend::ChildGroups() {
  std::vector<std::unique_ptr<GroupBackend>> out;
  for (const auto& o : group_detail::QueryObjects(
           graph_, did_, living_web::kContextAcceptsParticipation)) {
    if (o.is_literal())
      continue;
    if (!living_web::did_graph::IsDidGraph(o.iri_or_bnode))
      continue;
    if (GraphBackend* host = manager_->LookupHost(o.iri_or_bnode))
      out.push_back(manager_->MakeHandle(host));
  }
  return out;
}

// §5.4 signGraph: resolve |target| (a did:graph or a graph IRI) to
// {graphDid, graphIri, timestamp} and sign that structure with the acting
// credential via Spec 01 sign(). Requires the acting credential to hold an
// assertionMethod delegate (§5.4 → "NotAllowedError"). A target that is not
// locally mounted is signed as an opaque IRI with a null graphDid.
bool GroupBackend::SignGraph(const std::string& target,
                             SignedContentResult* out) {
  if (!RequireDelegate(living_web::DIDCapabilitySection::kAssertionMethod))
    return false;
  std::optional<std::string> graph_did;
  std::string graph_iri;
  if (GraphBackend* host = manager_->LookupHost(target)) {
    if (host->did())
      graph_did = *host->did();
    if (!host->GetIri(&graph_iri)) {
      last_error_ = host->last_error();
      return false;
    }
  } else {
    graph_iri = target;
  }
  std::string timestamp = NowRfc3339();
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
Participant GroupBackend::MakeParticipant(const std::string& participant) {
  Participant p;
  p.did = participant;
  p.is_group = living_web::did_graph::IsDidGraph(participant);
  living_web::Triple accept = group_detail::T_iri(
      did_, living_web::kContextAcceptsParticipation, participant);
  std::vector<living_web::Reifier> reifs;
  if (graph_->Provenance(accept, &reifs) && !reifs.empty()) {
    std::string earliest = reifs.front().timestamp;
    for (const auto& r : reifs)
      if (r.timestamp < earliest)
        earliest = r.timestamp;
    p.joined_at = std::move(earliest);
  }
  if (GraphBackend* host = manager_->LookupHost(participant)) {
    std::string subject = host->did().value_or(participant);
    p.name = group_detail::FirstLiteralOf(host, subject, living_web::kGroupName);
  }
  return p;
}

}  // namespace content
