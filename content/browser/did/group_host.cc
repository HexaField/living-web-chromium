// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/did/group_host.h"

#include <utility>

namespace content {

namespace {

// The four capability sections (§5.1), in the fixed order used to project a
// method's section memberships for signers()/isSigner().
constexpr living_web::DIDCapabilitySection kAllSections[] = {
    living_web::DIDCapabilitySection::kCapabilityInvocation,
    living_web::DIDCapabilitySection::kCapabilityDelegation,
    living_web::DIDCapabilitySection::kAssertionMethod,
    living_web::DIDCapabilitySection::kAuthentication,
};

}  // namespace

GroupHost::GroupHost(std::unique_ptr<GroupBackend> group,
                     mojo::PendingReceiver<graph::mojom::GroupHost> receiver)
    : group_(std::move(group)), receiver_(this, std::move(receiver)) {}

GroupHost::~GroupHost() = default;

void GroupHost::set_disconnect_handler(base::OnceClosure handler) {
  receiver_.set_disconnect_handler(std::move(handler));
}

// ---- converters -----------------------------------------------------------

// static
graph::mojom::DIDCapabilitySection GroupHost::SectionToMojo(
    living_web::DIDCapabilitySection s) {
  switch (s) {
    case living_web::DIDCapabilitySection::kCapabilityInvocation:
      return graph::mojom::DIDCapabilitySection::kCapabilityInvocation;
    case living_web::DIDCapabilitySection::kCapabilityDelegation:
      return graph::mojom::DIDCapabilitySection::kCapabilityDelegation;
    case living_web::DIDCapabilitySection::kAssertionMethod:
      return graph::mojom::DIDCapabilitySection::kAssertionMethod;
    case living_web::DIDCapabilitySection::kAuthentication:
      return graph::mojom::DIDCapabilitySection::kAuthentication;
  }
  return graph::mojom::DIDCapabilitySection::kCapabilityInvocation;
}

// static
living_web::DIDCapabilitySection GroupHost::SectionFromMojo(
    graph::mojom::DIDCapabilitySection s) {
  switch (s) {
    case graph::mojom::DIDCapabilitySection::kCapabilityInvocation:
      return living_web::DIDCapabilitySection::kCapabilityInvocation;
    case graph::mojom::DIDCapabilitySection::kCapabilityDelegation:
      return living_web::DIDCapabilitySection::kCapabilityDelegation;
    case graph::mojom::DIDCapabilitySection::kAssertionMethod:
      return living_web::DIDCapabilitySection::kAssertionMethod;
    case graph::mojom::DIDCapabilitySection::kAuthentication:
      return living_web::DIDCapabilitySection::kAuthentication;
  }
  return living_web::DIDCapabilitySection::kCapabilityInvocation;
}

// static
graph::mojom::VerificationMethodInfoPtr GroupHost::MethodToMojo(
    const living_web::VerificationMethod& vm,
    const living_web::DidDocument& doc) {
  auto out = graph::mojom::VerificationMethodInfo::New();
  out->id = vm.id;
  out->type = vm.type;
  out->controller = vm.controller;
  out->public_key_multibase = vm.public_key_multibase;
  for (living_web::DIDCapabilitySection s : kAllSections) {
    if (doc.InSection(s, vm.id))
      out->sections.push_back(SectionToMojo(s));
  }
  return out;
}

// static
graph::mojom::DidDocumentInfoPtr GroupHost::DocumentToMojo(
    const living_web::DidDocument& doc) {
  auto out = graph::mojom::DidDocumentInfo::New();
  out->id = doc.id;
  out->verification_method.reserve(doc.verification_method.size());
  for (const auto& vm : doc.verification_method)
    out->verification_method.push_back(MethodToMojo(vm, doc));
  out->capability_invocation = doc.capability_invocation;
  out->capability_delegation = doc.capability_delegation;
  out->assertion_method = doc.assertion_method;
  out->authentication = doc.authentication;
  out->deactivated = doc.deactivated;
  out->trust_level = doc.trust_level;
  out->document_json = doc.ToJsonLd();
  return out;
}

// static
graph::mojom::ParticipantInfoPtr GroupHost::ParticipantToMojo(
    const Participant& p) {
  auto out = graph::mojom::ParticipantInfo::New();
  out->did = p.did;
  out->is_group = p.is_group;
  out->joined_at = p.joined_at;
  out->name = p.name;
  return out;
}

// static
graph::mojom::SignedContentPtr GroupHost::SignedToMojo(
    const SignedContentResult& r) {
  auto out = graph::mojom::SignedContent::New();
  out->author = r.author;
  out->timestamp = r.timestamp;
  out->data_json = r.data_json;
  auto proof = graph::mojom::ContentProof::New();
  proof->method = r.proof_method;
  proof->signature = r.proof_sig;
  proof->type = r.proof_type;
  out->proof = std::move(proof);
  return out;
}

// ---- mojom::GroupHost ------------------------------------------------------

void GroupHost::SetActingCredential(const std::string& credential_id,
                                    SetActingCredentialCallback callback) {
  group_->SetActingCredential(credential_id);
  std::move(callback).Run();
}

void GroupHost::Invite(const std::string& participant,
                       InviteCallback callback) {
  if (!group_->Invite(participant)) {
    std::move(callback).Run(group_->last_error());
    return;
  }
  std::move(callback).Run(std::nullopt);
}

void GroupHost::RevokeParticipation(const std::string& participant,
                                    RevokeParticipationCallback callback) {
  if (!group_->RevokeParticipation(participant)) {
    std::move(callback).Run(group_->last_error());
    return;
  }
  std::move(callback).Run(std::nullopt);
}

void GroupHost::HasParticipant(const std::string& participant,
                               HasParticipantCallback callback) {
  std::move(callback).Run(group_->HasParticipant(participant));
}

void GroupHost::Participants(ParticipantsCallback callback) {
  std::vector<graph::mojom::ParticipantInfoPtr> out;
  for (const auto& p : group_->Participants())
    out.push_back(ParticipantToMojo(p));
  std::move(callback).Run(std::move(out));
}

void GroupHost::TransitiveParticipants(
    TransitiveParticipantsCallback callback) {
  std::vector<graph::mojom::ParticipantInfoPtr> out;
  for (const auto& p : group_->TransitiveParticipants())
    out.push_back(ParticipantToMojo(p));
  std::move(callback).Run(std::move(out));
}

void GroupHost::ParentGroups(ParentGroupsCallback callback) {
  std::vector<std::string> dids;
  for (const auto& g : group_->ParentGroups())
    dids.push_back(g->did());
  std::move(callback).Run(std::move(dids));
}

void GroupHost::ChildGroups(ChildGroupsCallback callback) {
  std::vector<std::string> dids;
  for (const auto& g : group_->ChildGroups())
    dids.push_back(g->did());
  std::move(callback).Run(std::move(dids));
}

void GroupHost::Signers(SignersCallback callback) {
  living_web::DidDocument doc;
  group_->Resolve(&doc);
  std::vector<graph::mojom::VerificationMethodInfoPtr> out;
  out.reserve(doc.verification_method.size());
  for (const auto& vm : doc.verification_method)
    out.push_back(MethodToMojo(vm, doc));
  std::move(callback).Run(std::move(out));
}

void GroupHost::AddSigner(
    graph::mojom::DIDDocumentMethodPtr method,
    const std::vector<graph::mojom::DIDCapabilitySection>& sections,
    AddSignerCallback callback) {
  living_web::VerificationMethod vm;
  vm.id = method->id;
  vm.type = method->type;
  vm.controller = method->controller;
  vm.public_key_multibase = method->public_key_multibase;
  std::vector<living_web::DIDCapabilitySection> secs;
  secs.reserve(sections.size());
  for (graph::mojom::DIDCapabilitySection s : sections)
    secs.push_back(SectionFromMojo(s));
  if (!group_->AddSigner(vm, secs)) {
    std::move(callback).Run(group_->last_error());
    return;
  }
  std::move(callback).Run(std::nullopt);
}

void GroupHost::RemoveSigner(const std::string& method_id,
                             RemoveSignerCallback callback) {
  if (!group_->RemoveSigner(method_id)) {
    std::move(callback).Run(group_->last_error());
    return;
  }
  std::move(callback).Run(std::nullopt);
}

void GroupHost::GrantSection(const std::string& method_id,
                             graph::mojom::DIDCapabilitySection section,
                             GrantSectionCallback callback) {
  if (!group_->GrantSection(method_id, SectionFromMojo(section))) {
    std::move(callback).Run(group_->last_error());
    return;
  }
  std::move(callback).Run(std::nullopt);
}

void GroupHost::RevokeSection(const std::string& method_id,
                              graph::mojom::DIDCapabilitySection section,
                              RevokeSectionCallback callback) {
  if (!group_->RevokeSection(method_id, SectionFromMojo(section))) {
    std::move(callback).Run(group_->last_error());
    return;
  }
  std::move(callback).Run(std::nullopt);
}

void GroupHost::IsSigner(const std::string& delegate_did,
                         IsSignerCallback callback) {
  living_web::DidDocument doc;
  group_->Resolve(&doc);
  std::vector<graph::mojom::DIDCapabilitySection> sections;
  auto vm = group_detail::MethodFromDelegateDid(group_->did(), delegate_did);
  bool is_signer = vm && doc.FindMethod(vm->id) != nullptr;
  if (is_signer) {
    for (living_web::DIDCapabilitySection s : kAllSections) {
      if (doc.InSection(s, vm->id))
        sections.push_back(SectionToMojo(s));
    }
  }
  std::move(callback).Run(is_signer, std::move(sections));
}

void GroupHost::SignGraph(const std::string& target,
                          SignGraphCallback callback) {
  SignedContentResult r;
  if (!group_->SignGraph(target, &r)) {
    std::move(callback).Run(nullptr, group_->last_error());
    return;
  }
  std::move(callback).Run(SignedToMojo(r), std::nullopt);
}

void GroupHost::Resolve(ResolveCallback callback) {
  living_web::DidDocument doc;
  if (!group_->Resolve(&doc)) {
    std::move(callback).Run(nullptr, group_->last_error());
    return;
  }
  std::move(callback).Run(DocumentToMojo(doc), std::nullopt);
}

void GroupHost::Deactivate(DeactivateCallback callback) {
  if (!group_->Deactivate()) {
    std::move(callback).Run(group_->last_error());
    return;
  }
  std::move(callback).Run(std::nullopt);
}

}  // namespace content
