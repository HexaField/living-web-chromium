// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// GroupHost — the Mojo host for a single group (Spec 03 §5/§6/§7/§8.1). A thin
// adapter that converts between the Spec 03 graph.mojom value types and the
// living_web/content group model and delegates every operation to a GroupBackend
// (a non-owning view over the group's host GraphBackend plus the browser
// identity). One receiver is bound per Group handed to a renderer, alongside the
// group's PersonalGraphHost over the same host graph.
//
// Every did:graph private key lives in the browser identity backend, so every
// governed write and every signGraph proof is produced here, never in the
// renderer. On failure a method runs its callback with the backend's
// DOMException-name last_error(): "NotAllowedError" when the acting credential
// lacks the required section delegate (§5.4/§6.2), "InvalidStateError" for a
// brick-state guard (§5.4) or a failed assertion, "NotFoundError" for an
// unresolved signGraph target.

#ifndef CONTENT_BROWSER_DID_GROUP_HOST_H_
#define CONTENT_BROWSER_DID_GROUP_HOST_H_

#include <memory>
#include <string>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/governance/governance_backend.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/mojom/graph/graph.mojom.h"

namespace content {

class GroupHost : public graph::mojom::GroupHost {
 public:
  // |group| is a non-owning view whose host GraphBackend is owned by the realm's
  // GraphBackendManager; the backend outlives this host. |governance| is the
  // realm's Spec 04 registry, shared for §8.1.5 delegateCapability (it likewise
  // outlives this host). The host binds itself to |receiver| and owns the view
  // for as long as the pipe is open.
  GroupHost(std::unique_ptr<GroupBackend> group,
            GovernanceBackend* governance,
            mojo::PendingReceiver<graph::mojom::GroupHost> receiver);

  GroupHost(const GroupHost&) = delete;
  GroupHost& operator=(const GroupHost&) = delete;

  ~GroupHost() override;

  GroupBackend* backend() { return group_.get(); }

  // Runs |handler| once the renderer drops its end of the pipe. GroupService uses
  // this to destroy the host; the group's host graph stays mounted so the group
  // can be re-opened by did:graph or IRI (§4.7).
  void set_disconnect_handler(base::OnceClosure handler);

  // graph::mojom::GroupHost:
  void SetActingCredential(const std::string& credential_id,
                           SetActingCredentialCallback callback) override;
  void Invite(const std::string& participant,
              InviteCallback callback) override;
  void RevokeParticipation(const std::string& participant,
                           RevokeParticipationCallback callback) override;
  void HasParticipant(const std::string& participant,
                      HasParticipantCallback callback) override;
  void Participants(ParticipantsCallback callback) override;
  void TransitiveParticipants(TransitiveParticipantsCallback callback) override;
  void ParentGroups(ParentGroupsCallback callback) override;
  void ChildGroups(ChildGroupsCallback callback) override;
  void Signers(SignersCallback callback) override;
  void AddSigner(
      graph::mojom::DIDDocumentMethodPtr method,
      const std::vector<graph::mojom::DIDCapabilitySection>& sections,
      AddSignerCallback callback) override;
  void RemoveSigner(const std::string& method_id,
                    RemoveSignerCallback callback) override;
  void GrantSection(const std::string& method_id,
                    graph::mojom::DIDCapabilitySection section,
                    GrantSectionCallback callback) override;
  void RevokeSection(const std::string& method_id,
                     graph::mojom::DIDCapabilitySection section,
                     RevokeSectionCallback callback) override;
  void IsSigner(const std::string& delegate_did,
                IsSignerCallback callback) override;
  void SignGraph(const std::string& target,
                 SignGraphCallback callback) override;
  void Resolve(ResolveCallback callback) override;
  void Deactivate(DeactivateCallback callback) override;
  void DelegateCapability(graph::mojom::DelegateOptionsPtr options,
                          DelegateCapabilityCallback callback) override;

 private:
  // ---- mojom<->living_web converters ----
  static graph::mojom::DIDCapabilitySection SectionToMojo(
      living_web::DIDCapabilitySection s);
  static living_web::DIDCapabilitySection SectionFromMojo(
      graph::mojom::DIDCapabilitySection s);
  // The verification method plus the sections of |doc| that currently reference
  // it (§4.4 projection).
  static graph::mojom::VerificationMethodInfoPtr MethodToMojo(
      const living_web::VerificationMethod& vm,
      const living_web::DidDocument& doc);
  static graph::mojom::DidDocumentInfoPtr DocumentToMojo(
      const living_web::DidDocument& doc);
  static graph::mojom::ParticipantInfoPtr ParticipantToMojo(
      const Participant& p);
  static graph::mojom::SignedContentPtr SignedToMojo(
      const SignedContentResult& r);

  std::unique_ptr<GroupBackend> group_;
  raw_ptr<GovernanceBackend> governance_;  // The realm's Spec 04 registry.
  mojo::Receiver<graph::mojom::GroupHost> receiver_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_DID_GROUP_HOST_H_
