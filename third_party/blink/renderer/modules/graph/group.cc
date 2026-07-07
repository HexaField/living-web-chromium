// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/graph/group.h"

#include <optional>
#include <utility>

#include "base/notreached.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_did_capability_section.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_did_document_method.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_participant.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/graph/content_proof.h"
#include "third_party/blink/renderer/modules/graph/graph.h"
#include "third_party/blink/renderer/modules/graph/graph_manager.h"
#include "third_party/blink/renderer/modules/graph/signed_content.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

scoped_refptr<base::SequencedTaskRunner> GetTaskRunner(
    ExecutionContext* context) {
  // SingleThreadTaskRunner IS-A SequencedTaskRunner; explicit cast needed.
  return static_cast<scoped_refptr<base::SequencedTaskRunner>>(
      context->GetTaskRunner(TaskType::kMiscPlatformAPI));
}

// §5.1: the four capability sections. IDL enum -> Mojo enum.
graph::mojom::blink::DIDCapabilitySection SectionToMojo(
    const V8DIDCapabilitySection& section) {
  switch (section.AsEnum()) {
    case V8DIDCapabilitySection::Enum::kCapabilityInvocation:
      return graph::mojom::blink::DIDCapabilitySection::kCapabilityInvocation;
    case V8DIDCapabilitySection::Enum::kCapabilityDelegation:
      return graph::mojom::blink::DIDCapabilitySection::kCapabilityDelegation;
    case V8DIDCapabilitySection::Enum::kAssertionMethod:
      return graph::mojom::blink::DIDCapabilitySection::kAssertionMethod;
    case V8DIDCapabilitySection::Enum::kAuthentication:
      return graph::mojom::blink::DIDCapabilitySection::kAuthentication;
  }
  NOTREACHED();
}

Vector<graph::mojom::blink::DIDCapabilitySection> SectionsToMojo(
    const Vector<V8DIDCapabilitySection>& sections) {
  Vector<graph::mojom::blink::DIDCapabilitySection> out;
  out.ReserveInitialCapacity(sections.size());
  for (const auto& section : sections)
    out.push_back(SectionToMojo(section));
  return out;
}

// §4.4 DIDDocumentMethod (dictionary, addSigner/replaceSigner input) -> Mojo.
graph::mojom::blink::DIDDocumentMethodPtr MethodToMojo(
    const DIDDocumentMethod* method) {
  auto out = graph::mojom::blink::DIDDocumentMethod::New();
  out->id = method->id();
  out->type = method->type();
  out->controller = method->controller();
  out->public_key_multibase = method->publicKeyMultibase();
  return out;
}

// §8.1 signers(): a resolved verification method, projected as the DIDDocumentMethod
// dictionary (the section membership is filtered on separately, §5.4).
DIDDocumentMethod* MethodFromMojo(
    const graph::mojom::blink::VerificationMethodInfoPtr& info) {
  auto* method = MakeGarbageCollected<DIDDocumentMethod>();
  method->setId(info->id);
  method->setType(info->type);
  method->setController(info->controller);
  method->setPublicKeyMultibase(info->public_key_multibase);
  return method;
}

// §8.1 Participant (dictionary). |name| stays unset when the browser could not
// resolve the participant's group://name locally.
Participant* ParticipantFromMojo(
    const graph::mojom::blink::ParticipantInfoPtr& info) {
  auto* participant = MakeGarbageCollected<Participant>();
  participant->setDid(info->did);
  participant->setIsGroup(info->is_group);
  participant->setJoinedAt(info->joined_at);
  if (!info->name.IsNull())
    participant->setName(info->name);
  return participant;
}

HeapVector<Member<Participant>> ParticipantsFromMojo(
    const Vector<graph::mojom::blink::ParticipantInfoPtr>& participants) {
  HeapVector<Member<Participant>> out;
  out.ReserveInitialCapacity(participants.size());
  for (const auto& participant : participants)
    out.push_back(ParticipantFromMojo(participant));
  return out;
}

// §5.4 signGraph(): the Spec 01 SignedContent proof shape, reused verbatim.
SignedContent* SignedContentFromMojo(
    const graph::mojom::blink::SignedContentPtr& result) {
  auto* proof = MakeGarbageCollected<ContentProof>(
      result->proof->method, result->proof->signature, result->proof->type);
  return MakeGarbageCollected<SignedContent>(
      result->author, result->timestamp, result->data_json, proof);
}

// Shared settle path for the `=> (string? error)` governed mutations: resolve on
// a null error, otherwise reject with the browser-supplied DOMException name.
void ResolveOrReject(ScriptPromiseResolver<IDLUndefined>* resolver,
                     const String& error) {
  if (error.IsNull()) {
    resolver->Resolve();
  } else {
    Graph::RejectWithName(resolver, error);
  }
}

// Fan-in for parentGroups()/childGroups()/GraphManager.listGroups(): each did is
// opened into a Group asynchronously via GraphManager::OpenGroupByDid; the
// barrier collects the results in order and settles once the last one lands,
// dropping entries that failed to open (§8.1).
class GroupResolveBarrier final
    : public GarbageCollected<GroupResolveBarrier> {
 public:
  GroupResolveBarrier(ScriptPromiseResolver<IDLSequence<Group>>* resolver,
                      wtf_size_t count)
      : resolver_(resolver), results_(count), remaining_(count) {}

  void Place(wtf_size_t index, Group* group) {
    results_[index] = group;
    if (--remaining_ > 0)
      return;
    HeapVector<Member<Group>> out;
    out.ReserveInitialCapacity(results_.size());
    for (const auto& group_entry : results_) {
      if (group_entry)
        out.push_back(group_entry);
    }
    resolver_->Resolve(std::move(out));
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(resolver_);
    visitor->Trace(results_);
  }

 private:
  Member<ScriptPromiseResolver<IDLSequence<Group>>> resolver_;
  HeapVector<Member<Group>> results_;
  wtf_size_t remaining_;
};

}  // namespace

Group::Group(ExecutionContext* context,
             const graph::mojom::blink::GroupInfoPtr& info,
             mojo::PendingRemote<graph::mojom::blink::GroupHost> host,
             Graph* graph,
             GraphManager* manager)
    : did_(info->did),
      iri_(info->graph->iri),
      name_(info->name),
      description_(info->description),
      created_(info->created),
      creator_(info->creator),
      execution_context_(context),
      graph_(graph),
      manager_(manager),
      host_(context) {
  // A Group has no pushed events (governance is request/reply), so — unlike
  // Graph — there is no client to Subscribe.
  host_.Bind(std::move(host), GetTaskRunner(context));
}

// ---- participation (§8.1.1-8.1.3) ----

ScriptPromise<IDLSequence<Participant>> Group::participants(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Participant>>>(
          script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->Participants(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Participant>>* resolver,
         Vector<graph::mojom::blink::ParticipantInfoPtr> participants) {
        resolver->Resolve(ParticipantsFromMojo(participants));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<Participant>> Group::transitiveParticipants(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Participant>>>(
          script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->TransitiveParticipants(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Participant>>* resolver,
         Vector<graph::mojom::blink::ParticipantInfoPtr> participants) {
        resolver->Resolve(ParticipantsFromMojo(participants));
      },
      WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLSequence<Group>> Group::parentGroups(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Group>>>(
          script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->ParentGroups(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Group>>* resolver,
         GraphManager* manager, Vector<String> dids) {
        Group::ResolveGroupList(manager, resolver, dids);
      },
      WrapPersistent(resolver), WrapPersistent(manager_.Get())));

  return promise;
}

ScriptPromise<IDLSequence<Group>> Group::childGroups(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<Group>>>(
          script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->ChildGroups(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<Group>>* resolver,
         GraphManager* manager, Vector<String> dids) {
        Group::ResolveGroupList(manager, resolver, dids);
      },
      WrapPersistent(resolver), WrapPersistent(manager_.Get())));

  return promise;
}

ScriptPromise<IDLUndefined> Group::invite(ScriptState* script_state,
                                          const String& participant_did) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->Invite(participant_did,
                WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Group::revokeParticipation(
    ScriptState* script_state,
    const String& participant_did) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->RevokeParticipation(
      participant_did,
      WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLBoolean> Group::hasParticipant(ScriptState* script_state,
                                                const String& did) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->HasParticipant(
      did, WTF::BindOnce(
               [](ScriptPromiseResolver<IDLBoolean>* resolver, bool has) {
                 resolver->Resolve(has);
               },
               WrapPersistent(resolver)));

  return promise;
}

// ---- signing authority / delegate management (§5.4, §8.1.4) ----

ScriptPromise<IDLSequence<DIDDocumentMethod>> Group::signers(
    ScriptState* script_state,
    std::optional<V8DIDCapabilitySection> section) {
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<DIDDocumentMethod>>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  std::optional<graph::mojom::blink::DIDCapabilitySection> filter;
  if (section)
    filter = SectionToMojo(*section);

  host_->Signers(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLSequence<DIDDocumentMethod>>* resolver,
         std::optional<graph::mojom::blink::DIDCapabilitySection> filter,
         Vector<graph::mojom::blink::VerificationMethodInfoPtr> methods) {
        HeapVector<Member<DIDDocumentMethod>> out;
        out.ReserveInitialCapacity(methods.size());
        for (const auto& method : methods) {
          // signers(section) returns only the methods that currently reference
          // that section; signers() returns every method.
          if (filter && !method->sections.Contains(*filter))
            continue;
          out.push_back(MethodFromMojo(method));
        }
        resolver->Resolve(std::move(out));
      },
      WrapPersistent(resolver), filter));

  return promise;
}

ScriptPromise<IDLUndefined> Group::addSigner(
    ScriptState* script_state,
    const DIDDocumentMethod* method,
    const Vector<V8DIDCapabilitySection>& sections) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->AddSigner(MethodToMojo(method), SectionsToMojo(sections),
                   WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Group::removeSigner(ScriptState* script_state,
                                                const String& method_id) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->RemoveSigner(method_id,
                      WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Group::replaceSigner(
    ScriptState* script_state,
    const String& old_method_id,
    const DIDDocumentMethod* new_method,
    const Vector<V8DIDCapabilitySection>& sections) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  // §5.4 replaceSigner is composed add-then-remove: adding the replacement
  // before removing the old key means the capabilityDelegation section is never
  // momentarily emptied, so the brick-state guard can never trip mid-swap.
  host_->AddSigner(
      MethodToMojo(new_method), SectionsToMojo(sections),
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver, Group* self,
             const String& old_method_id, const String& error) {
            if (!error.IsNull()) {
              Graph::RejectWithName(resolver, error);
              return;
            }
            if (!self->host_.is_bound()) {
              resolver->Resolve();
              return;
            }
            self->host_->RemoveSigner(
                old_method_id,
                WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));
          },
          WrapPersistent(resolver), WrapPersistent(this), old_method_id));

  return promise;
}

ScriptPromise<IDLBoolean> Group::isSigner(
    ScriptState* script_state,
    const String& did,
    std::optional<V8DIDCapabilitySection> section) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  std::optional<graph::mojom::blink::DIDCapabilitySection> filter;
  if (section)
    filter = SectionToMojo(*section);

  host_->IsSigner(
      did,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLBoolean>* resolver,
             std::optional<graph::mojom::blink::DIDCapabilitySection> filter,
             bool is_signer,
             Vector<graph::mojom::blink::DIDCapabilitySection> sections) {
            if (!is_signer) {
              resolver->Resolve(false);
              return;
            }
            // isSigner(did, section) narrows to membership of that section.
            resolver->Resolve(!filter || sections.Contains(*filter));
          },
          WrapPersistent(resolver), filter));

  return promise;
}

ScriptPromise<IDLUndefined> Group::grantSection(
    ScriptState* script_state,
    const String& method_id,
    const V8DIDCapabilitySection& section) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->GrantSection(method_id, SectionToMojo(section),
                      WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Group::revokeSection(
    ScriptState* script_state,
    const String& method_id,
    const V8DIDCapabilitySection& section) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->RevokeSection(
      method_id, SectionToMojo(section),
      WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));

  return promise;
}

// ---- assertion / acting delegate / deactivation (§5.4, §4.9) ----

ScriptPromise<SignedContent> Group::signGraph(ScriptState* script_state,
                                              const String& target) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<SignedContent>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->SignGraph(
      target,
      WTF::BindOnce(
          [](ScriptPromiseResolver<SignedContent>* resolver,
             graph::mojom::blink::SignedContentPtr result,
             const String& error) {
            if (!result || !error.IsNull()) {
              Graph::RejectWithName(resolver, error);
              return;
            }
            resolver->Resolve(SignedContentFromMojo(result));
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Group::setActingCredential(
    ScriptState* script_state,
    const String& credential_id) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->SetActingCredential(
      credential_id,
      WTF::BindOnce(
          [](ScriptPromiseResolver<IDLUndefined>* resolver) {
            resolver->Resolve();
          },
          WrapPersistent(resolver)));

  return promise;
}

ScriptPromise<IDLUndefined> Group::deactivate(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->Deactivate(WTF::BindOnce(&ResolveOrReject, WrapPersistent(resolver)));

  return promise;
}

// ---- identity resolution (§4.7) ----

ScriptPromise<IDLAny> Group::resolve(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(script_state);
  auto promise = resolver->Promise();

  if (!host_.is_bound()) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "The group is not available");
    return promise;
  }

  host_->Resolve(WTF::BindOnce(
      [](ScriptPromiseResolver<IDLAny>* resolver,
         graph::mojom::blink::DidDocumentInfoPtr document,
         const String& error) {
        if (!document || !error.IsNull()) {
          Graph::RejectWithName(resolver, error);
          return;
        }
        ScriptState* ss = resolver->GetScriptState();
        if (!ss->ContextIsValid())
          return;
        ScriptState::Scope scope(ss);
        v8::Isolate* isolate = ss->GetIsolate();
        // §4.7: resolve with the [[DID-CORE]] JSON-LD document, mirroring
        // DIDCredential.resolve()'s parsed-any shape.
        const String& doc_json = document->document_json;
        if (doc_json.empty()) {
          resolver->Resolve(ScriptValue::CreateNull(isolate));
          return;
        }
        v8::Local<v8::String> json = V8String(isolate, doc_json);
        v8::Local<v8::Value> parsed;
        if (v8::JSON::Parse(ss->GetContext(), json).ToLocal(&parsed)) {
          resolver->Resolve(ScriptValue(isolate, parsed));
        } else {
          resolver->Resolve(ScriptValue(isolate, json));
        }
      },
      WrapPersistent(resolver)));

  return promise;
}

// static
void Group::ResolveGroupList(
    GraphManager* manager,
    ScriptPromiseResolver<IDLSequence<Group>>* resolver,
    const Vector<String>& dids) {
  if (dids.empty()) {
    resolver->Resolve(HeapVector<Member<Group>>());
    return;
  }

  auto* barrier =
      MakeGarbageCollected<GroupResolveBarrier>(resolver, dids.size());
  for (wtf_size_t i = 0; i < dids.size(); ++i) {
    manager->OpenGroupByDid(
        dids[i],
        WTF::BindOnce(&GroupResolveBarrier::Place, WrapPersistent(barrier), i));
  }
}

void Group::Trace(Visitor* visitor) const {
  visitor->Trace(execution_context_);
  visitor->Trace(graph_);
  visitor->Trace(manager_);
  visitor->Trace(host_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
