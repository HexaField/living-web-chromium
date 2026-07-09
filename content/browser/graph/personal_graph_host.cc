// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/personal_graph_host.h"

#include <cstdint>
#include <utility>

namespace content {

namespace {

// The graph's current content-address IRI after a mutation, or nullopt if it
// could not be recomputed (the mutation still succeeded; the renderer keeps its
// prior value and refreshes on the next event).
std::optional<std::string> CurrentIri(GraphBackend* backend) {
  std::string iri;
  if (backend->GetIri(&iri))
    return iri;
  return std::nullopt;
}

// Spec 04 §2 / §11.5 data-layer gate. In enforced mode every renderer-authored
// triple must pass the capability check for the current identity before it is
// admitted; a single failure rejects the whole batch atomically (mirroring the
// §4.2 all-or-nothing add semantics). Open and announced modes never gate here —
// announced results are advisory only (§11) and open skips checks entirely.
// Returns the DOMException name to reject with, or nullopt to admit the batch.
std::optional<std::string> EnforcementError(
    GovernanceBackend* governance,
    GraphBackend* backend,
    const std::vector<living_web::Triple>& triples) {
  if (!governance ||
      governance->GetEnforcementMode(backend) != EnforcementMode::kEnforced) {
    return std::nullopt;
  }
  const std::string author = governance->ActiveAuthorDid();
  for (const living_web::Triple& t : triples) {
    if (!governance->CanAddTriple(backend, t, author).allowed)
      return std::string("NotAllowedError");
  }
  return std::nullopt;
}

// Maps a living_web SPARQL result kind onto the mojom |kind| byte (§4.2): 0
// Solutions, 1 Boolean, 2 Graph.
uint8_t KindToByte(living_web::SparqlResultKind kind) {
  switch (kind) {
    case living_web::SparqlResultKind::kSolutions:
      return 0;
    case living_web::SparqlResultKind::kBoolean:
      return 1;
    case living_web::SparqlResultKind::kGraph:
      return 2;
  }
  return 0;
}

}  // namespace

PersonalGraphHost::PersonalGraphHost(
    GraphBackend* backend,
    GraphBackendManager* manager,
    GovernanceBackend* governance,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver)
    : backend_(backend),
      manager_(manager),
      governance_(governance),
      receiver_(this, std::move(receiver)) {}

PersonalGraphHost::~PersonalGraphHost() = default;

void PersonalGraphHost::set_disconnect_handler(base::OnceClosure handler) {
  receiver_.set_disconnect_handler(std::move(handler));
}

// ---- converters -----------------------------------------------------------

// static
graph::mojom::LiteralValuePtr PersonalGraphHost::ToMojo(
    const living_web::LiteralValue& v) {
  auto out = graph::mojom::LiteralValue::New();
  out->lexical = v.lexical;
  out->datatype = v.datatype;
  out->language = v.language;
  return out;
}

// static
living_web::LiteralValue PersonalGraphHost::FromMojo(
    const graph::mojom::LiteralValuePtr& v) {
  living_web::LiteralValue out;
  out.lexical = v->lexical;
  out.datatype = v->datatype;
  out.language = v->language;
  return out;
}

// static
graph::mojom::TripleObjectPtr PersonalGraphHost::ToMojo(
    const living_web::ObjectTerm& o) {
  if (o.is_literal())
    return graph::mojom::TripleObject::NewLiteral(ToMojo(*o.literal));
  return graph::mojom::TripleObject::NewIriOrBnode(o.iri_or_bnode);
}

// static
living_web::ObjectTerm PersonalGraphHost::FromMojo(
    const graph::mojom::TripleObjectPtr& o) {
  if (o->is_literal())
    return living_web::ObjectTerm::Literal(FromMojo(o->get_literal()));
  return living_web::ObjectTerm::Iri(o->get_iri_or_bnode());
}

// static
graph::mojom::TriplePtr PersonalGraphHost::ToMojo(const living_web::Triple& t) {
  auto out = graph::mojom::Triple::New();
  out->subject = t.subject;
  out->predicate = t.predicate;
  out->object = ToMojo(t.object);
  return out;
}

// static
living_web::Triple PersonalGraphHost::FromMojo(
    const graph::mojom::TriplePtr& t) {
  living_web::Triple out;
  out.subject = t->subject;
  out.predicate = t->predicate;
  out.object = FromMojo(t->object);
  return out;
}

// static
graph::mojom::ReifierPtr PersonalGraphHost::ToMojo(
    const living_web::Reifier& r) {
  auto out = graph::mojom::Reifier::New();
  out->id = r.id;
  out->triple = ToMojo(r.triple);
  out->author = r.author;
  out->timestamp = r.timestamp;
  out->method = r.method;
  out->signature = r.signature;
  return out;
}

// static
graph::mojom::SnapshotFormat PersonalGraphHost::FormatToMojo(SnapshotFormat f) {
  switch (f) {
    case SnapshotFormat::kNQuadsCanonical:
      return graph::mojom::SnapshotFormat::kNQuadsCanonical;
    case SnapshotFormat::kNQuads:
      return graph::mojom::SnapshotFormat::kNQuads;
    case SnapshotFormat::kTurtle:
      return graph::mojom::SnapshotFormat::kTurtle;
    case SnapshotFormat::kJsonLd:
      return graph::mojom::SnapshotFormat::kJsonLd;
  }
  return graph::mojom::SnapshotFormat::kNQuadsCanonical;
}

// static
SnapshotFormat PersonalGraphHost::FormatFromMojo(
    graph::mojom::SnapshotFormat f) {
  switch (f) {
    case graph::mojom::SnapshotFormat::kNQuadsCanonical:
      return SnapshotFormat::kNQuadsCanonical;
    case graph::mojom::SnapshotFormat::kNQuads:
      return SnapshotFormat::kNQuads;
    case graph::mojom::SnapshotFormat::kTurtle:
      return SnapshotFormat::kTurtle;
    case graph::mojom::SnapshotFormat::kJsonLd:
      return SnapshotFormat::kJsonLd;
  }
  return SnapshotFormat::kNQuadsCanonical;
}

// static
GraphSignBy PersonalGraphHost::SignByFromMojo(graph::mojom::GraphSignBy s) {
  switch (s) {
    case graph::mojom::GraphSignBy::kAgent:
      return GraphSignBy::kAgent;
    case graph::mojom::GraphSignBy::kGraph:
      return GraphSignBy::kGraph;
    case graph::mojom::GraphSignBy::kBoth:
      return GraphSignBy::kBoth;
  }
  return GraphSignBy::kAgent;
}

// static
graph::mojom::GraphSnapshotPtr PersonalGraphHost::ToMojo(
    const GraphSnapshot& s) {
  auto out = graph::mojom::GraphSnapshot::New();
  out->graph_iri = s.graph_iri;
  out->graph_did = s.graph_did;
  out->format = FormatToMojo(s.format);
  out->timestamp = s.timestamp;
  out->data = s.data;
  out->proofs.reserve(s.proofs.size());
  for (const auto& p : s.proofs) {
    auto proof = graph::mojom::SnapshotProof::New();
    proof->role = p.role;
    proof->author = p.author;
    proof->method = p.method;
    proof->signature = p.signature;
    out->proofs.push_back(std::move(proof));
  }
  return out;
}

// static
GraphSnapshot PersonalGraphHost::FromMojo(
    const graph::mojom::GraphSnapshotPtr& s) {
  GraphSnapshot out;
  out.graph_iri = s->graph_iri;
  out.graph_did = s->graph_did;
  out.format = FormatFromMojo(s->format);
  out.timestamp = s->timestamp;
  out.data = s->data;
  out.proofs.reserve(s->proofs.size());
  for (const auto& p : s->proofs) {
    SnapshotProof proof;
    proof.role = p->role;
    proof.author = p->author;
    proof.method = p->method;
    proof.signature = p->signature;
    out.proofs.push_back(std::move(proof));
  }
  return out;
}

// static
TripleQuery PersonalGraphHost::FromMojo(
    const graph::mojom::TripleQueryPtr& q) {
  TripleQuery out;
  out.subject = q->subject;
  out.predicate = q->predicate;
  if (q->object)
    out.object = FromMojo(q->object);
  out.author = q->author;
  out.from_date = q->from_date;
  out.until_date = q->until_date;
  out.offset = q->offset;
  out.limit = q->limit;
  return out;
}

// ---- mojom::PersonalGraphHost ---------------------------------------------

void PersonalGraphHost::GetIri(GetIriCallback callback) {
  std::string iri;
  if (!backend_->GetIri(&iri)) {
    std::move(callback).Run(std::nullopt, backend_->last_error());
    return;
  }
  std::move(callback).Run(iri, std::nullopt);
}

void PersonalGraphHost::AddTriple(graph::mojom::TriplePtr triple,
                                  AddTripleCallback callback) {
  living_web::Triple in = FromMojo(triple);
  if (auto err = EnforcementError(governance_, backend_, {in})) {
    std::move(callback).Run(nullptr, std::nullopt, *err);
    return;
  }
  living_web::Triple added;
  if (!backend_->AddTriple(in, &added)) {
    std::move(callback).Run(nullptr, std::nullopt, backend_->last_error());
    return;
  }
  std::move(callback).Run(ToMojo(added), CurrentIri(backend_), std::nullopt);
}

void PersonalGraphHost::AddTriples(std::vector<graph::mojom::TriplePtr> triples,
                                   AddTriplesCallback callback) {
  std::vector<living_web::Triple> in;
  in.reserve(triples.size());
  for (const auto& t : triples)
    in.push_back(FromMojo(t));
  if (auto err = EnforcementError(governance_, backend_, in)) {
    std::move(callback).Run(std::nullopt, std::nullopt, *err);
    return;
  }
  std::vector<living_web::Triple> added;
  if (!backend_->AddTriples(in, &added)) {
    std::move(callback).Run(std::nullopt, std::nullopt, backend_->last_error());
    return;
  }
  std::vector<graph::mojom::TriplePtr> out;
  out.reserve(added.size());
  for (const auto& t : added)
    out.push_back(ToMojo(t));
  std::move(callback).Run(std::move(out), CurrentIri(backend_), std::nullopt);
}

void PersonalGraphHost::RemoveTriple(graph::mojom::TriplePtr triple,
                                     RemoveTripleCallback callback) {
  bool removed = false;
  if (!backend_->RemoveTriple(FromMojo(triple), &removed)) {
    std::move(callback).Run(false, std::nullopt, backend_->last_error());
    return;
  }
  std::move(callback).Run(removed, CurrentIri(backend_), std::nullopt);
}

void PersonalGraphHost::QueryTriples(graph::mojom::TripleQueryPtr query,
                                     QueryTriplesCallback callback) {
  std::vector<living_web::Triple> triples;
  if (!backend_->QueryTriples(FromMojo(query), &triples)) {
    std::move(callback).Run(std::nullopt, backend_->last_error());
    return;
  }
  std::vector<graph::mojom::TriplePtr> out;
  out.reserve(triples.size());
  for (const auto& t : triples)
    out.push_back(ToMojo(t));
  std::move(callback).Run(std::move(out), std::nullopt);
}

void PersonalGraphHost::Snapshot(SnapshotCallback callback) {
  std::vector<living_web::Triple> triples;
  if (!backend_->Snapshot(&triples)) {
    std::move(callback).Run(std::nullopt, backend_->last_error());
    return;
  }
  std::vector<graph::mojom::TriplePtr> out;
  out.reserve(triples.size());
  for (const auto& t : triples)
    out.push_back(ToMojo(t));
  std::move(callback).Run(std::move(out), std::nullopt);
}

void PersonalGraphHost::Provenance(graph::mojom::TriplePtr triple,
                                   ProvenanceCallback callback) {
  std::vector<living_web::Reifier> reifiers;
  if (!backend_->Provenance(FromMojo(triple), &reifiers)) {
    std::move(callback).Run(std::nullopt, backend_->last_error());
    return;
  }
  std::vector<graph::mojom::ReifierPtr> out;
  out.reserve(reifiers.size());
  for (const auto& r : reifiers)
    out.push_back(ToMojo(r));
  std::move(callback).Run(std::move(out), std::nullopt);
}

void PersonalGraphHost::QuerySparql(
    const std::string& sparql,
    const std::vector<std::string>& named_graph_ids,
    std::optional<uint64_t> timeout_ms,
    QuerySparqlCallback callback) {
  std::vector<GraphBackend*> named;
  named.reserve(named_graph_ids.size());
  for (const std::string& id : named_graph_ids) {
    GraphBackend* g = manager_->Find(id);
    if (g)
      named.push_back(g);
  }
  living_web::SparqlResult r = backend_->QuerySparql(sparql, named, timeout_ms);
  auto out = graph::mojom::SparqlQueryResult::New();
  out->ok = r.ok;
  out->error = r.error;
  out->kind = KindToByte(r.kind);
  out->payload = r.payload;
  std::move(callback).Run(std::move(out));
}

void PersonalGraphHost::GetAsSnapshot(graph::mojom::SnapshotFormat format,
                                      graph::mojom::GraphSignBy sign_by,
                                      GetAsSnapshotCallback callback) {
  GraphSnapshot snap;
  if (!backend_->GetAsSnapshot(FormatFromMojo(format), SignByFromMojo(sign_by),
                               &snap)) {
    std::move(callback).Run(nullptr, backend_->last_error());
    return;
  }
  std::move(callback).Run(ToMojo(snap), std::nullopt);
}

void PersonalGraphHost::Dissolve(DissolveCallback callback) {
  // Idempotent (§4.3). The backend stays owned by the manager and is marked
  // dissolved, so every later operation surfaces "InvalidStateError". Ownership
  // is released by PersonalGraphManager when the host's pipe disconnects.
  backend_->Dissolve();
  std::move(callback).Run();
}

void PersonalGraphHost::Subscribe(
    mojo::PendingRemote<graph::mojom::PersonalGraphClient> client) {
  client_.reset();
  client_.Bind(std::move(client));
  // Deliver tripleadded/tripleremoved in commit order (§4.2/§4.4). The backend
  // holds std::function sinks; capture a weak pointer so a backend that outlives
  // this host never touches freed client state.
  base::WeakPtr<PersonalGraphHost> self = weak_factory_.GetWeakPtr();
  backend_->set_on_triple_added([self](const living_web::Triple& t) {
    if (self)
      self->OnTripleAdded(t);
  });
  backend_->set_on_triple_removed([self](const living_web::Triple& t) {
    if (self)
      self->OnTripleRemoved(t);
  });
}

void PersonalGraphHost::OnTripleAdded(const living_web::Triple& triple) {
  if (client_)
    client_->OnTripleAdded(ToMojo(triple));
}

void PersonalGraphHost::OnTripleRemoved(const living_web::Triple& triple) {
  if (client_)
    client_->OnTripleRemoved(ToMojo(triple));
}

// ---- Spec 04 §11 result converters ----------------------------------------

// static
graph::mojom::EnforcementMode PersonalGraphHost::ModeToMojo(EnforcementMode m) {
  switch (m) {
    case EnforcementMode::kOpen:
      return graph::mojom::EnforcementMode::kOpen;
    case EnforcementMode::kAnnounced:
      return graph::mojom::EnforcementMode::kAnnounced;
    case EnforcementMode::kEnforced:
      return graph::mojom::EnforcementMode::kEnforced;
  }
  return graph::mojom::EnforcementMode::kOpen;
}

// static
EnforcementMode PersonalGraphHost::ModeFromMojo(graph::mojom::EnforcementMode m) {
  switch (m) {
    case graph::mojom::EnforcementMode::kOpen:
      return EnforcementMode::kOpen;
    case graph::mojom::EnforcementMode::kAnnounced:
      return EnforcementMode::kAnnounced;
    case graph::mojom::EnforcementMode::kEnforced:
      return EnforcementMode::kEnforced;
  }
  return EnforcementMode::kOpen;
}

// static
graph::mojom::GovernanceValidationResultPtr PersonalGraphHost::ToMojo(
    const GovernanceValidationResult& r) {
  auto out = graph::mojom::GovernanceValidationResult::New();
  out->allowed = r.allowed;
  out->rejected_by = r.rejected_by;
  out->constraint_kind = r.constraint_kind;
  out->reason = r.reason;
  out->mode = r.mode;
  return out;
}

// static
graph::mojom::GraphConstraintPtr PersonalGraphHost::ToMojo(
    const GraphConstraint& c) {
  auto out = graph::mojom::GraphConstraint::New();
  out->id = c.id;
  out->kind = c.kind;
  out->scope = c.scope;
  out->properties.reserve(c.properties.size());
  for (const auto& kv : c.properties) {
    auto p = graph::mojom::GraphConstraintProperty::New();
    p->predicate = kv.first;
    p->value = kv.second;
    out->properties.push_back(std::move(p));
  }
  return out;
}

// static
graph::mojom::CapabilityInfoPtr PersonalGraphHost::ToMojo(
    const CapabilityInfo& c) {
  auto out = graph::mojom::CapabilityInfo::New();
  out->id = c.id;
  out->actions = c.actions;
  out->resource = c.resource;
  out->caveats = c.caveats;
  out->expires = c.expires;
  return out;
}

// ---- Spec 04 §11 governance API -------------------------------------------

void PersonalGraphHost::CanAddTriple(graph::mojom::TriplePtr triple,
                                     CanAddTripleCallback callback) {
  GovernanceValidationResult r = governance_->CanAddTriple(
      backend_, FromMojo(triple), governance_->ActiveAuthorDid());
  std::move(callback).Run(ToMojo(r), std::nullopt);
}

void PersonalGraphHost::CanPerformAction(
    const std::string& action,
    const std::string& author_did,
    graph::mojom::CapabilityProofInputPtr proof,
    CanPerformActionCallback callback) {
  // The capability chain named by |proof| is resolved from the target graph by
  // the §7 walk, so it needs no separate wiring here; |proof->presentations|
  // feed the CONSTRAINT-VOCABULARY (Spec 08) `credential` caveat handler, which
  // reads them from the ValidationContext when that plug-in is registered.
  GovernanceValidationResult r =
      governance_->CanPerformAction(backend_, action, author_did);
  std::move(callback).Run(ToMojo(r), std::nullopt);
}

void PersonalGraphHost::ConstraintsFor(const std::string& context_did,
                                       ConstraintsForCallback callback) {
  std::vector<GraphConstraint> constraints =
      governance_->ConstraintsFor(backend_, context_did);
  std::vector<graph::mojom::GraphConstraintPtr> out;
  out.reserve(constraints.size());
  for (const GraphConstraint& c : constraints)
    out.push_back(ToMojo(c));
  std::move(callback).Run(std::move(out), std::nullopt);
}

void PersonalGraphHost::MyCapabilities(MyCapabilitiesCallback callback) {
  std::vector<CapabilityInfo> caps =
      governance_->MyCapabilities(backend_, governance_->ActiveAuthorDid());
  std::vector<graph::mojom::CapabilityInfoPtr> out;
  out.reserve(caps.size());
  for (const CapabilityInfo& c : caps)
    out.push_back(ToMojo(c));
  std::move(callback).Run(std::move(out), std::nullopt);
}

void PersonalGraphHost::GetEnforcementMode(GetEnforcementModeCallback callback) {
  std::move(callback).Run(ModeToMojo(governance_->GetEnforcementMode(backend_)),
                          std::nullopt);
}

void PersonalGraphHost::SetEnforcementMode(graph::mojom::EnforcementMode mode,
                                           SetEnforcementModeCallback callback) {
  if (!governance_->SetEnforcementMode(backend_,
                                       governance_->ActiveCredentialId(),
                                       ModeFromMojo(mode))) {
    // §5.2: only an updateGovernance holder may change the mode.
    std::string err = governance_->last_error();
    std::move(callback).Run(err == "not_authorised" ? "NotAllowedError" : err);
    return;
  }
  std::move(callback).Run(std::nullopt);
}

}  // namespace content
