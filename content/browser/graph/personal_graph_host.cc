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
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver)
    : backend_(backend),
      manager_(manager),
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
  living_web::Triple added;
  if (!backend_->AddTriple(FromMojo(triple), &added)) {
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

}  // namespace content
