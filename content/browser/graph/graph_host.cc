// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/graph/graph_host.h"

#include "base/logging.h"
#include "base/time/time.h"

namespace content {

namespace {

std::string NowRfc3339() {
  base::Time now = base::Time::Now();
  base::Time::Exploded exploded;
  now.UTCExplode(&exploded);
  char buf[64];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
           exploded.year, exploded.month, exploded.day_of_month,
           exploded.hour, exploded.minute, exploded.second);
  return std::string(buf);
}

}  // namespace

GraphHost::GraphHost(
    GraphStore* store,
    mojo::PendingReceiver<graph::mojom::PersonalGraphHost> receiver)
    : store_(store), receiver_(this, std::move(receiver)) {}

GraphHost::~GraphHost() = default;

content::SignedTriple GraphHost::ToContentSignedTriple(
    const graph::mojom::SemanticTriplePtr& mojo_triple) {
  content::SignedTriple signed_triple;
  signed_triple.data.source = mojo_triple->source;
  signed_triple.data.target = mojo_triple->target;
  signed_triple.data.predicate = mojo_triple->predicate;
  signed_triple.author = "did:key:local";
  signed_triple.timestamp = NowRfc3339();
  signed_triple.proof.key = "did:key:local";
  signed_triple.proof.signature = "unsigned";
  return signed_triple;
}

graph::mojom::SignedTriplePtr GraphHost::ToMojoSignedTriple(
    const content::SignedTriple& triple) {
  auto result = graph::mojom::SignedTriple::New();
  result->data = graph::mojom::SemanticTriple::New();
  result->data->source = triple.data.source;
  result->data->target = triple.data.target;
  result->data->predicate = triple.data.predicate;
  result->author = triple.author;
  result->timestamp = triple.timestamp;
  result->proof = graph::mojom::ContentProof::New();
  result->proof->key = triple.proof.key;
  result->proof->signature = triple.proof.signature;
  return result;
}

void GraphHost::AddTriple(graph::mojom::SemanticTriplePtr triple,
                           AddTripleCallback callback) {
  content::SignedTriple signed_triple = ToContentSignedTriple(triple);
  store_->AddTriple(signed_triple);
  std::move(callback).Run(ToMojoSignedTriple(signed_triple));
}

void GraphHost::AddTriples(
    std::vector<graph::mojom::SemanticTriplePtr> triples,
    AddTriplesCallback callback) {
  std::vector<content::SignedTriple> content_triples;
  content_triples.reserve(triples.size());
  for (const auto& t : triples) {
    content_triples.push_back(ToContentSignedTriple(t));
  }
  store_->AddTriples(content_triples);

  std::vector<graph::mojom::SignedTriplePtr> results;
  results.reserve(content_triples.size());
  for (const auto& ct : content_triples) {
    results.push_back(ToMojoSignedTriple(ct));
  }
  std::move(callback).Run(std::move(results));
}

void GraphHost::RemoveTriple(graph::mojom::SignedTriplePtr triple,
                              RemoveTripleCallback callback) {
  content::SignedTriple ct;
  ct.data.source = triple->data->source;
  ct.data.target = triple->data->target;
  ct.data.predicate = triple->data->predicate;
  ct.author = triple->author;
  ct.timestamp = triple->timestamp;
  ct.proof.key = triple->proof->key;
  ct.proof.signature = triple->proof->signature;
  bool ok = store_->RemoveTriple(ct);
  std::move(callback).Run(ok);
}

void GraphHost::QueryTriples(graph::mojom::TripleQueryPtr query,
                              QueryTriplesCallback callback) {
  content::TripleQuery cq;
  cq.source = query->source;
  cq.target = query->target;
  cq.predicate = query->predicate;
  cq.from_date = query->from_date;
  cq.until_date = query->until_date;
  if (query->limit) {
    cq.limit = *query->limit;
  }
  auto results = store_->QueryTriples(cq);

  std::vector<graph::mojom::SignedTriplePtr> mojo_results;
  mojo_results.reserve(results.size());
  for (const auto& r : results) {
    mojo_results.push_back(ToMojoSignedTriple(r));
  }
  std::move(callback).Run(std::move(mojo_results));
}

void GraphHost::QuerySparql(const std::string& sparql,
                             QuerySparqlCallback callback) {
  std::string json = store_->QuerySparql(sparql);
  auto result = graph::mojom::SparqlResult::New();
  result->result_type = "bindings";
  result->bindings_json = json;
  std::move(callback).Run(std::move(result));
}

void GraphHost::Snapshot(SnapshotCallback callback) {
  auto triples = store_->Snapshot();
  std::vector<graph::mojom::SignedTriplePtr> mojo_triples;
  mojo_triples.reserve(triples.size());
  for (const auto& t : triples) {
    mojo_triples.push_back(ToMojoSignedTriple(t));
  }
  std::move(callback).Run(std::move(mojo_triples));
}

void GraphHost::GrantAccess(const std::string& origin,
                             graph::mojom::GraphAccessLevel level,
                             GrantAccessCallback callback) {
  // TODO: Implement access control in GraphStore.
  std::move(callback).Run(true);
}

void GraphHost::RevokeAccess(const std::string& origin,
                              RevokeAccessCallback callback) {
  // TODO: Implement access control in GraphStore.
  std::move(callback).Run(true);
}

void GraphHost::AddShape(const std::string& name,
                          const std::string& shacl_json,
                          AddShapeCallback callback) {
  bool ok = store_->AddShape(name, shacl_json);
  std::move(callback).Run(ok);
}

void GraphHost::GetShapes(GetShapesCallback callback) {
  auto shapes = store_->GetShapes();
  std::move(callback).Run(std::move(shapes));
}

void GraphHost::RemoveShape(const std::string& name,
                             RemoveShapeCallback callback) {
  bool ok = store_->RemoveShape(name);
  std::move(callback).Run(ok);
}

void GraphHost::GetShapeInstances(const std::string& shape_name,
                                   GetShapeInstancesCallback callback) {
  auto instances = store_->GetShapeInstances(shape_name);
  std::move(callback).Run(std::move(instances));
}

void GraphHost::CreateShapeInstance(const std::string& shape_name,
                                    const std::string& data_json,
                                    CreateShapeInstanceCallback callback) {
  std::string uri = store_->CreateShapeInstance(shape_name, data_json);
  if (uri.empty()) {
    std::move(callback).Run(std::nullopt);
  } else {
    std::move(callback).Run(uri);
  }
}

void GraphHost::GetShapeInstanceData(const std::string& shape_name,
                                      const std::string& instance_uri,
                                      GetShapeInstanceDataCallback callback) {
  // TODO: Implement in GraphStore.
  std::move(callback).Run(std::nullopt);
}

void GraphHost::Subscribe(
    mojo::PendingRemote<graph::mojom::PersonalGraphClient> client) {
  client_.Bind(std::move(client));
}

}  // namespace content
