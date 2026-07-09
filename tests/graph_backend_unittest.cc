// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 02 browser-process graph port
// (content::GraphBackend / content::GraphBackendManager) — Personal Linked Data
// Graphs. These exercise the same normative behaviour as the standalone Graph_*
// harness, but against the browser port bound to content::DIDKeyProvider, so the
// full-tree content_unittests build has direct coverage of the §4/§5/§7
// algorithms and their DOMException error names.

#include "content/browser/graph/graph_backend_manager.h"

#include <string>
#include <vector>

#include "content/browser/did/did_key_provider.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph/sparql_results.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

// The content-address IRI of the empty graph: "graph://" + hex(SHA-256("")).
// Shared by every fresh graph until its first write (§3.3, §4.1).
constexpr char kEmptyGraphIri[] =
    "graph://"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

constexpr char kPred[] = "https://example.org/p";

// A fixture with one active credential, ready to sign reifiers (§3.2.1).
class GraphBackendTest : public testing::Test {
 protected:
  GraphBackendTest() : manager_(&identity_) {
    identity_.CreateKey("Author");  // the first key is active by default
  }

  const std::string& ActiveDid() {
    return identity_.GetActiveCredential()->did;
  }

  static living_web::Triple IriTriple(const std::string& s,
                                      const std::string& o) {
    living_web::Triple t;
    t.subject = s;
    t.predicate = kPred;
    t.object = living_web::ObjectTerm::Iri(o);
    return t;
  }

  DIDKeyProvider identity_;
  GraphBackendManager manager_;
};

TEST_F(GraphBackendTest, CreateEmptyGraph) {
  GraphBackend* g = manager_.Create("My Graph");
  ASSERT_NE(g, nullptr);
  EXPECT_EQ(g->id().substr(0, 10), "urn:graph:");
  EXPECT_FALSE(g->did().has_value());
  ASSERT_TRUE(g->display_name().has_value());
  EXPECT_EQ(*g->display_name(), "My Graph");
  EXPECT_EQ(g->trust_level(), GraphTrustLevel::kLocal);

  std::string iri;
  ASSERT_TRUE(g->GetIri(&iri));
  EXPECT_EQ(iri, kEmptyGraphIri);
}

TEST_F(GraphBackendTest, AddTripleAdvancesIri) {
  GraphBackend* g = manager_.Create();
  living_web::Triple in = IriTriple("https://example.org/s", "https://example.org/o");
  living_web::Triple out;
  ASSERT_TRUE(g->AddTriple(in, &out));
  EXPECT_EQ(out, in);

  std::string iri;
  ASSERT_TRUE(g->GetIri(&iri));
  EXPECT_NE(iri, kEmptyGraphIri);
  EXPECT_EQ(iri.substr(0, 8), "graph://");
}

TEST_F(GraphBackendTest, QueryTriplesReturnsDataNotReifiers) {
  GraphBackend* g = manager_.Create();
  living_web::Triple in = IriTriple("https://example.org/s", "https://example.org/o");
  ASSERT_TRUE(g->AddTriple(in));

  // An all-null query returns every data triple — never the 5 reifier triples
  // written alongside it (§4.2 queryTriples).
  std::vector<living_web::Triple> got;
  ASSERT_TRUE(g->QueryTriples(TripleQuery{}, &got));
  ASSERT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0], in);
}

TEST_F(GraphBackendTest, QueryTriplesFiltersByAuthor) {
  GraphBackend* g = manager_.Create();
  living_web::Triple in = IriTriple("https://example.org/s", "https://example.org/o");
  ASSERT_TRUE(g->AddTriple(in));

  TripleQuery match;
  match.author = ActiveDid();
  std::vector<living_web::Triple> got;
  ASSERT_TRUE(g->QueryTriples(match, &got));
  EXPECT_EQ(got.size(), 1u);

  TripleQuery miss;
  miss.author = "did:key:z6MkNoSuchAuthor";
  ASSERT_TRUE(g->QueryTriples(miss, &got));
  EXPECT_EQ(got.size(), 0u);
}

TEST_F(GraphBackendTest, ProvenanceReturnsSignedReifier) {
  GraphBackend* g = manager_.Create();
  living_web::Triple in = IriTriple("https://example.org/s", "https://example.org/o");
  ASSERT_TRUE(g->AddTriple(in));

  std::vector<living_web::Reifier> reifiers;
  ASSERT_TRUE(g->Provenance(in, &reifiers));
  ASSERT_EQ(reifiers.size(), 1u);
  const living_web::Reifier& r = reifiers[0];
  EXPECT_EQ(r.triple, in);
  EXPECT_EQ(r.author, ActiveDid());
  EXPECT_EQ(r.method.substr(0, r.author.size() + 1), r.author + "#");
  EXPECT_FALSE(r.timestamp.empty());
  EXPECT_FALSE(r.signature.empty());
}

TEST_F(GraphBackendTest, AddTriplesBatchIsAtomic) {
  GraphBackend* g = manager_.Create();
  std::vector<living_web::Triple> in = {
      IriTriple("https://example.org/s1", "https://example.org/o1"),
      IriTriple("https://example.org/s2", "https://example.org/o2"),
  };
  ASSERT_TRUE(g->AddTriples(in));

  std::vector<living_web::Triple> snap;
  ASSERT_TRUE(g->Snapshot(&snap));
  EXPECT_EQ(snap.size(), 2u);
}

TEST_F(GraphBackendTest, RemoveTripleEmptiesGraph) {
  GraphBackend* g = manager_.Create();
  living_web::Triple in = IriTriple("https://example.org/s", "https://example.org/o");
  ASSERT_TRUE(g->AddTriple(in));

  bool removed = false;
  ASSERT_TRUE(g->RemoveTriple(in, &removed));
  EXPECT_TRUE(removed);

  // Data triple + all reifier triples gone: the IRI returns to the empty-set
  // value and queryTriples is empty.
  std::string iri;
  ASSERT_TRUE(g->GetIri(&iri));
  EXPECT_EQ(iri, kEmptyGraphIri);

  std::vector<living_web::Triple> got;
  ASSERT_TRUE(g->QueryTriples(TripleQuery{}, &got));
  EXPECT_EQ(got.size(), 0u);
}

TEST_F(GraphBackendTest, RemoveBlankNodeSubjectIsNoOp) {
  GraphBackend* g = manager_.Create();
  // A blank-node data-triple subject cannot be named by a DELETE template, so
  // removeTriple is a no-op that resolves false (SPEC_COMPLIANCE amendment (i)).
  living_web::Triple bnode = IriTriple("_:b0", "https://example.org/o");
  bool removed = true;
  ASSERT_TRUE(g->RemoveTriple(bnode, &removed));
  EXPECT_FALSE(removed);
}

TEST_F(GraphBackendTest, SnapshotRoundTripPreservesIri) {
  GraphBackend* g = manager_.Create();
  living_web::Triple in = IriTriple("https://example.org/s", "https://example.org/o");
  ASSERT_TRUE(g->AddTriple(in));
  std::string original_iri;
  ASSERT_TRUE(g->GetIri(&original_iri));

  GraphSnapshot snap;
  ASSERT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));
  EXPECT_EQ(snap.graph_iri, original_iri);
  ASSERT_EQ(snap.proofs.size(), 1u);
  EXPECT_EQ(snap.proofs[0].role, "agent");

  std::string error;
  GraphBackend* restored = manager_.FromSnapshot(snap, &error);
  ASSERT_NE(restored, nullptr) << error;
  EXPECT_EQ(restored->trust_level(), GraphTrustLevel::kExternal);

  std::string restored_iri;
  ASSERT_TRUE(restored->GetIri(&restored_iri));
  EXPECT_EQ(restored_iri, original_iri);

  std::vector<living_web::Triple> got;
  ASSERT_TRUE(restored->QueryTriples(TripleQuery{}, &got));
  ASSERT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0], in);
}

TEST_F(GraphBackendTest, JsonLdSnapshotNotSupported) {
  GraphBackend* g = manager_.Create();
  GraphSnapshot snap;
  EXPECT_FALSE(g->GetAsSnapshot(SnapshotFormat::kJsonLd, GraphSignBy::kAgent,
                                &snap));
  EXPECT_EQ(g->last_error(), "NotSupportedError");
}

TEST_F(GraphBackendTest, SupportedSnapshotFormatsAdvertised) {
  // §5.3.4: the advertised set is the three REQUIRED formats; jsonld is OPTIONAL
  // and not advertised. This is what GraphManager.supportedSnapshotFormats
  // exposes to script and what drives NotSupportedError on both sides.
  std::vector<SnapshotFormat> formats = SupportedSnapshotFormats();
  ASSERT_EQ(formats.size(), 3u);
  EXPECT_EQ(formats[0], SnapshotFormat::kNQuadsCanonical);
  EXPECT_EQ(formats[1], SnapshotFormat::kNQuads);
  EXPECT_EQ(formats[2], SnapshotFormat::kTurtle);
  EXPECT_TRUE(IsSnapshotFormatSupported(SnapshotFormat::kNQuadsCanonical));
  EXPECT_TRUE(IsSnapshotFormatSupported(SnapshotFormat::kNQuads));
  EXPECT_TRUE(IsSnapshotFormatSupported(SnapshotFormat::kTurtle));
  EXPECT_FALSE(IsSnapshotFormatSupported(SnapshotFormat::kJsonLd));

  // Consumer side: a snapshot tagged jsonld is rejected before proof/parse.
  GraphBackend* g = manager_.Create();
  ASSERT_TRUE(g->AddTriple(IriTriple("https://example.org/s", "https://example.org/o")));
  GraphSnapshot snap;
  ASSERT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));
  snap.format = SnapshotFormat::kJsonLd;
  std::string error;
  EXPECT_EQ(manager_.FromSnapshot(snap, &error), nullptr);
  EXPECT_EQ(error, "NotSupportedError");
}

TEST_F(GraphBackendTest, SignByGraphRequiresDidMatch) {
  // A fresh local graph has no DID, so it cannot produce a "graph"-role proof.
  GraphBackend* g = manager_.Create();
  GraphSnapshot snap;
  EXPECT_FALSE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                                GraphSignBy::kGraph, &snap));
  EXPECT_EQ(g->last_error(), "NotAllowedError");
}

TEST_F(GraphBackendTest, HolonicQueryAcrossNamedGraph) {
  GraphBackend* a = manager_.Create("A");
  GraphBackend* b = manager_.Create("B");
  ASSERT_TRUE(a->AddTriple(IriTriple("https://example.org/a", "https://example.org/1")));
  ASSERT_TRUE(b->AddTriple(IriTriple("https://example.org/b", "https://example.org/2")));

  std::string b_iri;
  ASSERT_TRUE(b->GetIri(&b_iri));

  // Default graph = A; named graph <b_iri> = B (§7.2 dataset construction).
  std::string q =
      "SELECT (COUNT(*) AS ?n) WHERE { { ?s <" + std::string(kPred) +
      "> ?o } UNION { GRAPH <" + b_iri + "> { ?s <" + std::string(kPred) +
      "> ?o } } }";
  living_web::SparqlResult r = a->QuerySparql(q, {b});
  ASSERT_TRUE(r.ok) << r.error;
  // Both graphs contribute one data triple → COUNT = 2.
  EXPECT_NE(r.payload.find("\"2\""), std::string::npos);
}

TEST_F(GraphBackendTest, NoActiveCredentialRejectsAddTriple) {
  DIDKeyProvider empty_identity;  // no CreateKey → no active credential
  GraphBackendManager manager(&empty_identity);
  GraphBackend* g = manager.Create();
  living_web::Triple in = IriTriple("https://example.org/s", "https://example.org/o");
  EXPECT_FALSE(g->AddTriple(in));
  EXPECT_EQ(g->last_error(), "InvalidStateError");
}

TEST_F(GraphBackendTest, DissolveIsTerminalAndIdempotent) {
  GraphBackend* g = manager_.Create();
  ASSERT_TRUE(g->AddTriple(IriTriple("https://example.org/s", "https://example.org/o")));

  EXPECT_TRUE(g->Dissolve());
  EXPECT_TRUE(g->Dissolve());  // idempotent (§4.3)
  EXPECT_TRUE(g->dissolved());

  // Every subsequent operation rejects with InvalidStateError.
  living_web::Triple in = IriTriple("https://example.org/s2", "https://example.org/o2");
  EXPECT_FALSE(g->AddTriple(in));
  EXPECT_EQ(g->last_error(), "InvalidStateError");

  std::string iri;
  EXPECT_FALSE(g->GetIri(&iri));
  EXPECT_EQ(g->last_error(), "InvalidStateError");

  std::vector<living_web::Triple> got;
  EXPECT_FALSE(g->QueryTriples(TripleQuery{}, &got));
  EXPECT_EQ(g->last_error(), "InvalidStateError");
}

TEST_F(GraphBackendTest, FromSnapshotRejectsEmptyProofs) {
  GraphBackend* g = manager_.Create();
  ASSERT_TRUE(g->AddTriple(IriTriple("https://example.org/s", "https://example.org/o")));
  GraphSnapshot snap;
  ASSERT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));

  snap.proofs.clear();  // §5.5 step 2: unsigned snapshots are rejected
  std::string error;
  EXPECT_EQ(manager_.FromSnapshot(snap, &error), nullptr);
  EXPECT_EQ(error, "DataError");
}

TEST_F(GraphBackendTest, FromSnapshotRejectsTamperedData) {
  GraphBackend* g = manager_.Create();
  ASSERT_TRUE(g->AddTriple(IriTriple("https://example.org/s", "https://example.org/o")));
  GraphSnapshot snap;
  ASSERT_TRUE(g->GetAsSnapshot(SnapshotFormat::kNQuadsCanonical,
                               GraphSignBy::kAgent, &snap));

  // Tamper with the payload after signing: the proof no longer matches and the
  // recomputed content hash diverges from the claimed IRI (§5.5 steps 2/4).
  snap.data += "<https://example.org/x> <https://example.org/y> "
               "<https://example.org/z> .\n";
  std::string error;
  EXPECT_EQ(manager_.FromSnapshot(snap, &error), nullptr);
  EXPECT_EQ(error, "DataError");
}

}  // namespace
}  // namespace content
