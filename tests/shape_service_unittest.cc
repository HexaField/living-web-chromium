// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 07 browser-process shape port (content::ShapeService)
// plus the shared Chromium-independent shape-definition core
// (content/browser/shapes/shape_definition.{h,cc}) — Dynamic Graph Shape
// Validation. These exercise the same normative behaviour as the standalone
// Shape_* conformance harness, but against the browser port bound to
// content::DIDKeyProvider, content::GovernanceBackend, content::
// GraphBackendManager and content::GroupBackendManager, so the full-tree
// content_unittests build has direct coverage of the §5.2 registration +
// storage, the §5.2/§10.4 updateSHACL authorisation gate, the §4.6/§7.1
// narrowing rule, the §5.5 constructor execution + §5.6 instance query, the
// §5.7 setter/collection classification, and the §7 cross-graph inheritance with
// its §10.5 acceptance (tamper) defence. The byte-critical core (the §4 grammar,
// the §6.3 JCS canonicalisation, the §6.4 `sha256:`+hex content address, and the
// §4.4/§10.3 datatype validation) is shared verbatim with the standalone
// harness, so the shape parsed, the content address derived, and the value
// validated never diverge between the two build worlds.

#include "content/browser/shapes/shape_service.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/did/group_backend_manager.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/shapes/shape_definition.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

// ---- §4 shape-definition JSON fixtures (identical to the standalone harness) --

// A Person shape exercising a required scalar (name), an optional scalar (age),
// and an unbounded IRI collection (knows), with a full §5.5 constructor.
constexpr char kPersonShape[] = R"JSON({
  "targetClass": "http://schema.org/Person",
  "properties": [
    {"path": "http://schema.org/name", "name": "name", "datatype": "xsd:string", "minCount": 1, "maxCount": 1},
    {"path": "http://schema.org/age", "name": "age", "datatype": "xsd:integer", "maxCount": 1},
    {"path": "http://schema.org/knows", "name": "knows", "datatype": "URI"}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://schema.org/Person"},
    {"action": "shape://actions/setSingleTarget", "subject": "this", "predicate": "http://schema.org/name", "object": "name"},
    {"action": "shape://actions/setSingleTarget", "subject": "this", "predicate": "http://schema.org/age", "object": "age"},
    {"action": "shape://actions/addCollectionTarget", "subject": "this", "predicate": "http://schema.org/knows", "object": "knows"}
  ]
})JSON";

// A Thing shape exercising every §4.2 setter classification: `title` scalar,
// `locked` read-only (no setter), `tag` unbounded collection.
constexpr char kThingShape[] = R"JSON({
  "targetClass": "http://example.org/Thing",
  "properties": [
    {"path": "http://example.org/title", "name": "title", "datatype": "xsd:string", "minCount": 1, "maxCount": 1},
    {"path": "http://example.org/locked", "name": "locked", "datatype": "xsd:string", "maxCount": 1, "readOnly": true},
    {"path": "http://example.org/tag", "name": "tag", "datatype": "xsd:string"}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Thing"},
    {"action": "shape://actions/setSingleTarget", "subject": "this", "predicate": "http://example.org/title", "object": "title"}
  ]
})JSON";

constexpr char kAnimalShape[] = R"JSON({
  "targetClass": "http://example.org/Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 0, "maxCount": 1}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Animal"}
  ]
})JSON";

// Extends Animal and narrows it (legs becomes required) — a valid §4.6 refinement.
constexpr char kDogShape[] = R"JSON({
  "targetClass": "http://example.org/Dog",
  "extends": "Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 1, "maxCount": 1}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Dog"}
  ]
})JSON";

// Extends Animal but LOOSENS it (maxCount 1 → 4) — an invalid §4.6 extension.
constexpr char kCatShape[] = R"JSON({
  "targetClass": "http://example.org/Cat",
  "extends": "Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 0, "maxCount": 4}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Cat"}
  ]
})JSON";

// A same-name "Animal" shape that strictly narrows the inherited Animal (legs
// minCount 0 → 1) WITHOUT `extends` — a §7.3 local override that shadows the
// inherited definition. Not an extension, so it carries no `extends` key.
constexpr char kAnimalNarrowedShape[] = R"JSON({
  "targetClass": "http://example.org/Animal",
  "properties": [
    {"path": "http://example.org/legs", "name": "legs", "datatype": "xsd:integer", "minCount": 1, "maxCount": 1}
  ],
  "constructor": [
    {"action": "shape://actions/addLink", "subject": "this", "predicate": "rdf://type", "object": "http://example.org/Animal"}
  ]
})JSON";

// ---- lookup helpers (mirror the standalone FindInfo / FindInfoProp) ----------

ShapePropertyInfo* FindInfoProp(ShapeInfo* s, const std::string& name) {
  for (auto& p : s->properties)
    if (p.name == name)
      return &p;
  return nullptr;
}

ShapeInfo* FindInfo(std::vector<ShapeInfo>* v, const std::string& name) {
  for (auto& s : *v)
    if (s.name == name)
      return &s;
  return nullptr;
}

// ---- fixture ---------------------------------------------------------------

// A shape fixture mirroring the standalone GovFixture: a group W (a graph
// bearing a did:graph whose DID document holds the group key in every capability
// section) plus a GovernanceBackend and a ShapeService over the same
// DIDKeyProvider / GraphBackendManager. Each write is authored by the group's
// constitutional key (gcred_, whose did == W's did:graph), so an open-mode graph
// authorises registration out of the box and the §7 inheritance tests can hand
// the acting credential to GroupBackend::Invite().
class ShapeServiceTest : public testing::Test {
 protected:
  ShapeServiceTest()
      : graphs_(&identity_),
        groups_(&identity_, &graphs_),
        gov_(&identity_),
        svc_(&identity_, &gov_, &graphs_) {
    identity_.CreateKey("Human");  // the first key is active by default
    group_ = MakeGroup("Governed", std::nullopt);
    gcred_ = CredIdForDid(group_->did());
  }

  // Create a group with the given display name and optional participates_in
  // parent (a did:graph). Every group requires a REQUIRED §4.5 sync module.
  std::unique_ptr<GroupBackend> MakeGroup(
      const std::string& display_name,
      const std::optional<std::string>& participates_in) {
    GroupCreationOptions o;
    o.sync_module = "urn:sync:module:default";
    o.display_name = display_name;
    o.participates_in = participates_in;
    return groups_.CreateGroup(o);
  }

  // The credential whose DID equals |did| — for a group, its own adopted key.
  std::string CredIdForDid(const std::string& did) const {
    for (const DIDKeyPair* c : identity_.ListCredentials())
      if (c->did == did)
        return c->id;
    return std::string();
  }

  // Mint the root (optionally with an explicit action set), install the
  // capability constraint, and enter enforced mode, all authored by the group
  // key. Returns the root capability id. Mirrors the standalone BootstrapEnforced.
  std::string BootstrapEnforced(
      const std::optional<std::vector<std::string>>& actions = std::nullopt) {
    std::string root;
    EXPECT_TRUE(gov_.MintRootCapability(W(), gcred_, actions, &root));
    std::string cid;
    EXPECT_TRUE(
        gov_.InstallCapabilityConstraint(W(), gcred_, std::nullopt, &cid));
    EXPECT_TRUE(
        gov_.SetEnforcementMode(W(), gcred_, EnforcementMode::kEnforced));
    return root;
  }

  GraphBackend* W() { return group_->graph(); }
  const std::string& Wdid() { return group_->did(); }

  DIDKeyProvider identity_;
  GraphBackendManager graphs_;
  GroupBackendManager groups_;
  GovernanceBackend gov_;
  ShapeService svc_;
  std::unique_ptr<GroupBackend> group_;
  std::string gcred_;
};

// ---- §5 service: registration, storage, listing ----------------------------

TEST_F(ShapeServiceTest, AddShapeStoresAndLists) {
  // Open mode: no capability constraint installed, so registration is allowed.
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));

  auto shapes = svc_.GetShapes(W());
  EXPECT_EQ(shapes.size(), size_t(1));
  ShapeInfo* p = FindInfo(&shapes, "Person");
  EXPECT_TRUE(p != nullptr);
  EXPECT_EQ(p->target_class, std::string("http://schema.org/Person"));
  EXPECT_EQ(p->source_graph_did, Wdid());  // registered locally
  EXPECT_TRUE(living_web::IsWellFormedShapeAddress(p->definition_address));
  EXPECT_EQ(p->properties.size(), size_t(3));
  EXPECT_TRUE(FindInfoProp(p, "name") != nullptr);
}

TEST_F(ShapeServiceTest, DuplicateNameConstraintError) {
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));
  EXPECT_FALSE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("ConstraintError"));
}

TEST_F(ShapeServiceTest, MalformedSyntaxError) {
  EXPECT_FALSE(svc_.AddShape(W(), "Bad", "{not a shape", gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("SyntaxError"));
}

TEST_F(ShapeServiceTest, UnknownAuthorInvalidState) {
  EXPECT_FALSE(svc_.AddShape(W(), "Person", kPersonShape, "urn:uuid:nope"));
  EXPECT_EQ(svc_.last_error(), std::string("InvalidStateError"));
}

TEST_F(ShapeServiceTest, ExtendsNarrowingEnforced) {
  EXPECT_TRUE(svc_.AddShape(W(), "Animal", kAnimalShape, gcred_));
  EXPECT_TRUE(svc_.AddShape(W(), "Dog", kDogShape, gcred_));  // valid narrowing
  EXPECT_FALSE(svc_.AddShape(W(), "Cat", kCatShape, gcred_));  // loosens
  EXPECT_EQ(svc_.last_error(), std::string("ConstraintError"));
  // extends an unresolvable parent name → ConstraintError.
  const char kGhost[] =
      R"({"targetClass":"G","extends":"Nonexistent","properties":[],"constructor":[]})";
  EXPECT_FALSE(svc_.AddShape(W(), "Ghost", kGhost, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("ConstraintError"));
}

TEST_F(ShapeServiceTest, RemoveShape) {
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));
  EXPECT_EQ(svc_.GetShapes(W()).size(), size_t(1));
  EXPECT_TRUE(svc_.RemoveShape(W(), "Person", gcred_));
  EXPECT_EQ(svc_.GetShapes(W()).size(), size_t(0));
  // Removing a shape that was never registered is a no-op success.
  EXPECT_TRUE(svc_.RemoveShape(W(), "Ghost", gcred_));
}

// ---- §5.5/§5.6 instance construction + query -------------------------------

TEST_F(ShapeServiceTest, CreateInstanceExecutesConstructor) {
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));

  std::string inst;
  std::map<std::string, std::string> vals = {
      {"name", "Ada Lovelace"}, {"age", "36"}, {"knows", "did:example:bob"}};
  EXPECT_TRUE(svc_.CreateShapeInstance(W(), "Person", "", vals, gcred_, &inst));
  EXPECT_EQ(inst.substr(0, 9), std::string("urn:uuid:"));

  std::vector<std::string> instances;
  EXPECT_TRUE(svc_.GetShapeInstances(W(), "Person", &instances));
  EXPECT_EQ(instances.size(), size_t(1));
  EXPECT_EQ(instances[0], inst);  // matched via the rdf://type IRI discriminator

  ShapeInstanceData data;
  EXPECT_TRUE(svc_.GetShapeInstanceData(W(), "Person", inst, &data));
  EXPECT_EQ(data["name"].size(), size_t(1));
  EXPECT_EQ(data["name"][0], std::string("Ada Lovelace"));
  EXPECT_EQ(data["age"][0], std::string("36"));
  EXPECT_EQ(data["knows"][0], std::string("did:example:bob"));  // URI → IRI term
}

TEST_F(ShapeServiceTest, CreateInstanceRequiredMissingTypeError) {
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));
  std::string inst;
  std::map<std::string, std::string> vals = {{"age", "36"}};  // no required name
  EXPECT_FALSE(svc_.CreateShapeInstance(W(), "Person", "", vals, gcred_, &inst));
  EXPECT_EQ(svc_.last_error(), std::string("TypeError"));
}

TEST_F(ShapeServiceTest, CreateInstanceDatatypeTypeError) {
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "X"},
                                             {"age", "notanumber"}};
  EXPECT_FALSE(svc_.CreateShapeInstance(W(), "Person", "", vals, gcred_, &inst));
  EXPECT_EQ(svc_.last_error(), std::string("TypeError"));
}

TEST_F(ShapeServiceTest, CreateInstanceUnknownShapeNotFound) {
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "X"}};
  EXPECT_FALSE(svc_.CreateShapeInstance(W(), "Nope", "", vals, gcred_, &inst));
  EXPECT_EQ(svc_.last_error(), std::string("NotFoundError"));
}

// ---- §5.7 setters + collection operations ----------------------------------

TEST_F(ShapeServiceTest, ScalarSetterAndGuards) {
  EXPECT_TRUE(svc_.AddShape(W(), "Thing", kThingShape, gcred_));
  std::string inst;
  std::map<std::string, std::string> vals = {{"title", "Hello"}};
  EXPECT_TRUE(svc_.CreateShapeInstance(W(), "Thing", "", vals, gcred_, &inst));

  // Scalar setter replaces the single value.
  EXPECT_TRUE(
      svc_.SetShapeProperty(W(), "Thing", inst, "title", "World", gcred_));
  ShapeInstanceData data;
  EXPECT_TRUE(svc_.GetShapeInstanceData(W(), "Thing", inst, &data));
  EXPECT_EQ(data["title"].size(), size_t(1));
  EXPECT_EQ(data["title"][0], std::string("World"));

  // Read-only property: no setter (§4.2).
  EXPECT_FALSE(
      svc_.SetShapeProperty(W(), "Thing", inst, "locked", "x", gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("NoModificationAllowedError"));

  // Collection property via the scalar setter → wrong accessor.
  EXPECT_FALSE(svc_.SetShapeProperty(W(), "Thing", inst, "tag", "x", gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("InvalidAccessError"));
}

TEST_F(ShapeServiceTest, CollectionAddRemove) {
  EXPECT_TRUE(svc_.AddShape(W(), "Thing", kThingShape, gcred_));
  std::string inst;
  std::map<std::string, std::string> vals = {{"title", "T"}};
  EXPECT_TRUE(svc_.CreateShapeInstance(W(), "Thing", "", vals, gcred_, &inst));

  EXPECT_TRUE(
      svc_.AddToShapeCollection(W(), "Thing", inst, "tag", "red", gcred_));
  EXPECT_TRUE(
      svc_.AddToShapeCollection(W(), "Thing", inst, "tag", "blue", gcred_));
  ShapeInstanceData data;
  EXPECT_TRUE(svc_.GetShapeInstanceData(W(), "Thing", inst, &data));
  EXPECT_EQ(data["tag"].size(), size_t(2));

  EXPECT_TRUE(svc_.RemoveFromShapeCollection(W(), "Thing", inst, "tag", "red",
                                             gcred_));
  data.clear();
  EXPECT_TRUE(svc_.GetShapeInstanceData(W(), "Thing", inst, &data));
  EXPECT_EQ(data["tag"].size(), size_t(1));
  EXPECT_EQ(data["tag"][0], std::string("blue"));

  // The scalar `title` rejects collection operations.
  EXPECT_FALSE(
      svc_.AddToShapeCollection(W(), "Thing", inst, "title", "x", gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("InvalidAccessError"));
}

// ---- §5.2/§10.4 updateSHACL authorisation under enforcement ----------------

TEST_F(ShapeServiceTest, UpdateShaclRequiredUnderEnforcement) {
  // Root holds the 8 framework-core actions, NOT updateSHACL.
  BootstrapEnforced();
  EXPECT_FALSE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("NotAllowedError"));
}

TEST_F(ShapeServiceTest, UpdateShaclGrantedUnderEnforcement) {
  // Mint the root WITH the updateSHACL extension action (+ the write actions the
  // constructor needs + updateGovernance, which BootstrapEnforced's
  // SetEnforcementMode requires once a capability constraint is installed).
  BootstrapEnforced(std::vector<std::string>{"createLink", "removeLink",
                                             "updateSHACL", "updateGovernance"});
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "Grace"}};
  EXPECT_TRUE(svc_.CreateShapeInstance(W(), "Person", "", vals, gcred_, &inst));
}

// ---- §7 cross-graph inheritance + §10.5 tamper defence ---------------------

TEST_F(ShapeServiceTest, InheritanceRequiresAcceptance) {
  // The fixture's group_ is the PARENT context.
  EXPECT_TRUE(svc_.AddShape(W(), "Person", kPersonShape, gcred_));

  // A child context that unilaterally declares participation in the parent.
  std::unique_ptr<GroupBackend> child = MakeGroup("Child", Wdid());
  EXPECT_TRUE(child != nullptr);
  GraphBackend* C = child->graph();
  const std::string ccred = CredIdForDid(child->did());

  // §10.5: without the parent's acceptance the inherited shape is invisible.
  EXPECT_EQ(svc_.GetShapes(C).size(), size_t(0));
  std::string inst;
  std::map<std::string, std::string> vals = {{"name", "X"}};
  EXPECT_FALSE(svc_.CreateShapeInstance(C, "Person", "", vals, ccred, &inst));
  EXPECT_EQ(svc_.last_error(), std::string("NotFoundError"));

  // Parent accepts the child (authored by a capabilityDelegation delegate).
  group_->SetActingCredential(gcred_);
  EXPECT_TRUE(group_->Invite(child->did()));

  // Now the shape is inherited and instantiable in the child, and construction
  // triples land in the CHILD graph (§5.5 step 4).
  auto shapes = svc_.GetShapes(C);
  EXPECT_EQ(shapes.size(), size_t(1));
  ShapeInfo* p = FindInfo(&shapes, "Person");
  EXPECT_TRUE(p != nullptr);
  EXPECT_EQ(p->source_graph_did, Wdid());  // sourced from the parent
  EXPECT_TRUE(svc_.CreateShapeInstance(C, "Person", "", vals, ccred, &inst));
  std::vector<std::string> in_child;
  EXPECT_TRUE(svc_.GetShapeInstances(C, "Person", &in_child));
  EXPECT_EQ(in_child.size(), size_t(1));
  // The parent graph holds no instances of its own.
  std::vector<std::string> in_parent;
  EXPECT_TRUE(svc_.GetShapeInstances(W(), "Person", &in_parent));
  EXPECT_EQ(in_parent.size(), size_t(0));
}

TEST_F(ShapeServiceTest, LocalOverridesInherited) {
  EXPECT_TRUE(svc_.AddShape(W(), "Animal", kAnimalShape, gcred_));

  std::unique_ptr<GroupBackend> child = MakeGroup("Child", Wdid());
  GraphBackend* C = child->graph();
  const std::string ccred = CredIdForDid(child->did());
  group_->SetActingCredential(gcred_);
  EXPECT_TRUE(group_->Invite(child->did()));

  // Child registers a same-name shape that strictly narrows the inherited one.
  EXPECT_TRUE(svc_.AddShape(C, "Animal", kAnimalNarrowedShape, ccred));

  auto shapes = svc_.GetShapes(C);
  ShapeInfo* a = FindInfo(&shapes, "Animal");
  EXPECT_TRUE(a != nullptr);
  EXPECT_EQ(a->source_graph_did, child->did());  // local shadows inherited (§7.3)
  ShapePropertyInfo* legs = FindInfoProp(a, "legs");
  EXPECT_TRUE(legs != nullptr);
  EXPECT_EQ(legs->min_count, 1ul);  // the child's tightened constraint
}

}  // namespace
}  // namespace content
