// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Standalone Dynamic Graph Shape Validation service (Spec 07).
//
// This header-only service is the Chromium-independent mirror of the browser
// shape service (content/browser/shapes/shape_service.*). It composes the shared
// shape-definition core (content/browser/shapes/shape_definition.{h,cc} — §4
// grammar parsing, §6.3 JCS content-addressing, §4.4/§10.3 datatype validation
// and the §4.6/§7.1 narrowing rule) into the full §5 `Graph` shape API on top of
// the public Spec 02 Graph surface, the Spec 04 GovernanceEngine, and the
// Spec 03 GroupManager.
//
// What it enforces, normatively:
//   * §5.2/§10.4 authorisation — every registration/removal requires the
//     `updateSHACL` extension capability (GovernanceEngine::CanPerformAction);
//     an open-mode / no-DID graph always allows (there is nothing to enforce);
//   * §5.2 step 2 — malformed shape JSON is a "SyntaxError";
//   * §5.2 last line — a duplicate local shape name is a "ConstraintError";
//   * §4.6 / §7.1 — a shape that overrides an inherited or `extends` parent MUST
//     be a strict narrowing (ShapeNarrows), else "ConstraintError";
//   * §6.2–§6.4 — shapes are stored as content-addressed triples inside the graph
//     they govern: `<graph-id> shape://has_shape sha256:<hex>` plus the
//     rdf://type / shape://name / shape://targetClass / shape://definition quad,
//     the address being `sha256:` + hex(SHA-256(JCS(shapeJson)));
//   * §5.5 — createShapeInstance validates that every required property
//     (minCount ≥ 1) without a constructor-literal default is supplied
//     ("TypeError" otherwise), then executes the constructor actions as governed
//     triple writes to THIS graph, resolving each object's term type from the
//     property whose `path` equals the action predicate;
//   * §4.4/§10.3 — every value written by a constructor or setter is validated
//     against its property datatype before the write ("TypeError" on failure);
//   * §5.7 — setter/collection operations honour the §4.2 setter classification
//     (scalar vs collection vs none) and are subject to graph governance;
//   * §7 — shapes registered on a parent graph are visible to a child graph that
//     participates in it (context://participates_in), resolved depth-first;
//   * §10.5 — an inherited shape is only visible when the parent's governance
//     ACCEPTS the child's participation: a context://accepts_participation link
//     from the parent whose reifier author is a capabilityDelegation delegate of
//     the parent. Unaccepted participation is ignored (tamper defence).
//
// The SHA-256 primitive is the one world-specific dependency: the standalone
// harness hashes with crypto::SHA256HashString (OpenSSL); the browser service
// hashes with //crypto. The shared core never hashes — it canonicalises with
// CanonicalizeShapeJson() and formats the raw digest with FormatShapeAddress().

#ifndef LIVING_WEB_SHAPE_PROVIDER_H_
#define LIVING_WEB_SHAPE_PROVIDER_H_

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "content/browser/shapes/shape_definition.h"
#include "capability_provider.h"
#include "crypto_sha2.h"
#include "did_key_provider.h"
#include "graph_provider.h"
#include "group_provider.h"

namespace living_web {

// -- §5.1 API value types (mirror the ShapeInfo / PropertyInfo IDL dicts) -----

struct ShapePropertyInfo {
  std::string name;
  std::string path;
  std::optional<std::string> datatype;
  unsigned long min_count = 0;
  std::optional<unsigned long> max_count;
  bool writable = true;
  bool read_only = false;
};

struct ShapeInfo {
  std::string name;
  std::string target_class;
  std::string definition_address;
  std::string source_graph_did;  // graph where registered (this graph, or parent)
  std::vector<ShapePropertyInfo> properties;
};

// The full property dictionary of a shape instance (§5.6 getShapeInstanceData):
// each property `name` maps to its ordered object values (IRI or literal lexical
// form). A scalar property carries one value; a collection carries many.
using ShapeInstanceData = std::map<std::string, std::vector<std::string>>;

// -- the shape service --------------------------------------------------------

// Implements the Spec 07 §5 API over a set of graphs. Every method takes the
// target Graph* as its first argument (the browser binds these onto the `Graph`
// interface; the harness calls them directly). |governance| gates the
// `updateSHACL` extension action and the per-write governance of §5.5/§5.7; it
// may be null (treated as open). |groups| resolves context://participates_in
// parents for §7 inheritance and may be null (local shapes only).
class ShapeService {
 public:
  ShapeService(DIDKeyProvider* identity,
               GovernanceEngine* governance,
               GroupManager* groups)
      : identity_(identity), governance_(governance), groups_(groups) {}

  ShapeService(const ShapeService&) = delete;
  ShapeService& operator=(const ShapeService&) = delete;

  const std::string& last_error() const { return last_error_; }

  // §5.2 addShape: register |shape_json| under |name| into |W|, authored by the
  // credential |author_cred_id|. Returns false + last_error() on any rejection.
  bool AddShape(Graph* W,
                const std::string& name,
                const std::string& shape_json,
                const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    // §5.2 step 1 / §10.4 — updateSHACL is REQUIRED.
    if (!CanUpdateShacl(W, author->did))
      return Fail("NotAllowedError");
    // §5.2 step 2 — malformed shape → SyntaxError.
    ShapeDefinition def;
    std::string perr;
    if (!ParseShapeDefinition(shape_json, &def, &perr))
      return Fail("SyntaxError");

    const std::string gid = GraphId(W);
    // §5.2 last line — a duplicate local name is a ConstraintError.
    ResolvedShape existing_local;
    if (FindLocalShape(W, gid, name, &existing_local))
      return Fail("ConstraintError");

    // §4.6 / §7.1 / §7.2-step-4 — narrowing against the resolved parent.
    if (def.extends) {
      ResolvedShape parent;
      if (!ResolveShape(W, *def.extends, &parent))
        return Fail("ConstraintError");  // §7.2 step 4: parent MUST resolve
      std::string reason;
      if (!ShapeNarrows(parent.def, def, &reason))
        return Fail("ConstraintError");
    } else {
      // §7.1 — overriding an inherited shape of the same name MUST narrow it.
      ResolvedShape inherited;
      if (ResolveShape(W, name, &inherited)) {
        std::string reason;
        if (!ShapeNarrows(inherited.def, def, &reason))
          return Fail("ConstraintError");
      }
    }

    // §6.3 — content address = "sha256:" + hex(SHA-256(JCS(shapeJson))).
    auto canonical = CanonicalizeShapeJson(shape_json);
    if (!canonical)
      return Fail("SyntaxError");
    const std::string address =
        FormatShapeAddress(crypto::SHA256HashString(*canonical));

    // §6.4 — the stored triple shape, authored by the caller.
    std::vector<Triple> triples = {
        group_detail::T_iri(gid, kShapeHasShape, address),
        group_detail::T_iri(address, kShapeRdfType, kShapeTypeShape),
        group_detail::T_lit(address, kShapeName, name),
        group_detail::T_iri(address, kShapeTargetClass, def.target_class),
        group_detail::T_lit(address, kShapeDefinition, *canonical),
    };
    group_detail::ScopedActive active(identity_, author_cred_id);
    if (!W->AddTriples(triples))
      return Fail(W->last_error());
    return Ok();
  }

  // §5.3 removeShape: drop the registration of |name| (requires updateSHACL).
  // Existing instances are NOT deleted. A missing shape is a no-op success.
  bool RemoveShape(Graph* W,
                   const std::string& name,
                   const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    if (!CanUpdateShacl(W, author->did))
      return Fail("NotAllowedError");

    const std::string gid = GraphId(W);
    ResolvedShape local;
    if (!FindLocalShape(W, gid, name, &local))
      return Ok();  // nothing registered locally under this name

    const std::string& addr = local.address;
    std::vector<Triple> to_remove = {
        group_detail::T_iri(gid, kShapeHasShape, addr),
        group_detail::T_iri(addr, kShapeRdfType, kShapeTypeShape),
        group_detail::T_lit(addr, kShapeName, name),
        group_detail::T_iri(addr, kShapeTargetClass, local.def.target_class),
    };
    // The definition literal is content-addressed; remove whatever JCS form is
    // stored (re-derive it to match the stored bytes exactly).
    if (auto stored_def =
            group_detail::FirstLiteralOf(W, addr, kShapeDefinition)) {
      to_remove.push_back(group_detail::T_lit(addr, kShapeDefinition, *stored_def));
    }
    group_detail::ScopedActive active(identity_, author_cred_id);
    for (const Triple& t : to_remove) {
      bool removed = false;
      if (!W->RemoveTriple(t, &removed))
        return Fail(W->last_error());
    }
    return Ok();
  }

  // §5.4 getShapes: the shapes registered in |W| and, when |include_inherited|,
  // the accepted shapes inherited from parent graphs (§7). Local shapes shadow
  // inherited shapes of the same name (§7.3).
  std::vector<ShapeInfo> GetShapes(Graph* W, bool include_inherited = true) {
    std::vector<ShapeInfo> out;
    std::set<std::string> names;
    const std::string gid = GraphId(W);
    CollectLocalShapes(W, gid, gid, &out, &names);
    if (include_inherited && groups_) {
      std::set<std::string> visited;
      visited.insert(gid);
      CollectInherited(W, &out, &names, &visited, 0);
    }
    return out;
  }

  // §5.5 createShapeInstance: execute |shape_name|'s constructor into |W|.
  // |address| may be empty (a fresh urn:uuid is minted). |initial_values| maps
  // property names to their lexical/IRI values. Returns the instance address in
  // |*out_address|.
  bool CreateShapeInstance(Graph* W,
                           const std::string& shape_name,
                           const std::string& address,
                           const std::map<std::string, std::string>& initial_values,
                           const std::string& author_cred_id,
                           std::string* out_address) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    ResolvedShape shape;
    if (!ResolveShape(W, shape_name, &shape))  // §5.5 step 1 (local or inherited)
      return Fail("NotFoundError");
    const ShapeDefinition& def = shape.def;

    // §5.5 step 2 — mint a content-free identifier when none is supplied.
    std::string instance = address;
    if (instance.empty()) {
      instance =
          "urn:uuid:" + base::Uuid::GenerateRandomV4().AsLowercaseString();
    }

    // §5.5 step 3 — every required property without a constructor default MUST be
    // present in initial_values, else TypeError.
    for (const ShapePropertyDef& p : def.properties) {
      if (p.min_count < 1)
        continue;
      if (initial_values.count(p.name))
        continue;
      if (HasConstructorDefault(def, p))
        continue;
      return Fail("TypeError");
    }

    // §5.5 step 4 — each constructor action is a governed triple write to THIS
    // graph. Build + validate all triples first (fail atomically), then commit.
    std::vector<Triple> triples;
    for (const ShapeConstructorAction& a : def.constructor) {
      const ShapePropertyDef* ref = FindPropertyByName(def, a.object);
      std::string value;
      if (ref) {
        auto it = initial_values.find(a.object);
        if (it == initial_values.end())
          continue;  // optional property with no supplied value → no triple
        value = it->second;
      } else {
        value = a.object;  // §4.3 — a literal/IRI constant
      }
      const ShapePropertyDef* by_path = FindPropertyByPath(def, a.predicate);
      if (by_path && by_path->datatype &&
          !ValidateLexicalForDatatype(value,
                                      NormalizeDatatype(*by_path->datatype))) {
        return Fail("TypeError");  // §4.4/§10.3
      }
      // §4.3.1 addLink always produces an IRI object term (a link — e.g. the
      // §4.5 rdf://type discriminator whose object is the targetClass IRI);
      // §4.3.2/§4.3.3 target setters are typed by the referenced property.
      ObjectTerm obj = (a.kind == ShapeActionKind::kAddLink)
                           ? ObjectTerm::Iri(value)
                           : MakeObjectTerm(by_path, value);
      triples.push_back(Triple{instance, a.predicate, obj});
    }

    if (!GovernedWriteAllowed(W, triples, author->did))
      return Fail("NotAllowedError");

    group_detail::ScopedActive active(identity_, author_cred_id);
    if (!triples.empty() && !W->AddTriples(triples))
      return Fail(W->last_error());
    *out_address = instance;  // §5.5 step 5
    return Ok();
  }

  // §5.6 getShapeInstances: the addresses of every entity in |W| whose §4.5 type
  // discriminator (rdf://type) matches the shape's targetClass.
  bool GetShapeInstances(Graph* W,
                         const std::string& shape_name,
                         std::vector<std::string>* out) {
    out->clear();
    ResolvedShape shape;
    if (!ResolveShape(W, shape_name, &shape))
      return Fail("NotFoundError");
    TripleQuery q;
    q.predicate = kShapeRdfType;
    q.object = ObjectTerm::Iri(shape.def.target_class);
    std::vector<Triple> ts;
    if (!W->QueryTriples(q, &ts))
      return Fail(W->last_error());
    std::set<std::string> seen;
    for (const Triple& t : ts)
      if (seen.insert(t.subject).second)
        out->push_back(t.subject);
    return Ok();
  }

  // §5.6 getShapeInstanceData: the full property dictionary of |address|.
  bool GetShapeInstanceData(Graph* W,
                            const std::string& shape_name,
                            const std::string& address,
                            ShapeInstanceData* out) {
    out->clear();
    ResolvedShape shape;
    if (!ResolveShape(W, shape_name, &shape))
      return Fail("NotFoundError");
    for (const ShapePropertyDef& p : shape.def.properties) {
      std::vector<std::string> values;
      for (const ObjectTerm& o :
           group_detail::QueryObjects(W, address, p.path)) {
        values.push_back(o.is_literal() ? o.literal->lexical : o.iri_or_bnode);
      }
      if (!values.empty())
        (*out)[p.name] = std::move(values);
    }
    return Ok();
  }

  // §5.7 setShapeProperty: the scalar setter — remove any existing
  // (address, path, *) then add (address, path, value). Rejects a non-scalar or
  // non-writable property, and a value that fails datatype validation.
  bool SetShapeProperty(Graph* W,
                        const std::string& shape_name,
                        const std::string& address,
                        const std::string& property,
                        const std::string& value,
                        const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    ResolvedShape shape;
    if (!ResolveShape(W, shape_name, &shape))
      return Fail("NotFoundError");
    const ShapePropertyDef* p = FindPropertyByName(shape.def, property);
    if (!p)
      return Fail("NotFoundError");
    switch (SetterKindFor(*p)) {
      case SetterKind::kNone:
        return Fail("NoModificationAllowedError");  // §4.2 no setter
      case SetterKind::kCollection:
        return Fail("InvalidAccessError");  // use add/removeToShapeCollection
      case SetterKind::kScalar:
        break;
    }
    if (p->datatype &&
        !ValidateLexicalForDatatype(value, NormalizeDatatype(*p->datatype)))
      return Fail("TypeError");

    Triple add{address, p->path, MakeObjectTerm(p, value)};
    if (!GovernedWriteAllowed(W, {add}, author->did))
      return Fail("NotAllowedError");

    group_detail::ScopedActive active(identity_, author_cred_id);
    // Remove any existing values for this scalar property first (§4.4).
    std::vector<Triple> existing;
    TripleQuery q;
    q.subject = address;
    q.predicate = p->path;
    if (W->QueryTriples(q, &existing)) {
      for (const Triple& t : existing) {
        bool removed = false;
        if (!W->RemoveTriple(t, &removed))
          return Fail(W->last_error());
      }
    }
    if (!W->AddTriple(add))
      return Fail(W->last_error());
    return Ok();
  }

  // §5.7 addToShapeCollection: add (address, path, value) for a collection
  // property.
  bool AddToShapeCollection(Graph* W,
                            const std::string& shape_name,
                            const std::string& address,
                            const std::string& collection,
                            const std::string& value,
                            const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    ResolvedShape shape;
    if (!ResolveShape(W, shape_name, &shape))
      return Fail("NotFoundError");
    const ShapePropertyDef* p = FindPropertyByName(shape.def, collection);
    if (!p)
      return Fail("NotFoundError");
    if (SetterKindFor(*p) != SetterKind::kCollection)
      return Fail("InvalidAccessError");
    if (p->datatype &&
        !ValidateLexicalForDatatype(value, NormalizeDatatype(*p->datatype)))
      return Fail("TypeError");

    Triple add{address, p->path, MakeObjectTerm(p, value)};
    if (!GovernedWriteAllowed(W, {add}, author->did))
      return Fail("NotAllowedError");
    group_detail::ScopedActive active(identity_, author_cred_id);
    if (!W->AddTriple(add))
      return Fail(W->last_error());
    return Ok();
  }

  // §5.7 removeFromShapeCollection: remove (address, path, value).
  bool RemoveFromShapeCollection(Graph* W,
                                 const std::string& shape_name,
                                 const std::string& address,
                                 const std::string& collection,
                                 const std::string& value,
                                 const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    ResolvedShape shape;
    if (!ResolveShape(W, shape_name, &shape))
      return Fail("NotFoundError");
    const ShapePropertyDef* p = FindPropertyByName(shape.def, collection);
    if (!p)
      return Fail("NotFoundError");
    if (SetterKindFor(*p) != SetterKind::kCollection)
      return Fail("InvalidAccessError");

    group_detail::ScopedActive active(identity_, author_cred_id);
    Triple t{address, p->path, MakeObjectTerm(p, value)};
    bool removed = false;
    if (!W->RemoveTriple(t, &removed))
      return Fail(W->last_error());
    return Ok();
  }

 private:
  // A shape resolved to its definition, content address, and source graph.
  struct ResolvedShape {
    ShapeDefinition def;
    std::string address;
    std::string source_graph_id;
    Graph* source_graph = nullptr;
  };

  bool Ok() {
    last_error_.clear();
    return true;
  }
  bool Fail(const std::string& e) {
    last_error_ = e;
    return false;
  }

  // The stable identifier the shape triples are subject-keyed on (§6.2/§6.4):
  // the graph's DID when it has one, else its urn:graph id.
  static std::string GraphId(Graph* g) { return g->did().value_or(g->id()); }

  bool CanUpdateShacl(Graph* W, const std::string& author_did) {
    if (!governance_)
      return true;
    return governance_->CanPerformAction(W, kActionUpdateSHACL, author_did)
        .allowed;
  }

  // §5.5/§5.7 — every candidate write must pass graph governance.
  bool GovernedWriteAllowed(Graph* W,
                            const std::vector<Triple>& triples,
                            const std::string& author_did) {
    if (!governance_)
      return true;
    for (const Triple& t : triples) {
      if (!governance_->CanAddTriple(W, t, author_did).allowed)
        return false;
    }
    return true;
  }

  // The object term for |value| under the property (if any) that owns the
  // predicate: a "URI" datatype selects an IRI term; any other datatype (or a
  // property whose path matches) selects a typed literal; an unknown predicate
  // defaults to a plain xsd:string literal.
  static ObjectTerm MakeObjectTerm(const ShapePropertyDef* prop,
                                   const std::string& value) {
    if (prop && prop->datatype) {
      const std::string norm = NormalizeDatatype(*prop->datatype);
      if (IsUriDatatype(norm))
        return ObjectTerm::Iri(value);
      LiteralValue lv;
      lv.lexical = value;
      lv.datatype = norm.empty() ? std::string(kXsdString) : norm;
      return ObjectTerm::Literal(lv);
    }
    LiteralValue lv;
    lv.lexical = value;
    lv.datatype = kXsdString;
    return ObjectTerm::Literal(lv);
  }

  // True iff a constructor action supplies |p| a literal/IRI constant (a default,
  // e.g. the §4.5 type_flag set to the targetClass) rather than an initialValues
  // reference — such a property is "defaulted" for the §5.5-step-3 required check.
  static bool HasConstructorDefault(const ShapeDefinition& def,
                                    const ShapePropertyDef& p) {
    for (const ShapeConstructorAction& a : def.constructor) {
      if (a.predicate != p.path)
        continue;
      // A constant object (not the name of any property) is a default value.
      if (!FindPropertyByName(def, a.object))
        return true;
    }
    return false;
  }

  // Load the shape stored at |addr| in |g|: its registration name and parsed
  // definition. False if the address is not a well-formed stored shape.
  static bool LoadShapeAt(Graph* g,
                          const std::string& addr,
                          std::string* name,
                          ShapeDefinition* def) {
    auto nm = group_detail::FirstLiteralOf(g, addr, kShapeName);
    auto raw = group_detail::FirstLiteralOf(g, addr, kShapeDefinition);
    if (!nm || !raw)
      return false;
    std::string err;
    if (!ParseShapeDefinition(*raw, def, &err))
      return false;
    *name = *nm;
    return true;
  }

  // Find a shape registered LOCALLY in |g| (keyed by |gid|) under |name|.
  static bool FindLocalShape(Graph* g,
                             const std::string& gid,
                             const std::string& name,
                             ResolvedShape* out) {
    for (const ObjectTerm& o :
         group_detail::QueryObjects(g, gid, kShapeHasShape)) {
      if (o.is_literal())
        continue;
      const std::string& addr = o.iri_or_bnode;
      std::string nm;
      ShapeDefinition def;
      if (!LoadShapeAt(g, addr, &nm, &def) || nm != name)
        continue;
      out->def = std::move(def);
      out->address = addr;
      out->source_graph = g;
      out->source_graph_id = gid;
      return true;
    }
    return false;
  }

  // §7.2 — resolve |name| to a shape, local first then depth-first up the
  // accepted context://participates_in chain. First match wins.
  bool ResolveShape(Graph* W, const std::string& name, ResolvedShape* out) {
    std::set<std::string> visited;
    return ResolveShapeRec(W, name, out, &visited, 0);
  }

  bool ResolveShapeRec(Graph* W,
                       const std::string& name,
                       ResolvedShape* out,
                       std::set<std::string>* visited,
                       int depth) {
    const std::string gid = GraphId(W);
    if (!visited->insert(gid).second)
      return false;  // cycle guard
    if (FindLocalShape(W, gid, name, out))
      return true;
    if (!groups_ || depth >= 16)
      return false;
    for (const ObjectTerm& o :
         group_detail::QueryObjects(W, gid, kContextParticipatesIn)) {
      if (o.is_literal())
        continue;
      Graph* parent = groups_->LookupHost(o.iri_or_bnode);
      if (!parent)
        continue;
      if (!ParentAcceptsChild(parent, W))  // §10.5 tamper defence
        continue;
      if (ResolveShapeRec(parent, name, out, visited, depth + 1))
        return true;
    }
    return false;
  }

  // §10.5 — the parent's governance must accept the child's participation: a
  // context://accepts_participation link from the parent to the child, whose
  // reifier author is a capabilityDelegation delegate of the parent. Checked
  // against both the child's stable id (DID) and its current IRI.
  bool ParentAcceptsChild(Graph* parent, Graph* child) {
    const std::string parent_id = GraphId(parent);
    DidDocument doc;
    group_detail::ProjectDidDocument(parent, parent_id, &doc);
    if (doc.capability_delegation.empty())
      return false;

    std::vector<std::string> child_keys;
    child_keys.push_back(GraphId(child));
    std::string child_iri;
    if (child->GetIri(&child_iri) && child_iri != child_keys.front())
      child_keys.push_back(child_iri);

    for (const std::string& child_key : child_keys) {
      Triple accept =
          group_detail::T_iri(parent_id, kContextAcceptsParticipation, child_key);
      std::vector<Reifier> reifs;
      if (!parent->Provenance(accept, &reifs))
        continue;
      for (const Reifier& r : reifs) {
        auto akey = ParseAnyDidEd25519(r.author);
        if (!akey)
          continue;
        for (const std::string& mid : doc.capability_delegation) {
          auto key = DecodePublicKeyMultibase(cap_detail::Fragment(mid));
          if (key && *key == *akey)
            return true;
        }
      }
    }
    return false;
  }

  static ShapeInfo ToInfo(const std::string& name,
                          const ShapeDefinition& def,
                          const std::string& addr,
                          const std::string& source_graph_id) {
    ShapeInfo info;
    info.name = name;
    info.target_class = def.target_class;
    info.definition_address = addr;
    info.source_graph_did = source_graph_id;
    for (const ShapePropertyDef& p : def.properties) {
      ShapePropertyInfo pi;
      pi.name = p.name;
      pi.path = p.path;
      pi.datatype = p.datatype;
      pi.min_count = p.min_count;
      pi.max_count = p.max_count;
      pi.writable = p.writable;
      pi.read_only = p.read_only;
      info.properties.push_back(std::move(pi));
    }
    return info;
  }

  // Append |g|'s locally-registered shapes to |out|, recording their names in
  // |names| so inherited shapes of the same name are shadowed (§7.3).
  void CollectLocalShapes(Graph* g,
                          const std::string& gid,
                          const std::string& source_graph_id,
                          std::vector<ShapeInfo>* out,
                          std::set<std::string>* names) {
    for (const ObjectTerm& o :
         group_detail::QueryObjects(g, gid, kShapeHasShape)) {
      if (o.is_literal())
        continue;
      const std::string& addr = o.iri_or_bnode;
      std::string name;
      ShapeDefinition def;
      if (!LoadShapeAt(g, addr, &name, &def))
        continue;
      if (!names->insert(name).second)
        continue;  // a nearer graph already owns this name
      out->push_back(ToInfo(name, def, addr, source_graph_id));
    }
  }

  void CollectInherited(Graph* W,
                        std::vector<ShapeInfo>* out,
                        std::set<std::string>* names,
                        std::set<std::string>* visited,
                        int depth) {
    if (depth >= 16)
      return;
    const std::string gid = GraphId(W);
    for (const ObjectTerm& o :
         group_detail::QueryObjects(W, gid, kContextParticipatesIn)) {
      if (o.is_literal())
        continue;
      Graph* parent = groups_->LookupHost(o.iri_or_bnode);
      if (!parent)
        continue;
      const std::string pid = GraphId(parent);
      if (!visited->insert(pid).second)
        continue;
      if (!ParentAcceptsChild(parent, W))  // §10.5
        continue;
      CollectLocalShapes(parent, pid, pid, out, names);
      CollectInherited(parent, out, names, visited, depth + 1);
    }
  }

  DIDKeyProvider* identity_;
  GovernanceEngine* governance_;  // may be null (open graphs)
  GroupManager* groups_;          // may be null (local shapes only)
  std::string last_error_;
};

}  // namespace living_web

#endif  // LIVING_WEB_SHAPE_PROVIDER_H_
