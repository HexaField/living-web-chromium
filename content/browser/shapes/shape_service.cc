// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/shapes/shape_service.h"

#include <utility>

#include "base/uuid.h"
#include "crypto/sha2.h"

namespace content {

using living_web::LiteralValue;
using living_web::ObjectTerm;
using living_web::ShapeConstructorAction;
using living_web::ShapeDefinition;
using living_web::ShapePropertyDef;
using living_web::Triple;

// §5.2 addShape.
bool ShapeService::AddShape(GraphBackend* W,
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
  if (!living_web::ParseShapeDefinition(shape_json, &def, &perr))
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
    if (!living_web::ShapeNarrows(parent.def, def, &reason))
      return Fail("ConstraintError");
  } else {
    // §7.1 — overriding an inherited shape of the same name MUST narrow it.
    ResolvedShape inherited;
    if (ResolveShape(W, name, &inherited)) {
      std::string reason;
      if (!living_web::ShapeNarrows(inherited.def, def, &reason))
        return Fail("ConstraintError");
    }
  }

  // §6.3 — content address = "sha256:" + hex(SHA-256(JCS(shapeJson))).
  auto canonical = living_web::CanonicalizeShapeJson(shape_json);
  if (!canonical)
    return Fail("SyntaxError");
  const std::string address =
      living_web::FormatShapeAddress(crypto::SHA256HashString(*canonical));

  // §6.4 — the stored triple shape, authored by the caller.
  std::vector<Triple> triples = {
      group_detail::T_iri(gid, living_web::kShapeHasShape, address),
      group_detail::T_iri(address, living_web::kShapeRdfType,
                          living_web::kShapeTypeShape),
      group_detail::T_lit(address, living_web::kShapeName, name),
      group_detail::T_iri(address, living_web::kShapeTargetClass,
                          def.target_class),
      group_detail::T_lit(address, living_web::kShapeDefinition, *canonical),
  };
  group_detail::ScopedActive active(identity_, author_cred_id);
  if (!W->AddTriples(triples))
    return Fail(W->last_error());
  return Ok();
}

// §5.3 removeShape.
bool ShapeService::RemoveShape(GraphBackend* W,
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
      group_detail::T_iri(gid, living_web::kShapeHasShape, addr),
      group_detail::T_iri(addr, living_web::kShapeRdfType,
                          living_web::kShapeTypeShape),
      group_detail::T_lit(addr, living_web::kShapeName, name),
      group_detail::T_iri(addr, living_web::kShapeTargetClass,
                          local.def.target_class),
  };
  // The definition literal is content-addressed; remove whatever JCS form is
  // stored (re-derive it to match the stored bytes exactly).
  if (auto stored_def = group_detail::FirstLiteralOf(
          W, addr, living_web::kShapeDefinition)) {
    to_remove.push_back(group_detail::T_lit(
        addr, living_web::kShapeDefinition, *stored_def));
  }
  group_detail::ScopedActive active(identity_, author_cred_id);
  for (const Triple& t : to_remove) {
    bool removed = false;
    if (!W->RemoveTriple(t, &removed))
      return Fail(W->last_error());
  }
  return Ok();
}

// §5.4 getShapes.
std::vector<ShapeInfo> ShapeService::GetShapes(GraphBackend* W,
                                               bool include_inherited) {
  std::vector<ShapeInfo> out;
  std::set<std::string> names;
  const std::string gid = GraphId(W);
  CollectLocalShapes(W, gid, gid, &out, &names);
  if (include_inherited && graphs_) {
    std::set<std::string> visited;
    visited.insert(gid);
    CollectInherited(W, &out, &names, &visited, 0);
  }
  return out;
}

// §5.5 createShapeInstance.
bool ShapeService::CreateShapeInstance(
    GraphBackend* W,
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
    const ShapePropertyDef* ref = living_web::FindPropertyByName(def, a.object);
    std::string value;
    if (ref) {
      auto it = initial_values.find(a.object);
      if (it == initial_values.end())
        continue;  // optional property with no supplied value → no triple
      value = it->second;
    } else {
      value = a.object;  // §4.3 — a literal/IRI constant
    }
    const ShapePropertyDef* by_path =
        living_web::FindPropertyByPath(def, a.predicate);
    if (by_path && by_path->datatype &&
        !living_web::ValidateLexicalForDatatype(
            value, living_web::NormalizeDatatype(*by_path->datatype))) {
      return Fail("TypeError");  // §4.4/§10.3
    }
    // §4.3.1 addLink always produces an IRI object term (a link — e.g. the
    // §4.5 rdf://type discriminator whose object is the targetClass IRI);
    // §4.3.2/§4.3.3 target setters are typed by the referenced property.
    ObjectTerm obj = (a.kind == living_web::ShapeActionKind::kAddLink)
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

// §5.6 getShapeInstances.
bool ShapeService::GetShapeInstances(GraphBackend* W,
                                     const std::string& shape_name,
                                     std::vector<std::string>* out) {
  out->clear();
  ResolvedShape shape;
  if (!ResolveShape(W, shape_name, &shape))
    return Fail("NotFoundError");
  TripleQuery q;
  q.predicate = living_web::kShapeRdfType;
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

// §5.6 getShapeInstanceData.
bool ShapeService::GetShapeInstanceData(GraphBackend* W,
                                        const std::string& shape_name,
                                        const std::string& address,
                                        ShapeInstanceData* out) {
  out->clear();
  ResolvedShape shape;
  if (!ResolveShape(W, shape_name, &shape))
    return Fail("NotFoundError");
  for (const ShapePropertyDef& p : shape.def.properties) {
    std::vector<std::string> values;
    for (const ObjectTerm& o : group_detail::QueryObjects(W, address, p.path)) {
      values.push_back(o.is_literal() ? o.literal->lexical : o.iri_or_bnode);
    }
    if (!values.empty())
      (*out)[p.name] = std::move(values);
  }
  return Ok();
}

// §5.7 setShapeProperty.
bool ShapeService::SetShapeProperty(GraphBackend* W,
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
  const ShapePropertyDef* p =
      living_web::FindPropertyByName(shape.def, property);
  if (!p)
    return Fail("NotFoundError");
  switch (living_web::SetterKindFor(*p)) {
    case living_web::SetterKind::kNone:
      return Fail("NoModificationAllowedError");  // §4.2 no setter
    case living_web::SetterKind::kCollection:
      return Fail("InvalidAccessError");  // use add/removeToShapeCollection
    case living_web::SetterKind::kScalar:
      break;
  }
  if (p->datatype &&
      !living_web::ValidateLexicalForDatatype(
          value, living_web::NormalizeDatatype(*p->datatype)))
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

// §5.7 addToShapeCollection.
bool ShapeService::AddToShapeCollection(GraphBackend* W,
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
  const ShapePropertyDef* p =
      living_web::FindPropertyByName(shape.def, collection);
  if (!p)
    return Fail("NotFoundError");
  if (living_web::SetterKindFor(*p) != living_web::SetterKind::kCollection)
    return Fail("InvalidAccessError");
  if (p->datatype &&
      !living_web::ValidateLexicalForDatatype(
          value, living_web::NormalizeDatatype(*p->datatype)))
    return Fail("TypeError");

  Triple add{address, p->path, MakeObjectTerm(p, value)};
  if (!GovernedWriteAllowed(W, {add}, author->did))
    return Fail("NotAllowedError");
  group_detail::ScopedActive active(identity_, author_cred_id);
  if (!W->AddTriple(add))
    return Fail(W->last_error());
  return Ok();
}

// §5.7 removeFromShapeCollection.
bool ShapeService::RemoveFromShapeCollection(
    GraphBackend* W,
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
  const ShapePropertyDef* p =
      living_web::FindPropertyByName(shape.def, collection);
  if (!p)
    return Fail("NotFoundError");
  if (living_web::SetterKindFor(*p) != living_web::SetterKind::kCollection)
    return Fail("InvalidAccessError");

  group_detail::ScopedActive active(identity_, author_cred_id);
  Triple t{address, p->path, MakeObjectTerm(p, value)};
  bool removed = false;
  if (!W->RemoveTriple(t, &removed))
    return Fail(W->last_error());
  return Ok();
}

// Spec 08 §7.8 — shape-caveat conformance. The production binding wired into
// ConstraintVocabOptions::shape_conforms; the standalone harness injects an
// equivalent lambda. Resolves the shape by its §7.2 registration name (local
// first, then up the accepted participation chain), then checks the candidate
// triple's subject against the shape's §4.2 property definitions: §4.3
// cardinality (minCount/maxCount) and §4.4 datatype, evaluated over the
// subject's currently-stored objects PLUS the advisory candidate object (the
// write is not yet committed). Fails closed on an unresolvable shape (§9.6).
bool ShapeService::Conforms(GraphBackend* W,
                            const std::string& shape_iri,
                            const living_web::Triple& triple) {
  ResolvedShape shape;
  if (!ResolveShape(W, shape_iri, &shape))
    return false;  // §9.6 unresolvable shape → fail-closed
  for (const ShapePropertyDef& p : shape.def.properties) {
    std::vector<std::string> values;
    for (const ObjectTerm& o :
         group_detail::QueryObjects(W, triple.subject, p.path))
      values.push_back(o.is_literal() ? o.literal->lexical : o.iri_or_bnode);
    if (triple.predicate == p.path) {
      const ObjectTerm& o = triple.object;
      values.push_back(o.is_literal() ? o.literal->lexical : o.iri_or_bnode);
    }
    if (values.size() < p.min_count)
      return false;  // §4.3 minCount
    if (p.max_count && values.size() > *p.max_count)
      return false;  // §4.3 maxCount
    if (p.datatype) {
      const std::string norm = living_web::NormalizeDatatype(*p.datatype);
      for (const std::string& v : values)
        if (!living_web::ValidateLexicalForDatatype(v, norm))
          return false;  // §4.4 datatype
    }
  }
  return true;
}

// ---- private helpers --------------------------------------------------------

bool ShapeService::CanUpdateShacl(GraphBackend* W,
                                  const std::string& author_did) {
  if (!governance_)
    return true;
  return governance_
      ->CanPerformAction(W, living_web::kActionUpdateSHACL, author_did)
      .allowed;
}

bool ShapeService::GovernedWriteAllowed(GraphBackend* W,
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

// static
ObjectTerm ShapeService::MakeObjectTerm(const ShapePropertyDef* prop,
                                        const std::string& value) {
  if (prop && prop->datatype) {
    const std::string norm = living_web::NormalizeDatatype(*prop->datatype);
    if (living_web::IsUriDatatype(norm))
      return ObjectTerm::Iri(value);
    LiteralValue lv;
    lv.lexical = value;
    lv.datatype = norm.empty() ? std::string(living_web::kXsdString) : norm;
    return ObjectTerm::Literal(lv);
  }
  LiteralValue lv;
  lv.lexical = value;
  lv.datatype = living_web::kXsdString;
  return ObjectTerm::Literal(lv);
}

// static
bool ShapeService::HasConstructorDefault(const ShapeDefinition& def,
                                         const ShapePropertyDef& p) {
  for (const ShapeConstructorAction& a : def.constructor) {
    if (a.predicate != p.path)
      continue;
    // A constant object (not the name of any property) is a default value.
    if (!living_web::FindPropertyByName(def, a.object))
      return true;
  }
  return false;
}

// static
bool ShapeService::LoadShapeAt(GraphBackend* g,
                               const std::string& addr,
                               std::string* name,
                               ShapeDefinition* def) {
  auto nm = group_detail::FirstLiteralOf(g, addr, living_web::kShapeName);
  auto raw = group_detail::FirstLiteralOf(g, addr, living_web::kShapeDefinition);
  if (!nm || !raw)
    return false;
  std::string err;
  if (!living_web::ParseShapeDefinition(*raw, def, &err))
    return false;
  *name = *nm;
  return true;
}

// static
bool ShapeService::FindLocalShape(GraphBackend* g,
                                  const std::string& gid,
                                  const std::string& name,
                                  ResolvedShape* out) {
  for (const ObjectTerm& o :
       group_detail::QueryObjects(g, gid, living_web::kShapeHasShape)) {
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

bool ShapeService::ResolveShape(GraphBackend* W,
                                const std::string& name,
                                ResolvedShape* out) {
  std::set<std::string> visited;
  return ResolveShapeRec(W, name, out, &visited, 0);
}

bool ShapeService::ResolveShapeRec(GraphBackend* W,
                                   const std::string& name,
                                   ResolvedShape* out,
                                   std::set<std::string>* visited,
                                   int depth) {
  const std::string gid = GraphId(W);
  if (!visited->insert(gid).second)
    return false;  // cycle guard
  if (FindLocalShape(W, gid, name, out))
    return true;
  if (!graphs_ || depth >= 16)
    return false;
  for (const ObjectTerm& o :
       group_detail::QueryObjects(W, gid, living_web::kContextParticipatesIn)) {
    if (o.is_literal())
      continue;
    GraphBackend* parent = graphs_->LookupHost(o.iri_or_bnode);
    if (!parent)
      continue;
    if (!ParentAcceptsChild(parent, W))  // §10.5 tamper defence
      continue;
    if (ResolveShapeRec(parent, name, out, visited, depth + 1))
      return true;
  }
  return false;
}

bool ShapeService::ParentAcceptsChild(GraphBackend* parent,
                                      GraphBackend* child) {
  const std::string parent_id = GraphId(parent);
  living_web::DidDocument doc;
  group_detail::ProjectDidDocument(parent, parent_id, &doc);
  if (doc.capability_delegation.empty())
    return false;

  std::vector<std::string> child_keys;
  child_keys.push_back(GraphId(child));
  std::string child_iri;
  if (child->GetIri(&child_iri) && child_iri != child_keys.front())
    child_keys.push_back(child_iri);

  for (const std::string& child_key : child_keys) {
    Triple accept = group_detail::T_iri(
        parent_id, living_web::kContextAcceptsParticipation, child_key);
    std::vector<living_web::Reifier> reifs;
    if (!parent->Provenance(accept, &reifs))
      continue;
    for (const living_web::Reifier& r : reifs) {
      auto akey = living_web::ParseAnyDidEd25519(r.author);
      if (!akey)
        continue;
      for (const std::string& mid : doc.capability_delegation) {
        auto key =
            living_web::DecodePublicKeyMultibase(gov_detail::Fragment(mid));
        if (key && *key == *akey)
          return true;
      }
    }
  }
  return false;
}

// static
ShapeInfo ShapeService::ToInfo(const std::string& name,
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

void ShapeService::CollectLocalShapes(GraphBackend* g,
                                      const std::string& gid,
                                      const std::string& source_graph_id,
                                      std::vector<ShapeInfo>* out,
                                      std::set<std::string>* names) {
  for (const ObjectTerm& o :
       group_detail::QueryObjects(g, gid, living_web::kShapeHasShape)) {
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

void ShapeService::CollectInherited(GraphBackend* W,
                                    std::vector<ShapeInfo>* out,
                                    std::set<std::string>* names,
                                    std::set<std::string>* visited,
                                    int depth) {
  if (depth >= 16)
    return;
  const std::string gid = GraphId(W);
  for (const ObjectTerm& o :
       group_detail::QueryObjects(W, gid, living_web::kContextParticipatesIn)) {
    if (o.is_literal())
      continue;
    GraphBackend* parent = graphs_->LookupHost(o.iri_or_bnode);
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

}  // namespace content
