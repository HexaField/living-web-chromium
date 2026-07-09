// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// ShapeService — the browser-process port of the §5 `Graph` shape API of Spec 07
// (Dynamic Graph Shape Validation). A faithful C++ port of living_web::
// ShapeService (standalone/shape_provider.h) onto the browser cores content::
// GraphBackend (the Spec 02 host graph a shape is registered into), content::
// DIDKeyProvider (the Spec 01 identity whose key authors the registration/
// instance writes), content::GovernanceBackend (the Spec 04 updateSHACL gate and
// the per-write §5.5/§5.7 governance), and content::GraphBackendManager (which
// resolves context://participates_in parents for §7 inheritance).
//
// The two ports share the Chromium-independent shape-definition core
// (content/browser/shapes/shape_definition.{h,cc} — §4 grammar parsing, §6.3 JCS
// content-addressing, §4.4/§10.3 datatype validation, and the §4.6/§7.1
// narrowing rule) verbatim, so the standalone conformance harness and the browser
// never diverge on the shape parsed, the content address derived, the value
// validated, or the narrowing decision.
//
// What it enforces, normatively (identical to the standalone provider):
//   * §5.2/§10.4 authorisation — every registration/removal requires the
//     `updateSHACL` extension capability (GovernanceBackend::CanPerformAction);
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
//     (minCount >= 1) without a constructor-literal default is supplied
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
// harness hashes with crypto::SHA256HashString (OpenSSL); this backend hashes
// with //crypto's crypto::SHA256HashString. The shared core never hashes — it
// canonicalises with CanonicalizeShapeJson() and formats the raw digest with
// FormatShapeAddress().
//
// ShapeService is a per-realm object (like GovernanceBackend, it operates on any
// GraphBackend* W passed to each call); PersonalGraphManager owns one and shares
// it with every PersonalGraphHost so the §11 renderer surface runs against a
// single identity/governance/graph view. Parent resolution for §7 inheritance
// uses GraphBackendManager::LookupHost (the standalone provider uses
// GroupManager::LookupHost; here every graph — group or not — is owned by the
// per-realm GraphBackendManager, which is the authority that resolves a
// participates_in target DID/IRI to a live backend).

#ifndef CONTENT_BROWSER_SHAPES_SHAPE_SERVICE_H_
#define CONTENT_BROWSER_SHAPES_SHAPE_SERVICE_H_

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_graph.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/shapes/shape_definition.h"

namespace content {

// ---- §5.1 API value types (mirror the ShapeInfo / PropertyInfo IDL dicts) ----

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

// ---- the shape service ------------------------------------------------------

// Implements the Spec 07 §5 API over a set of graphs. Every method takes the
// target GraphBackend* as its first argument (the browser binds these onto the
// `Graph` interface via PersonalGraphHost; the harness calls them directly).
// |governance| gates the `updateSHACL` extension action and the per-write
// governance of §5.5/§5.7; it may be null (treated as open). |graphs| resolves
// context://participates_in parents for §7 inheritance and may be null (local
// shapes only).
class ShapeService {
 public:
  ShapeService(DIDKeyProvider* identity,
               GovernanceBackend* governance,
               GraphBackendManager* graphs)
      : identity_(identity), governance_(governance), graphs_(graphs) {}

  ShapeService(const ShapeService&) = delete;
  ShapeService& operator=(const ShapeService&) = delete;

  const std::string& last_error() const { return last_error_; }

  // §5.2 addShape: register |shape_json| under |name| into |W|, authored by the
  // credential |author_cred_id|. Returns false + last_error() on any rejection.
  bool AddShape(GraphBackend* W,
                const std::string& name,
                const std::string& shape_json,
                const std::string& author_cred_id);

  // §5.3 removeShape: drop the registration of |name| (requires updateSHACL).
  // Existing instances are NOT deleted. A missing shape is a no-op success.
  bool RemoveShape(GraphBackend* W,
                   const std::string& name,
                   const std::string& author_cred_id);

  // §5.4 getShapes: the shapes registered in |W| and, when |include_inherited|,
  // the accepted shapes inherited from parent graphs (§7). Local shapes shadow
  // inherited shapes of the same name (§7.3).
  std::vector<ShapeInfo> GetShapes(GraphBackend* W,
                                   bool include_inherited = true);

  // §5.5 createShapeInstance: execute |shape_name|'s constructor into |W|.
  // |address| may be empty (a fresh urn:uuid is minted). |initial_values| maps
  // property names to their lexical/IRI values. Returns the instance address in
  // |*out_address|.
  bool CreateShapeInstance(
      GraphBackend* W,
      const std::string& shape_name,
      const std::string& address,
      const std::map<std::string, std::string>& initial_values,
      const std::string& author_cred_id,
      std::string* out_address);

  // §5.6 getShapeInstances: the addresses of every entity in |W| whose §4.5 type
  // discriminator (rdf://type) matches the shape's targetClass.
  bool GetShapeInstances(GraphBackend* W,
                         const std::string& shape_name,
                         std::vector<std::string>* out);

  // §5.6 getShapeInstanceData: the full property dictionary of |address|.
  bool GetShapeInstanceData(GraphBackend* W,
                            const std::string& shape_name,
                            const std::string& address,
                            ShapeInstanceData* out);

  // §5.7 setShapeProperty: the scalar setter — remove any existing
  // (address, path, *) then add (address, path, value). Rejects a non-scalar or
  // non-writable property, and a value that fails datatype validation.
  bool SetShapeProperty(GraphBackend* W,
                        const std::string& shape_name,
                        const std::string& address,
                        const std::string& property,
                        const std::string& value,
                        const std::string& author_cred_id);

  // §5.7 addToShapeCollection: add (address, path, value) for a collection
  // property.
  bool AddToShapeCollection(GraphBackend* W,
                            const std::string& shape_name,
                            const std::string& address,
                            const std::string& collection,
                            const std::string& value,
                            const std::string& author_cred_id);

  // §5.7 removeFromShapeCollection: remove (address, path, value).
  bool RemoveFromShapeCollection(GraphBackend* W,
                                 const std::string& shape_name,
                                 const std::string& address,
                                 const std::string& collection,
                                 const std::string& value,
                                 const std::string& author_cred_id);

 private:
  // A shape resolved to its definition, content address, and source graph.
  struct ResolvedShape {
    living_web::ShapeDefinition def;
    std::string address;
    std::string source_graph_id;
    raw_ptr<GraphBackend> source_graph = nullptr;
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
  static std::string GraphId(GraphBackend* g) {
    return g->did().value_or(g->id());
  }

  bool CanUpdateShacl(GraphBackend* W, const std::string& author_did);

  // §5.5/§5.7 — every candidate write must pass graph governance.
  bool GovernedWriteAllowed(GraphBackend* W,
                            const std::vector<living_web::Triple>& triples,
                            const std::string& author_did);

  // The object term for |value| under the property (if any) that owns the
  // predicate: a "URI" datatype selects an IRI term; any other datatype (or a
  // property whose path matches) selects a typed literal; an unknown predicate
  // defaults to a plain xsd:string literal.
  static living_web::ObjectTerm MakeObjectTerm(
      const living_web::ShapePropertyDef* prop,
      const std::string& value);

  // True iff a constructor action supplies |p| a literal/IRI constant (a default,
  // e.g. the §4.5 type_flag set to the targetClass) rather than an initialValues
  // reference — such a property is "defaulted" for the §5.5-step-3 required check.
  static bool HasConstructorDefault(const living_web::ShapeDefinition& def,
                                    const living_web::ShapePropertyDef& p);

  // Load the shape stored at |addr| in |g|: its registration name and parsed
  // definition. False if the address is not a well-formed stored shape.
  static bool LoadShapeAt(GraphBackend* g,
                          const std::string& addr,
                          std::string* name,
                          living_web::ShapeDefinition* def);

  // Find a shape registered LOCALLY in |g| (keyed by |gid|) under |name|.
  static bool FindLocalShape(GraphBackend* g,
                             const std::string& gid,
                             const std::string& name,
                             ResolvedShape* out);

  // §7.2 — resolve |name| to a shape, local first then depth-first up the
  // accepted context://participates_in chain. First match wins.
  bool ResolveShape(GraphBackend* W,
                    const std::string& name,
                    ResolvedShape* out);

  bool ResolveShapeRec(GraphBackend* W,
                       const std::string& name,
                       ResolvedShape* out,
                       std::set<std::string>* visited,
                       int depth);

  // §10.5 — the parent's governance must accept the child's participation: a
  // context://accepts_participation link from the parent to the child, whose
  // reifier author is a capabilityDelegation delegate of the parent. Checked
  // against both the child's stable id (DID) and its current IRI.
  bool ParentAcceptsChild(GraphBackend* parent, GraphBackend* child);

  static ShapeInfo ToInfo(const std::string& name,
                          const living_web::ShapeDefinition& def,
                          const std::string& addr,
                          const std::string& source_graph_id);

  // Append |g|'s locally-registered shapes to |out|, recording their names in
  // |names| so inherited shapes of the same name are shadowed (§7.3).
  void CollectLocalShapes(GraphBackend* g,
                          const std::string& gid,
                          const std::string& source_graph_id,
                          std::vector<ShapeInfo>* out,
                          std::set<std::string>* names);

  void CollectInherited(GraphBackend* W,
                        std::vector<ShapeInfo>* out,
                        std::set<std::string>* names,
                        std::set<std::string>* visited,
                        int depth);

  raw_ptr<DIDKeyProvider> identity_;      // Not owned.
  raw_ptr<GovernanceBackend> governance_;  // May be null (open graphs).
  raw_ptr<GraphBackendManager> graphs_;    // May be null (local shapes only).
  std::string last_error_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_SHAPES_SHAPE_SERVICE_H_
