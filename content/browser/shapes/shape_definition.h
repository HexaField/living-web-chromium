// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Dynamic Graph Shape Validation (Spec 07) — the shape-definition core: JSON
// grammar parsing, JCS content-addressing, datatype vocabulary + lexical
// validation, and the extension-narrowing rule.
//
// The Chromium-independent core (namespace `living_web`, pure-std, no Chromium
// and no standalone-shim dependencies) shared byte-for-byte by the browser shape
// service (content/browser/shapes/shape_service.*) and the standalone harness
// (standalone/shape_provider.h). It defines:
//
//   * the §4 shape-definition JSON grammar parsed into a structured
//     ShapeDefinition (targetClass, properties[], constructor[], extends), with
//     the §4.2 property-name grammar and setter-generation rules;
//   * the §6.3/§6.4 content address `"sha256:" + hex(SHA-256(JCS(shapeJson)))`
//     and its well-formedness check;
//   * the §4.2 datatype vocabulary (XSD URIs / "URI"), datatype normalisation,
//     and the §4.4/§10.3 lexical-value validation performed before every write;
//   * the §4.6 / §7.1 extension-narrowing rule (a child shape MUST be a strict
//     refinement of the shape it overrides).
//
// Like module_manifest.cc, module_capabilities.cc, graph_diff.cc and zcap.cc,
// this translation unit performs no hashing itself: the SHA-256 primitive
// resolves to a different header in the two build worlds (standalone/crypto_sha2.h
// vs //crypto), so the caller canonicalises with CanonicalizeShapeJson(), hashes
// the result, and hands the raw digest to FormatShapeAddress(). JCS
// canonicalisation IS shared (content/browser/did/jcs.*), so CanonicalizeShapeJson
// lives here and both worlds derive byte-identical content addresses. The JSON
// grammar is scanned by a small self-contained reader (mirroring
// module_manifest.cc, with no dependency on standalone/json_parser.h) so the same
// bytes parse in both worlds.

#ifndef CONTENT_BROWSER_SHAPES_SHAPE_DEFINITION_H_
#define CONTENT_BROWSER_SHAPES_SHAPE_DEFINITION_H_

#include <optional>
#include <string>
#include <vector>

namespace living_web {

// -- §4.5 / §6 shape vocabulary -------------------------------------------
//
// Scheme-shorthand IRIs used verbatim by the spec. These are NOT the w3.org
// RDF/XSD IRIs: `kShapeRdfType` is the spec's `rdf://type` discriminator
// predicate (§4.5), distinct from zcap.h/capability_provider.h's `kRdfType`
// (the real w3.org rdf:type used for ZCAP triples). Do not conflate them.

inline constexpr char kShapeRdfType[] = "rdf://type";
inline constexpr char kShapeHasShape[] = "shape://has_shape";
inline constexpr char kShapeTypeShape[] = "shape://Shape";
inline constexpr char kShapeName[] = "shape://name";
inline constexpr char kShapeTargetClass[] = "shape://targetClass";
inline constexpr char kShapeDefinition[] = "shape://definition";

inline constexpr char kShapeActionAddLink[] = "shape://actions/addLink";
inline constexpr char kShapeActionSetSingleTarget[] =
    "shape://actions/setSingleTarget";
inline constexpr char kShapeActionAddCollectionTarget[] =
    "shape://actions/addCollectionTarget";

// §4.2 — the sentinel datatype selecting an IRI object term rather than a typed
// literal.
inline constexpr char kShapeDatatypeUri[] = "URI";

// §5.1 / §10.4 — the extension action a caller MUST hold to register, modify or
// remove a shape. Distinct from the eight framework-core actions (see
// capability_provider.h): updateSHACL MUST be delegated explicitly.
inline constexpr char kActionUpdateSHACL[] = "updateSHACL";

// §6.3/§6.4 — the content-address IRI prefix. NOTE the colon: a shape address is
// `sha256:<hex>` (colon), unlike the module content-hash `sha256-<hex>` (hyphen,
// module_manifest.h). Both are lowercase-hex SHA-256, but of different pre-images
// and with different delimiters, so the two MUST NOT be interchanged.
inline constexpr char kShapeAddressPrefix[] = "sha256:";

// The XSD namespace that `xsd:`-prefixed datatypes expand to (§4.2 amendment).
inline constexpr char kXsdNamespace[] = "http://www.w3.org/2001/XMLSchema#";

// -- §4.3 constructor actions ---------------------------------------------

enum class ShapeActionKind {
  kAddLink,              // shape://actions/addLink (§4.3.1)
  kSetSingleTarget,      // shape://actions/setSingleTarget (§4.3.2)
  kAddCollectionTarget,  // shape://actions/addCollectionTarget (§4.3.3)
};

// One §4.3 constructor action. `subject` MUST be the literal "this"; `object` is
// either a property `name` (resolved from initialValues at construction) or a
// literal constant (§4.3 "object"). The parser accepts both the canonical
// `subject`/`object` keys (§4.3) and the `source`/`target` aliases used by the
// §12 examples — reconciled by the Spec 07 amendment pinning §4.3 as canonical.
struct ShapeConstructorAction {
  ShapeActionKind kind = ShapeActionKind::kSetSingleTarget;
  std::string action_uri;  // the verbatim shape://actions/* URI
  std::string subject;     // MUST be "this"
  std::string predicate;   // the triple predicate URI
  std::string object;      // property name or literal constant
};

// -- §4.2 property definitions --------------------------------------------

struct ShapePropertyDef {
  std::string path;                        // REQUIRED — predicate URI
  std::string name;                        // REQUIRED — [a-zA-Z_][a-zA-Z0-9_]*
  std::optional<std::string> datatype;     // OPTIONAL — XSD URI or "URI"
  unsigned long min_count = 0;             // OPTIONAL, default 0
  std::optional<unsigned long> max_count;  // OPTIONAL — absent == unbounded
  bool writable = true;                    // OPTIONAL, default true
  bool read_only = false;                  // OPTIONAL, default false
  std::optional<std::string> resolve_protocol;  // OPTIONAL
  std::optional<std::string> getter;            // OPTIONAL — SPARQL SELECT
};

// -- §4.1 shape definition ------------------------------------------------

struct ShapeDefinition {
  std::string target_class;                      // REQUIRED
  std::vector<ShapePropertyDef> properties;      // REQUIRED (may be empty)
  std::vector<ShapeConstructorAction> constructor;  // REQUIRED (may be empty)
  std::optional<std::string> extends;            // OPTIONAL — parent shape URI
  bool valid = false;
};

// Parse a §4 shape-definition JSON document into |*out|. Returns true iff the
// document is a well-formed shape per §4: `targetClass` present and non-empty;
// `properties` an array of well-formed §4.2 property objects (each with a
// non-empty `path`, a `name` matching [a-zA-Z_][a-zA-Z0-9_]* and unique within
// the shape, an OPTIONAL `datatype`/`minCount`/`maxCount`/`writable`/`readOnly`
// of the correct JSON type, and maxCount >= minCount when both are present);
// `constructor` an array of well-formed §4.3 actions (a recognised
// `shape://actions/*` URI, `subject`=="this", a non-empty `predicate`, and a
// non-empty `object`); and `extends`, when present, a non-empty string URI. On
// any failure returns false, sets |*error| (when non-null) to a human-readable
// reason, and leaves out->valid == false. This is the §5.2-step-2 "malformed →
// SyntaxError" check; the §5.2-step-3 extension check is ShapeNarrows().
bool ParseShapeDefinition(const std::string& json,
                          ShapeDefinition* out,
                          std::string* error);

// §4.2 — true iff |name| matches the property-name grammar [a-zA-Z_][a-zA-Z0-9_]*.
bool IsValidShapePropertyName(const std::string& name);

// §6.3 — the JCS (RFC 8785) canonical form of a shape-definition JSON document,
// the pre-image whose SHA-256 is the shape's content address. Returns nullopt if
// |json| is not well-formed JSON. Shared JCS (content/browser/did/jcs.*) makes
// this byte-identical across both build worlds.
std::optional<std::string> CanonicalizeShapeJson(const std::string& json);

// §6.3/§6.4 — format the content-address IRI `"sha256:" + hex(digest)` from the
// raw 32-byte SHA-256 digest of the JCS-canonical shape JSON. The caller supplies
// the digest (the SHA-256 primitive differs per build world); this core only
// prefixes and lowercase-hex-encodes.
std::string FormatShapeAddress(const std::string& raw_sha256_digest);

// True iff |s| is a well-formed §6.4 shape address: the literal "sha256:" prefix
// followed by exactly 64 lowercase hex characters.
bool IsWellFormedShapeAddress(const std::string& s);

// §4.2 (amendment c) — normalise a declared datatype to its canonical form:
//   * "URI"                          → "URI"                       (IRI term)
//   * "xsd:<name>"                   → "http://www.w3.org/2001/XMLSchema#<name>"
//   * a full URI (XSD or otherwise)  → unchanged                   (typed literal)
// An empty string maps to empty (no datatype declared → no type check).
std::string NormalizeDatatype(const std::string& datatype);

// True iff |normalized_datatype| selects an IRI object term (i.e. equals "URI").
bool IsUriDatatype(const std::string& normalized_datatype);

// §4.4/§10.3 — validate a lexical value against a NORMALISED datatype (the output
// of NormalizeDatatype). An empty datatype accepts anything (no check). "URI"
// requires a non-empty value with no whitespace. Recognised XSD datatypes
// (string family, boolean, the integer family with sign constraints, decimal,
// double/float, dateTime, date, anyURI) are checked against their XSD lexical
// space; any other (non-XSD, or unrecognised XSD) datatype is accepted as an
// opaque typed literal. Callers MUST invoke this before writing a value (setter
// TypeError on failure, §4.4).
bool ValidateLexicalForDatatype(const std::string& value,
                                const std::string& normalized_datatype);

// §4.6/§7.1 — true iff |child| is a valid strict narrowing of |parent|: for every
// property the child overrides (same `name` as a parent property) the child MUST
// only tighten — minCount may increase, maxCount may decrease (an absent/unbounded
// parent max permits any child max; a bounded parent max forbids an unbounded or
// larger child max), datatype may be added where the parent had none but MUST
// otherwise match, and writable may go true→false but never false→true (readOnly
// likewise). Loosening any constraint returns false and sets |*reason| (when
// non-null) to the offending property + constraint. Properties the child adds
// (names absent from the parent) are always permitted. This is the §5.2-step-3
// "invalid extension → ConstraintError" check.
bool ShapeNarrows(const ShapeDefinition& parent,
                  const ShapeDefinition& child,
                  std::string* reason);

// §4.2 setter-generation classification for a property.
enum class SetterKind {
  kNone,        // writable:false OR readOnly:true → no setter
  kScalar,      // maxCount==1 AND writable → set_{name}
  kCollection,  // maxCount absent/>1 AND writable → add_{name}/remove_{name}
};

// §4.2 — classify the setter a property generates.
SetterKind SetterKindFor(const ShapePropertyDef& property);

// Locate a property by its §4.2 `name` (nullptr if none). Used to resolve a
// constructor `object` that names a property (§4.3) and to dispatch setter /
// collection operations (§5.7).
const ShapePropertyDef* FindPropertyByName(const ShapeDefinition& shape,
                                           const std::string& name);

// Locate a property by its §4.2 `path` predicate (nullptr if none). Used to
// resolve the object term-type of a constructor action from the property whose
// path equals the action's predicate (§4.3 object resolution).
const ShapePropertyDef* FindPropertyByPath(const ShapeDefinition& shape,
                                           const std::string& path);

}  // namespace living_web

#endif  // CONTENT_BROWSER_SHAPES_SHAPE_DEFINITION_H_
