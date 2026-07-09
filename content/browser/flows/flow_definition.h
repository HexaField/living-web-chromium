// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Graph Flows (Spec 10) — the flow-definition core: the §4 flow-definition JSON
// grammar, the §5.2 `flow://` triple vocabulary, the §8 ISO 8601 duration
// parser, and the §4.4 action model.
//
// The Chromium-independent core (namespace `living_web::flows`, pure-std, no
// Chromium and no standalone-shim dependencies) shared byte-for-byte by the
// browser flow service (content/browser/flows/flow_service.*) and the standalone
// harness (standalone/flow_provider.h). It defines:
//
//   * the §4 flow-definition JSON grammar parsed into a structured
//     FlowDefinition (name, namespace, appliesTo, initialState, states[],
//     transitions[]), with the §4.2 state-name grammar, the §4.3 transition
//     endpoints/guard/temporal/role/actions/triggersSubFlow, and the §4.4 action
//     model;
//   * the §5.2 well-known `flow://` predicate vocabulary plus the `flow://<name>`
//     / `.../state/<s>` / `.../transition/<t>` node-IRI convention of §5.1;
//   * the §8.1 ISO 8601 duration → seconds parser used to evaluate `minDelay` /
//     `maxDelay`;
//   * the §5.1 canonical-JSON pre-image (`flow://definition`) the service stores
//     so a mounted graph round-trips its full flow logic — actions, sub-flows and
//     descriptions that the decomposed §5.1 structural triples do not capture
//     (SPEC_COMPLIANCE amendment, paralleling Spec 07's `shape://definition`).
//
// Like module_manifest.cc, shape_definition.cc, graph_diff.cc and zcap.cc, this
// translation unit performs no hashing itself. JCS canonicalisation IS shared
// (content/browser/did/jcs.*), so CanonicalizeFlowJson lives here and both worlds
// derive byte-identical `flow://definition` literals. The §13.2 concurrent-
// transition tie-break is NOT redefined here: it is exactly DEFAULT-SYNC-MODULE
// §8.4, so the service reuses living_web::default_sync::FlowStateWinner /
// CompareReifierHash. The JSON grammar is scanned by a small self-contained reader
// (mirroring module_manifest.cc / shape_definition.cc, with no dependency on
// standalone/json_parser.h) so the same bytes parse in both worlds.

#ifndef CONTENT_BROWSER_FLOWS_FLOW_DEFINITION_H_
#define CONTENT_BROWSER_FLOWS_FLOW_DEFINITION_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace living_web {
namespace flows {

// -- §5.2 flow vocabulary --------------------------------------------------
//
// Scheme-shorthand IRIs used verbatim by the spec. `kFlowRdfType` is the spec's
// `rdf://type` discriminator (§5.1 `<flow://Name> rdf://type flow://Flow`),
// distinct from the real w3.org rdf:type used for ZCAP/DID triples elsewhere.

inline constexpr char kFlowRdfType[] = "rdf://type";
inline constexpr char kFlowTypeFlow[] = "flow://Flow";

inline constexpr char kFlowHasFlow[] = "flow://has_flow";
inline constexpr char kFlowName[] = "flow://name";
inline constexpr char kFlowAppliesTo[] = "flow://applies_to";
inline constexpr char kFlowInitialState[] = "flow://initial_state";
inline constexpr char kFlowHasState[] = "flow://has_state";
inline constexpr char kFlowStateName[] = "flow://state_name";
inline constexpr char kFlowIsTerminal[] = "flow://is_terminal";
inline constexpr char kFlowHasTransition[] = "flow://has_transition";
inline constexpr char kFlowTransitionName[] = "flow://transition_name";
inline constexpr char kFlowTransitionFrom[] = "flow://transition_from";
inline constexpr char kFlowTransitionTo[] = "flow://transition_to";
inline constexpr char kFlowTransitionGuard[] = "flow://transition_guard";
inline constexpr char kFlowTransitionMinDelay[] = "flow://transition_min_delay";
inline constexpr char kFlowTransitionMaxDelay[] = "flow://transition_max_delay";
inline constexpr char kFlowTransitionOnDeadline[] =
    "flow://transition_on_deadline";
inline constexpr char kFlowTransitionRole[] = "flow://transition_role";

// §5.2 — a FlowInstance's current state (on the instance itself) and the reifier
// timestamp predicate the temporal engine reads (§8.2).
inline constexpr char kFlowState[] = "flow://state";
inline constexpr char kFlowEnteredStateAt[] = "flow://entered_state_at";

// §10.2 — a sub-flow's terminal-state completion link the parent may guard on.
inline constexpr char kFlowCompleted[] = "flow://completed";

// SPEC_COMPLIANCE amendment (§5.1) — the canonical-JSON pre-image literal, the
// service's round-trip source of truth (parallels shape://definition). NOTE the
// colon vs the module content-hash: this is a JSON literal, not a content hash.
inline constexpr char kFlowDefinition[] = "flow://definition";

// §11.2 — the extension action a caller MUST hold to register or remove a flow.
// Distinct from the eight framework-core actions (capability_provider.h):
// updateFlow MUST be delegated explicitly.
inline constexpr char kActionUpdateFlow[] = "updateFlow";

// §4.4 — the recognised action-type URIs.
inline constexpr char kFlowActionAddLink[] = "flow://actions/addLink";
inline constexpr char kFlowActionSetSingleTarget[] =
    "flow://actions/setSingleTarget";
inline constexpr char kFlowActionRemoveLink[] = "flow://actions/removeLink";

// §4.4 — the object substitution sentinels.
inline constexpr char kFlowObjectNow[] = "now";
inline constexpr char kFlowObjectAgent[] = "agent";

// §4.4 — the subject sentinel referring to the FlowInstance.
inline constexpr char kFlowSubjectThis[] = "this";

// -- §8.1 onDeadline behaviour ---------------------------------------------

enum class OnDeadline {
  kNone,            // no onDeadline declared
  kAutoTransition,  // "auto-transition" — runtime fires it (system-authored)
  kErrorState,      // "error-state" — runtime fires a configured error transition
  kNotify,          // "notify" — event only, no state change
};

// §8.1 — parse the onDeadline token; nullopt if unrecognised.
std::optional<OnDeadline> ParseOnDeadline(const std::string& token);

// §8.1 — the verbatim token for an OnDeadline (kNone → "").
std::string OnDeadlineToken(OnDeadline on_deadline);

// -- §4.4 actions ----------------------------------------------------------

enum class FlowActionKind {
  kAddLink,          // flow://actions/addLink
  kSetSingleTarget,  // flow://actions/setSingleTarget
  kRemoveLink,       // flow://actions/removeLink
};

// One §4.4 action executed atomically with the state change. `subject` is the
// literal "this" (the FlowInstance) or a static URI; `object` is a static
// URI/literal, or the sentinel "now" (current timestamp) or "agent" (firing
// agent's DID). The parser accepts both the canonical `subject`/`object` keys
// (§4.4) and the `source`/`target` aliases used by the §17 examples — reconciled
// by the Spec 10 amendment pinning §4.4 as canonical.
struct FlowAction {
  FlowActionKind kind = FlowActionKind::kSetSingleTarget;
  std::string action_uri;  // the verbatim flow://actions/* URI
  std::string subject;     // "this" or a static URI
  std::string predicate;   // the triple predicate URI
  std::string object;      // static URI/literal, or "now" / "agent"
};

// -- §4.2 state ------------------------------------------------------------

struct FlowState {
  std::string name;                          // [a-zA-Z_][a-zA-Z0-9_]*
  std::optional<std::string> display_name;   // OPTIONAL
  bool is_terminal = false;                  // OPTIONAL, default false
};

// -- §8.1 temporal constraints ---------------------------------------------

struct FlowTemporal {
  std::optional<std::string> min_delay;  // OPTIONAL — ISO 8601 duration (verbatim)
  std::optional<std::string> max_delay;  // OPTIONAL — ISO 8601 duration (verbatim)
  OnDeadline on_deadline = OnDeadline::kNone;  // OPTIONAL

  bool empty() const {
    return !min_delay && !max_delay && on_deadline == OnDeadline::kNone;
  }
};

// -- §4.3 transition -------------------------------------------------------

struct FlowTransition {
  std::string name;                             // REQUIRED, unique in the flow
  std::optional<std::string> display_name;      // OPTIONAL
  std::string from_state;                       // REQUIRED — a defined state
  std::string to_state;                         // REQUIRED — a defined state
  std::optional<std::string> guard;             // OPTIONAL — SPARQL ASK
  std::optional<std::string> guard_description; // OPTIONAL
  FlowTemporal temporal;                        // OPTIONAL
  std::optional<std::string> role;              // OPTIONAL — ZCAP action
  std::vector<FlowAction> actions;              // OPTIONAL
  std::optional<std::string> triggers_sub_flow; // OPTIONAL — sub-flow name
};

// -- §4.1 flow definition --------------------------------------------------

struct FlowDefinition {
  std::string name;           // REQUIRED
  std::string ns;             // REQUIRED — namespace (JSON key "namespace")
  std::string applies_to;     // REQUIRED — targetClass URI
  std::string initial_state;  // REQUIRED — a defined state name
  std::vector<FlowState> states;            // REQUIRED (>= 1)
  std::vector<FlowTransition> transitions;  // REQUIRED (may be empty)
  bool valid = false;
};

// Parse a §4 flow-definition JSON document into |*out|. Returns true iff the
// document is a well-formed flow per §4:
//   * `name`, `namespace`, `appliesTo`, `initialState` each present and non-empty;
//   * `states` an array of >= 1 well-formed §4.2 state objects (each with a `name`
//     matching [a-zA-Z_][a-zA-Z0-9_]* and unique within the flow, an OPTIONAL
//     string `displayName`, and an OPTIONAL boolean `isTerminal`);
//   * `initialState` naming a defined state;
//   * `transitions` an array of well-formed §4.3 transitions (a `name` unique in
//     the flow; `fromState`/`toState` each naming a defined state; an OPTIONAL
//     string `guard`/`guardDescription`/`role`/`triggersSubFlow`; an OPTIONAL
//     `temporal` object whose `minDelay`/`maxDelay` parse as ISO 8601 durations
//     and whose `onDeadline`, if present, is one of the three §8.1 tokens; and an
//     OPTIONAL `actions` array of well-formed §4.4 actions);
//   * no transition leaving a state marked `isTerminal` (§4.2 / §6.4).
// On any failure returns false, sets |*error| (when non-null) to a human-readable
// reason, and leaves out->valid == false.
bool ParseFlowDefinition(const std::string& json,
                         FlowDefinition* out,
                         std::string* error);

// §4.2 — true iff |name| matches the state-name grammar [a-zA-Z_][a-zA-Z0-9_]*.
bool IsValidFlowStateName(const std::string& name);

// Locate a state / transition by its §4.2 / §4.3 `name` (nullptr if none).
const FlowState* FindState(const FlowDefinition& flow, const std::string& name);
const FlowTransition* FindTransition(const FlowDefinition& flow,
                                     const std::string& name);

// §8.1 — parse an ISO 8601 duration (`PnYnMnWnDTnHnMnS`, integer components) to
// whole seconds. Returns false on malformation or an empty duration ("P"/"PT").
// Nominal calendar units: Y = 365 d, M (date section) = 30 d, W = 7 d.
bool ParseIso8601Duration(const std::string& duration, int64_t* out_seconds);

// §5.1 node-IRI convention: the flow node `flow://<name>`, a state node
// `flow://<name>/state/<state>`, a transition node
// `flow://<name>/transition/<transition>`.
std::string FlowNodeIri(const std::string& flow_name);
std::string FlowStateNodeIri(const std::string& flow_name,
                             const std::string& state_name);
std::string FlowTransitionNodeIri(const std::string& flow_name,
                                  const std::string& transition_name);

// §5.1 — the JCS (RFC 8785) canonical form of a flow-definition JSON document,
// the `flow://definition` literal the service stores. Returns nullopt if |json|
// is not well-formed JSON. Shared JCS (content/browser/did/jcs.*) makes this
// byte-identical across both build worlds.
std::optional<std::string> CanonicalizeFlowJson(const std::string& json);

}  // namespace flows
}  // namespace living_web

#endif  // CONTENT_BROWSER_FLOWS_FLOW_DEFINITION_H_
