// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// FlowService — the browser-process port of the §5–§11 `Graph` flow API of
// Spec 10 (Graph Flows). A faithful C++ port of living_web::FlowService
// (standalone/flow_provider.h) onto the browser cores content::GraphBackend (the
// Spec 02 host graph a flow is registered into and whose FlowInstances it
// governs), content::DIDKeyProvider (the Spec 01 identity whose key authors the
// registration/instance writes), content::GovernanceBackend (the Spec 04
// updateFlow gate and the §9/§14.3 role requirement), and content::
// GraphBackendManager (accepted for parity / future cross-graph guard resolution;
// it may be null).
//
// The two ports share three Chromium-independent cores verbatim, so the harness
// and the browser never diverge on the bytes a flow stores, the verdict a guard
// reaches, or the transition a race resolves to:
//   * content/browser/flows/flow_definition.{h,cc} — §4 grammar parsing, §5.2
//     `flow://` vocabulary, §8.1 ISO 8601 durations, §5.1 JCS canonicalisation;
//   * content/browser/governance/constraint_vocabulary.h — the Spec 08 §5.3
//     timestamp-plausibility engine (living_web::constraint_vocab), reused for
//     the §8.2/§8.3 "entered state at" checks;
//   * content/browser/graph_sync/default_sync_module.h — the Spec 09 §8.4
//     concurrent-transition tie-break (living_web::default_sync::FlowStateWinner),
//     reused for the §13.2 race rule so a flow engine and its underlying sync
//     module never disagree about which transition stands.
//
// What it enforces, normatively (identical to the standalone provider):
//   * §5.2/§11.2 authorisation — every addFlow/removeFlow requires the
//     `updateFlow` extension capability (GovernanceBackend::CanPerformAction); an
//     open-mode / no-DID graph always allows (there is nothing to enforce);
//   * §5.2 — malformed flow JSON is a "SyntaxError"; a name/definition mismatch or
//     a duplicate local flow name is a "ConstraintError";
//   * §5.1/§5.2 — flows are stored as triples inside the graph they govern:
//     `<graph-id> flow://has_flow <flow://Name>` plus the rdf://type / name /
//     applies_to / initial_state header, the per-state and per-transition triples,
//     AND the canonical `flow://definition` JSON literal that is the round-trip
//     source of truth (SPEC_COMPLIANCE amendment, paralleling Spec 07's
//     `shape://definition`);
//   * §6.2 — executeFlowTransition runs the eight-step lifecycle: resolve, verify
//     the instance is in `fromState`, evaluate the §7 SPARQL ASK guard, evaluate
//     the §8 temporal constraint against the state-entry reifier timestamp
//     (subject to §5.3 plausibility), verify the §9 role under the graph's §14.3
//     enforcement mode, then atomically re-point the state link and execute the
//     §4.4 actions, instantiating any §10 sub-flow;
//   * §7.4 — guards MUST be pure `ASK` queries; the update/data-management and
//     federation forms are rejected fail-closed;
//   * §8.2/§8.3 — the "entered state at" time is the reifier timestamp on the
//     instance's current state link; a timestamp that fails the §5.3 checks is NOT
//     used to satisfy `minDelay` or to declare a `maxDelay` deadline elapsed;
//   * §13.2 — concurrent transitions resolve by the DEFAULT-SYNC-MODULE §8.4 rule
//     (smaller reifier hash wins), exposed via ConcurrentTransitionWinner;
//   * §14.3 — role requirements follow the graph's enforcement mode: open ignores
//     them, announced records but does not block, enforced mandates the ZCAP —
//     exactly the semantics GovernanceBackend::CanPerformAction already applies.
//
// SPEC_COMPLIANCE amendment (composite flows): a FlowInstance's current-state link
// is the flow-scoped predicate `flow://<name>/state`, NOT a single shared
// `flow://state`. Flow names are unique within a graph (§4.1), so a parent flow
// and a sub-flow (§10) governing the SAME instance keep independent states instead
// of colliding on one predicate.
//
// FlowService is a per-realm object (like ShapeService, it operates on any
// GraphBackend* W passed to each call); PersonalGraphManager owns one and shares
// it with every PersonalGraphHost so the §11 renderer surface runs against a
// single identity/governance/graph view. There is no world-specific dependency:
// the flow core never hashes, so — unlike ShapeService — this backend does not
// even touch //crypto; it canonicalises with CanonicalizeFlowJson() and defers
// every write to the shared graph.

#ifndef CONTENT_BROWSER_FLOWS_FLOW_SERVICE_H_
#define CONTENT_BROWSER_FLOWS_FLOW_SERVICE_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/flows/flow_definition.h"
#include "content/browser/governance/constraint_vocabulary.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph/rdf_serialization.h"
#include "content/browser/graph/sparql_results.h"
#include "content/browser/graph_sync/default_sync_module.h"

namespace content {

// ---- §11.1 API value types (mirror the FlowInfo / FlowTransitionResult IDL
// dicts) -------------------------------------------------------------------

struct FlowInfo {
  std::string name;
  std::string applies_to;
  std::string initial_state;
  std::vector<std::string> states;       // state names, definition order
  std::vector<std::string> transitions;  // transition names, definition order
};

struct FlowTransitionResult {
  bool success = false;
  std::optional<std::string> new_state;
  std::optional<std::string> reason;
  std::optional<std::string> guard_description;
  std::optional<std::string> seconds_until_allowed;  // set only on minDelay reject
};

// ---- the flow service -------------------------------------------------------

// Implements the Spec 10 §5–§11 API over a set of graphs. Every method takes the
// target GraphBackend* as its first argument (the browser binds these onto the
// `Graph` interface via PersonalGraphHost; the harness calls them directly).
// |governance| gates the `updateFlow` extension action and the §9/§14.3 role
// requirement; it may be null (treated as open). |graphs| is accepted for API
// parity with the other services and future cross-graph guard resolution; it may
// be null.
class FlowService {
 public:
  FlowService(DIDKeyProvider* identity,
              GovernanceBackend* governance,
              GraphBackendManager* graphs)
      : identity_(identity), governance_(governance), graphs_(graphs) {}

  FlowService(const FlowService&) = delete;
  FlowService& operator=(const FlowService&) = delete;

  const std::string& last_error() const { return last_error_; }

  // §5.2 addFlow: register |flow_json| under |name| into |W|, authored by the
  // credential |author_cred_id|. Returns false + last_error() on any rejection.
  bool AddFlow(GraphBackend* W,
               const std::string& name,
               const std::string& flow_json,
               const std::string& author_cred_id);

  // §5.3 removeFlow: drop the registration of |name| (requires updateFlow).
  // Existing FlowInstances are NOT reset. A missing flow is a no-op success.
  bool RemoveFlow(GraphBackend* W,
                  const std::string& name,
                  const std::string& author_cred_id);

  // §5.4 getFlows: the flows registered in |W|.
  std::vector<FlowInfo> GetFlows(GraphBackend* W);

  // Resolve a single flow definition by |name| (local). False → NotFoundError.
  bool GetFlow(GraphBackend* W,
               const std::string& name,
               living_web::flows::FlowDefinition* out);

  // §6.1 creation: establish the initial-state link on |instance_uri| for
  // |flow_name| (a governed, reified write). The reifier timestamp becomes the
  // §8.2 "entered state at" time. Refuses if the instance already carries a state
  // for this flow (InvalidStateError).
  bool InitializeInstance(GraphBackend* W,
                          const std::string& flow_name,
                          const std::string& instance_uri,
                          const std::string& author_cred_id);

  // §14.1 shape→flow auto-init: for every flow whose §4.1 `appliesTo` targetClass
  // equals |target_class|, apply that flow's §4.2 initialState to the freshly
  // created shape instance |instance_uri| (each a best-effort InitializeInstance
  // authored by |author_cred_id|). This is the SOLE JS-reachable instance-init
  // path — the §11.1 `Graph` flow surface exposes no initializeInstance method, so
  // without this wiring getFlowState/executeFlowTransition/availableTransitions are
  // unreachable on a shape instance. Returns the names of the flows initialised. A
  // flow already carrying a state on the instance is skipped (never an error), so
  // this composes with the §10 sub-flow instantiation on the same instance.
  // last_error() is cleared: auto-init is a best-effort side effect of
  // createShapeInstance, not a failable operation.
  std::vector<std::string> AutoInitInstanceForClass(
      GraphBackend* W,
      const std::string& target_class,
      const std::string& instance_uri,
      const std::string& author_cred_id);

  // §6.3 getFlowState: the FlowInstance's current state for |flow_name|.
  bool GetFlowState(GraphBackend* W,
                    const std::string& flow_name,
                    const std::string& instance_uri,
                    std::string* out_state);

  // §11.4 availableTransitions: the names of transitions that would currently
  // succeed for |instance_uri| under |author_cred_id| — guard, temporal and role
  // all satisfied against the present graph state.
  bool AvailableTransitions(GraphBackend* W,
                            const std::string& flow_name,
                            const std::string& instance_uri,
                            const std::string& author_cred_id,
                            std::vector<std::string>* out);

  // §6.2 / §11.3 executeFlowTransition: attempt to fire |transition_name| on
  // |instance_uri|. Business rejections (wrong state, guard, temporal, role) come
  // back as a result with success == false; a programming error (bad credential,
  // unknown flow/transition) sets last_error() to the DOMException name.
  FlowTransitionResult ExecuteFlowTransition(GraphBackend* W,
                                             const std::string& flow_name,
                                             const std::string& instance_uri,
                                             const std::string& transition_name,
                                             const std::string& author_cred_id);

  // §13.4 deadline: the name of an `onDeadline: "auto-transition"` transition out
  // of |instance_uri|'s current state whose `maxDelay` has elapsed under a
  // plausible state-entry timestamp, if any. The caller fires it via
  // ExecuteFlowTransition authored by the system identity (§8.4).
  std::optional<std::string> DueDeadlineTransition(
      GraphBackend* W,
      const std::string& flow_name,
      const std::string& instance_uri);

  // §13.2 concurrent-transition tie-break: reuse the DEFAULT-SYNC-MODULE §8.4 rule
  // verbatim — the commit with the lexicographically smaller reifier hash wins.
  static const std::string& ConcurrentTransitionWinner(
      const std::string& reifier_hash_a,
      const std::string& reifier_hash_b);

 private:
  struct TransitionCheck {
    bool ok = false;
    std::optional<std::string> reason;
    std::optional<std::string> guard_description;
    std::optional<std::string> seconds_until_allowed;
    std::string hard_error;  // non-empty → a DOMException-style failure
  };

  bool Ok() {
    last_error_.clear();
    return true;
  }
  bool Fail(const std::string& e) {
    last_error_ = e;
    return false;
  }

  // The stable identifier the flow triples are subject-keyed on: the graph's DID
  // when it has one, else its urn:graph id (§5.1).
  static std::string GraphId(GraphBackend* g) {
    return g->did().value_or(g->id());
  }

  // The flow-scoped current-state predicate (composite-flow amendment):
  // `flow://<name>/state`. Flow names are unique within a graph, so parent and
  // sub-flow states on one instance never collide.
  static std::string StatePredicate(const std::string& flow_name) {
    return living_web::flows::FlowNodeIri(flow_name) + "/state";
  }

  bool CanUpdateFlow(GraphBackend* W, const std::string& author_did);

  // Find the flow node `flow://<name>` registered locally in |W| and parse its
  // stored `flow://definition` literal into |*out_def|.
  bool GetFlowNodeAndDef(GraphBackend* W,
                         const std::string& name,
                         std::string* out_node,
                         living_web::flows::FlowDefinition* out_def);

  // The instance's current state under |state_pred|: the object of the most
  // recent (reifier-timestamp DESC) `<instance> <state_pred> ?state` link.
  static std::optional<std::string> CurrentState(GraphBackend* W,
                                                 const std::string& state_pred,
                                                 const std::string& instance);

  // §8.2/§8.3 — the reifier timestamp on the instance's current state link (the
  // most recent, when several reifiers exist). nullopt if the link is unreified.
  static std::optional<std::string> StateEntryTimestamp(
      GraphBackend* W,
      const std::string& state_pred,
      const std::string& instance,
      const std::string& state);

  // §5.3/§8.2 — a state-entry timestamp is usable only if it passes the future
  // bound (the local engine has no causal parents to compare against; the full
  // causal/per-author checks run at sync receipt, §13.4).
  bool TimestampPlausible(const std::string& ts) const;

  // True iff at least |need_seconds| have elapsed since |entry_ts| under a
  // plausible timestamp. |*out_seconds_left| is the remaining wait (0 when
  // elapsed, |need_seconds| when the timestamp is unusable).
  bool DelayElapsed(const std::string& entry_ts,
                    int64_t need_seconds,
                    int64_t* out_seconds_left) const;

  // §6.2 steps 2-5 as a pure check (no writes) — shared by executeFlowTransition
  // and availableTransitions.
  TransitionCheck CheckTransition(GraphBackend* W,
                                  const living_web::flows::FlowDefinition& flow,
                                  const living_web::flows::FlowTransition& tr,
                                  const std::string& instance,
                                  const std::string& author_did,
                                  const std::string& current_state);

  // §9 + §14.3 — CanPerformAction realises the §14.3 semantics in one call. A
  // null governance (or absent role) is open.
  bool RoleAllowed(GraphBackend* W,
                   const living_web::flows::FlowTransition& tr,
                   const std::string& author_did);

  // §7 — evaluate a SPARQL ASK guard with `$this` bound to |instance|.
  bool EvalGuard(GraphBackend* W,
                 const std::string& instance,
                 const std::string& guard,
                 bool* out);

  // §7.4 — a guard MUST be a pure `ASK`. Reject any update/data-management or
  // federation keyword (case-insensitive, whole-word).
  static bool GuardIsSafe(const std::string& guard);

  // Whole-word (non-alphanumeric-delimited) substring search in an
  // already-uppercased haystack.
  static bool ContainsWord(const std::string& hay, const std::string& word);

  static bool IsWordChar(char c);

  // Replace every `$this` token with the instance's SPARQL IRI reference
  // (injection-safe).
  static std::string SubstituteThis(const std::string& guard,
                                    const std::string& instance);

  // §4.4 — run the transition's actions as governed writes on |instance|.
  bool ApplyActions(
      GraphBackend* W,
      const std::string& instance,
      const std::string& agent_did,
      const std::vector<living_web::flows::FlowAction>& actions);

  // §4.4 object resolution: "now" → an xsd:dateTime literal of the current time;
  // "agent" → the firing agent's DID (an IRI); an `addLink` object is always an
  // IRI; otherwise a scheme-qualified value is an IRI and a bare value is a plain
  // xsd:string literal.
  static living_web::ObjectTerm ResolveActionObject(
      living_web::flows::FlowActionKind kind,
      const std::string& raw,
      const std::string& agent_did);

  // True iff |s| begins with an RFC 3986 scheme — used to tell a URI object from
  // a plain literal.
  static bool HasUriScheme(const std::string& s);

  static FlowInfo ToInfo(const living_web::flows::FlowDefinition& def);

  raw_ptr<DIDKeyProvider> identity_;       // Not owned.
  raw_ptr<GovernanceBackend> governance_;  // May be null (open graphs).
  raw_ptr<GraphBackendManager> graphs_;    // May be null.
  std::string last_error_;
};

}  // namespace content

#endif  // CONTENT_BROWSER_FLOWS_FLOW_SERVICE_H_
