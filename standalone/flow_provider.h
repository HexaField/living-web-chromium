// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Standalone Graph Flows service (Spec 10).
//
// This header-only service is the Chromium-independent mirror of the browser
// flow service (content/browser/flows/flow_service.*). It composes the shared
// flow-definition core (content/browser/flows/flow_definition.{h,cc} — §4 grammar
// parsing, §5.2 `flow://` vocabulary, §8.1 ISO 8601 durations, §5.1 JCS
// canonicalisation) into the full §5–§11 `Graph` flow API on top of the public
// Spec 02 Graph surface, the Spec 04 GovernanceEngine, and the Spec 03
// GroupManager. It reuses, verbatim, the Spec 08 §5.3 timestamp-plausibility
// engine (content/browser/governance/constraint_vocabulary.h) and the Spec 09
// §8.4 concurrent-transition tie-break (content/browser/graph_sync/
// default_sync_module.h) so a flow engine and its underlying sync module never
// disagree about which transition stands (§13.2).
//
// What it enforces, normatively:
//   * §5.2/§11.2 authorisation — every addFlow/removeFlow requires the
//     `updateFlow` extension capability (GovernanceEngine::CanPerformAction); an
//     open-mode / no-DID graph always allows (there is nothing to enforce);
//   * §5.2 — malformed flow JSON is a "SyntaxError"; a duplicate local flow name
//     is a "ConstraintError";
//   * §5.1/§5.2 — flows are stored as triples inside the graph they govern:
//     `<graph-id> flow://has_flow <flow://Name>` plus the rdf://type / name /
//     applies_to / initial_state header, the per-state has_state/state_name/
//     is_terminal triples, the per-transition has_transition/name/from/to/guard/
//     min_delay/max_delay/on_deadline/role triples, AND the canonical
//     `flow://definition` JSON literal that is the round-trip source of truth
//     (SPEC_COMPLIANCE amendment, paralleling Spec 07's `shape://definition`);
//   * §6.2 — executeFlowTransition runs the eight-step lifecycle: resolve, verify
//     the instance is in `fromState`, evaluate the §7 SPARQL ASK guard, evaluate
//     the §8 temporal constraint against the state-entry reifier timestamp
//     (subject to §5.3 plausibility), verify the §9 role under the graph's §14.3
//     enforcement mode, then atomically re-point the state link and execute the
//     §4.4 actions, instantiating any §10 sub-flow;
//   * §7.4 — guards MUST be pure `ASK` queries; `INSERT`/`DELETE`/`LOAD`/`CLEAR`/
//     `DROP`/`SERVICE` (and the other update forms) are rejected fail-closed;
//   * §8.2/§8.3 — the "entered state at" time is the reifier timestamp on the
//     instance's current state link; a timestamp that fails the §5.3 checks
//     (future bound, causal/per-author monotonicity) is NOT used to satisfy
//     `minDelay` or to declare a `maxDelay` deadline elapsed;
//   * §13.2 — concurrent transitions resolve by the DEFAULT-SYNC-MODULE §8.4 rule
//     (smaller reifier hash wins), exposed via ConcurrentTransitionWinner;
//   * §14.3 — role requirements follow the graph's enforcement mode: open ignores
//     them, announced records but does not block, enforced mandates the ZCAP —
//     exactly the semantics GovernanceEngine::CanPerformAction already applies.
//
// SPEC_COMPLIANCE amendment (composite flows): a FlowInstance's current-state
// link is the flow-scoped predicate `flow://<name>/state`, NOT a single shared
// `flow://state`. Flow names are unique within a graph (§4.1), so a parent flow
// and a sub-flow (§10) governing the *same* instance keep independent states
// instead of colliding on one predicate. The §8.2 timestamp source is unchanged
// — it is the reifier on whichever state link the engine wrote — so the
// definition round-trips and the temporal engine reads the same bytes it signed.

#ifndef LIVING_WEB_FLOW_PROVIDER_H_
#define LIVING_WEB_FLOW_PROVIDER_H_

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "content/browser/flows/flow_definition.h"
#include "content/browser/governance/constraint_vocabulary.h"
#include "content/browser/graph/sparql_results.h"
#include "content/browser/graph_sync/default_sync_module.h"
#include "capability_provider.h"
#include "did_key_provider.h"
#include "graph_provider.h"
#include "group_provider.h"

namespace living_web {

// The Spec 10 flow-definition core lives in living_web::flows; pull its names in
// (no collision with any living_web symbol — the Spec 09 tie-break is under
// living_web::default_sync).
using namespace flows;

// -- §11.1 API value types (mirror the FlowInfo / FlowTransitionResult dicts) --

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

// -- the flow service ---------------------------------------------------------

// Implements the Spec 10 §5–§11 API over a set of graphs. Every method takes the
// target Graph* as its first argument (the browser binds these onto the `Graph`
// interface; the harness calls them directly). |governance| gates the
// `updateFlow` extension action and the §9/§14.3 role requirement; it may be null
// (treated as open). |groups| is accepted for API parity with the other services
// and future cross-graph guard resolution; it may be null.
class FlowService {
 public:
  FlowService(DIDKeyProvider* identity,
              GovernanceEngine* governance,
              GroupManager* groups)
      : identity_(identity), governance_(governance), groups_(groups) {}

  FlowService(const FlowService&) = delete;
  FlowService& operator=(const FlowService&) = delete;

  const std::string& last_error() const { return last_error_; }

  // §5.2 addFlow: register |flow_json| under |name| into |W|, authored by the
  // credential |author_cred_id|. Returns false + last_error() on any rejection.
  bool AddFlow(Graph* W,
               const std::string& name,
               const std::string& flow_json,
               const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    // §11.2 — updateFlow is REQUIRED.
    if (!CanUpdateFlow(W, author->did))
      return Fail("NotAllowedError");
    // §5.2 — malformed flow → SyntaxError.
    FlowDefinition def;
    std::string perr;
    if (!ParseFlowDefinition(flow_json, &def, &perr))
      return Fail("SyntaxError");
    // The registration name MUST match the definition's own name (§4.1/§5.1: the
    // flow node is flow://<name>, keyed on the flow's unique name).
    if (name != def.name)
      return Fail("ConstraintError");

    const std::string gid = GraphId(W);
    // §5.2 — a duplicate local flow name is a ConstraintError.
    FlowDefinition existing;
    std::string existing_node;
    if (GetFlowNodeAndDef(W, name, &existing_node, &existing))
      return Fail("ConstraintError");

    // §5.1 — the canonical JSON literal (round-trip source of truth).
    auto canonical = CanonicalizeFlowJson(flow_json);
    if (!canonical)
      return Fail("SyntaxError");

    const std::string flow_node = FlowNodeIri(name);
    std::vector<Triple> triples = {
        group_detail::T_iri(gid, kFlowHasFlow, flow_node),
        group_detail::T_iri(flow_node, kFlowRdfType, kFlowTypeFlow),
        group_detail::T_lit(flow_node, kFlowName, name),
        group_detail::T_iri(flow_node, kFlowAppliesTo, def.applies_to),
        group_detail::T_lit(flow_node, kFlowInitialState, def.initial_state),
        group_detail::T_lit(flow_node, kFlowDefinition, *canonical),
    };
    for (const FlowState& s : def.states) {
      const std::string s_node = FlowStateNodeIri(name, s.name);
      triples.push_back(group_detail::T_iri(flow_node, kFlowHasState, s_node));
      triples.push_back(group_detail::T_lit(s_node, kFlowStateName, s.name));
      if (s.is_terminal) {
        triples.push_back(group_detail::T_lit(s_node, kFlowIsTerminal, "true",
                                              group_detail::kXsdBoolean));
      }
    }
    for (const FlowTransition& t : def.transitions) {
      const std::string t_node = FlowTransitionNodeIri(name, t.name);
      triples.push_back(
          group_detail::T_iri(flow_node, kFlowHasTransition, t_node));
      triples.push_back(
          group_detail::T_lit(t_node, kFlowTransitionName, t.name));
      triples.push_back(
          group_detail::T_lit(t_node, kFlowTransitionFrom, t.from_state));
      triples.push_back(
          group_detail::T_lit(t_node, kFlowTransitionTo, t.to_state));
      if (t.guard) {
        triples.push_back(
            group_detail::T_lit(t_node, kFlowTransitionGuard, *t.guard));
      }
      if (t.temporal.min_delay) {
        triples.push_back(group_detail::T_lit(t_node, kFlowTransitionMinDelay,
                                              *t.temporal.min_delay));
      }
      if (t.temporal.max_delay) {
        triples.push_back(group_detail::T_lit(t_node, kFlowTransitionMaxDelay,
                                              *t.temporal.max_delay));
      }
      if (t.temporal.on_deadline != OnDeadline::kNone) {
        triples.push_back(group_detail::T_lit(
            t_node, kFlowTransitionOnDeadline,
            OnDeadlineToken(t.temporal.on_deadline)));
      }
      if (t.role) {
        triples.push_back(
            group_detail::T_lit(t_node, kFlowTransitionRole, *t.role));
      }
    }

    group_detail::ScopedActive active(identity_, author_cred_id);
    if (!W->AddTriples(triples))
      return Fail(W->last_error());
    return Ok();
  }

  // §5.3 removeFlow: drop the registration of |name| (requires updateFlow).
  // Existing FlowInstances are NOT reset. A missing flow is a no-op success.
  bool RemoveFlow(Graph* W,
                  const std::string& name,
                  const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    if (!CanUpdateFlow(W, author->did))
      return Fail("NotAllowedError");

    const std::string gid = GraphId(W);
    FlowDefinition def;
    std::string flow_node;
    if (!GetFlowNodeAndDef(W, name, &flow_node, &def))
      return Ok();  // nothing registered locally under this name

    std::vector<Triple> to_remove = {
        group_detail::T_iri(gid, kFlowHasFlow, flow_node),
        group_detail::T_iri(flow_node, kFlowRdfType, kFlowTypeFlow),
        group_detail::T_lit(flow_node, kFlowName, name),
        group_detail::T_iri(flow_node, kFlowAppliesTo, def.applies_to),
        group_detail::T_lit(flow_node, kFlowInitialState, def.initial_state),
    };
    if (auto stored_def = group_detail::FirstLiteralOf(W, flow_node,
                                                       kFlowDefinition)) {
      to_remove.push_back(
          group_detail::T_lit(flow_node, kFlowDefinition, *stored_def));
    }
    for (const FlowState& s : def.states) {
      const std::string s_node = FlowStateNodeIri(name, s.name);
      to_remove.push_back(group_detail::T_iri(flow_node, kFlowHasState, s_node));
      to_remove.push_back(group_detail::T_lit(s_node, kFlowStateName, s.name));
      if (s.is_terminal) {
        to_remove.push_back(group_detail::T_lit(s_node, kFlowIsTerminal, "true",
                                                group_detail::kXsdBoolean));
      }
    }
    for (const FlowTransition& t : def.transitions) {
      const std::string t_node = FlowTransitionNodeIri(name, t.name);
      to_remove.push_back(
          group_detail::T_iri(flow_node, kFlowHasTransition, t_node));
      to_remove.push_back(
          group_detail::T_lit(t_node, kFlowTransitionName, t.name));
      to_remove.push_back(
          group_detail::T_lit(t_node, kFlowTransitionFrom, t.from_state));
      to_remove.push_back(
          group_detail::T_lit(t_node, kFlowTransitionTo, t.to_state));
      if (t.guard) {
        to_remove.push_back(
            group_detail::T_lit(t_node, kFlowTransitionGuard, *t.guard));
      }
      if (t.temporal.min_delay) {
        to_remove.push_back(group_detail::T_lit(
            t_node, kFlowTransitionMinDelay, *t.temporal.min_delay));
      }
      if (t.temporal.max_delay) {
        to_remove.push_back(group_detail::T_lit(
            t_node, kFlowTransitionMaxDelay, *t.temporal.max_delay));
      }
      if (t.temporal.on_deadline != OnDeadline::kNone) {
        to_remove.push_back(group_detail::T_lit(
            t_node, kFlowTransitionOnDeadline,
            OnDeadlineToken(t.temporal.on_deadline)));
      }
      if (t.role) {
        to_remove.push_back(
            group_detail::T_lit(t_node, kFlowTransitionRole, *t.role));
      }
    }

    group_detail::ScopedActive active(identity_, author_cred_id);
    for (const Triple& t : to_remove) {
      bool removed = false;
      if (!W->RemoveTriple(t, &removed))
        return Fail(W->last_error());
    }
    return Ok();
  }

  // §5.4 getFlows: the flows registered in |W|.
  std::vector<FlowInfo> GetFlows(Graph* W) {
    std::vector<FlowInfo> out;
    const std::string gid = GraphId(W);
    std::set<std::string> seen;
    for (const ObjectTerm& o :
         group_detail::QueryObjects(W, gid, kFlowHasFlow)) {
      if (o.is_literal())
        continue;
      const std::string& node = o.iri_or_bnode;
      auto raw = group_detail::FirstLiteralOf(W, node, kFlowDefinition);
      if (!raw)
        continue;
      FlowDefinition def;
      std::string err;
      if (!ParseFlowDefinition(*raw, &def, &err))
        continue;
      if (!seen.insert(def.name).second)
        continue;
      out.push_back(ToInfo(def));
    }
    return out;
  }

  // Resolve a single flow definition by |name| (local). False → NotFoundError.
  bool GetFlow(Graph* W, const std::string& name, FlowDefinition* out) {
    std::string node;
    if (!GetFlowNodeAndDef(W, name, &node, out))
      return Fail("NotFoundError");
    return Ok();
  }

  // §6.1 creation: establish the initial-state link on |instance_uri| for
  // |flow_name| (a governed, reified write). The reifier timestamp becomes the
  // §8.2 "entered state at" time. Idempotent-guarded: refuses if the instance
  // already carries a state for this flow (InvalidStateError).
  bool InitializeInstance(Graph* W,
                          const std::string& flow_name,
                          const std::string& instance_uri,
                          const std::string& author_cred_id) {
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    FlowDefinition flow;
    std::string flow_node;
    if (!GetFlowNodeAndDef(W, flow_name, &flow_node, &flow))
      return Fail("NotFoundError");
    const std::string state_pred = StatePredicate(flow_name);
    if (CurrentState(W, state_pred, instance_uri))
      return Fail("InvalidStateError");  // already initialised for this flow

    Triple link = group_detail::T_lit(instance_uri, state_pred, flow.initial_state);
    if (governance_ &&
        !governance_->CanAddTriple(W, link, author->did).allowed)
      return Fail("NotAllowedError");
    group_detail::ScopedActive active(identity_, author_cred_id);
    if (!W->AddTriple(link))
      return Fail(W->last_error());
    return Ok();
  }

  // §14.1 shape→flow auto-init: for every flow whose §4.1 `appliesTo` targetClass
  // equals |target_class|, apply that flow's §4.2 initialState to the freshly
  // created shape instance |instance_uri| (each a best-effort InitializeInstance
  // authored by |author_cred_id|). This is the SOLE JS-reachable instance-init
  // path — the §11.1 `Graph` flow surface exposes no initializeInstance method, so
  // without this wiring getFlowState/executeFlowTransition/availableTransitions are
  // unreachable on a shape instance. Returns the names of the flows initialised. A
  // flow already carrying a state on the instance is skipped (InitializeInstance →
  // InvalidStateError), never an error, so this composes with the §10 sub-flow
  // instantiation on the same instance. last_error() is cleared: auto-init is a
  // best-effort side effect of createShapeInstance, not a failable operation.
  std::vector<std::string> AutoInitInstanceForClass(
      Graph* W,
      const std::string& target_class,
      const std::string& instance_uri,
      const std::string& author_cred_id) {
    std::vector<std::string> initialised;
    for (const FlowInfo& fi : GetFlows(W)) {
      if (fi.applies_to != target_class)
        continue;
      if (InitializeInstance(W, fi.name, instance_uri, author_cred_id))
        initialised.push_back(fi.name);
    }
    last_error_.clear();
    return initialised;
  }

  // §6.3 getFlowState: the FlowInstance's current state for |flow_name|.
  bool GetFlowState(Graph* W,
                    const std::string& flow_name,
                    const std::string& instance_uri,
                    std::string* out_state) {
    FlowDefinition flow;
    std::string flow_node;
    if (!GetFlowNodeAndDef(W, flow_name, &flow_node, &flow))
      return Fail("NotFoundError");
    auto cur = CurrentState(W, StatePredicate(flow_name), instance_uri);
    if (!cur)
      return Fail("NotFoundError");  // instance not in this flow
    *out_state = *cur;
    return Ok();
  }

  // §11.4 availableTransitions: the names of transitions that would currently
  // succeed for |instance_uri| under |author_cred_id| — guard, temporal and role
  // all satisfied against the present graph state.
  bool AvailableTransitions(Graph* W,
                            const std::string& flow_name,
                            const std::string& instance_uri,
                            const std::string& author_cred_id,
                            std::vector<std::string>* out) {
    out->clear();
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author)
      return Fail("InvalidStateError");
    FlowDefinition flow;
    std::string flow_node;
    if (!GetFlowNodeAndDef(W, flow_name, &flow_node, &flow))
      return Fail("NotFoundError");
    auto cur = CurrentState(W, StatePredicate(flow_name), instance_uri);
    if (!cur)
      return Fail("NotFoundError");
    for (const FlowTransition& t : flow.transitions) {
      if (t.from_state != *cur)
        continue;
      TransitionCheck chk = CheckTransition(W, flow, t, instance_uri,
                                            author->did, *cur);
      if (chk.ok)
        out->push_back(t.name);
    }
    return Ok();
  }

  // §6.2 / §11.3 executeFlowTransition: attempt to fire |transition_name| on
  // |instance_uri|. Business rejections (wrong state, guard, temporal, role) come
  // back as a result with success == false; a programming error (bad credential,
  // unknown flow/transition) sets last_error() to the DOMException name.
  FlowTransitionResult ExecuteFlowTransition(Graph* W,
                                             const std::string& flow_name,
                                             const std::string& instance_uri,
                                             const std::string& transition_name,
                                             const std::string& author_cred_id) {
    FlowTransitionResult res;
    const DIDKeyPair* author = identity_->GetCredential(author_cred_id);
    if (!author) {
      Fail("InvalidStateError");
      res.reason = "InvalidStateError";
      return res;
    }
    // §6.2 step 1 — resolve the flow and the named transition.
    FlowDefinition flow;
    std::string flow_node;
    if (!GetFlowNodeAndDef(W, flow_name, &flow_node, &flow)) {
      Fail("NotFoundError");
      res.reason = "NotFoundError";
      return res;
    }
    const FlowTransition* tr = FindTransition(flow, transition_name);
    if (!tr) {
      Fail("NotFoundError");
      res.reason = "NotFoundError";
      return res;
    }
    const std::string state_pred = StatePredicate(flow_name);
    auto cur = CurrentState(W, state_pred, instance_uri);
    if (!cur) {
      Fail("NotFoundError");
      res.reason = "NotFoundError";
      return res;
    }

    // §6.2 steps 2-5 — state, guard, temporal, role.
    TransitionCheck chk =
        CheckTransition(W, flow, *tr, instance_uri, author->did, *cur);
    if (!chk.ok) {
      if (!chk.hard_error.empty())
        Fail(chk.hard_error);
      res.reason = chk.reason;
      res.guard_description = chk.guard_description;
      res.seconds_until_allowed = chk.seconds_until_allowed;
      return res;
    }

    // §6.2 step 6 — atomically re-point the state link and run the §4.4 actions.
    {
      group_detail::ScopedActive active(identity_, author_cred_id);
      Triple old_link = group_detail::T_lit(instance_uri, state_pred, *cur);
      bool removed = false;
      if (!W->RemoveTriple(old_link, &removed)) {
        Fail(W->last_error());
        res.reason = W->last_error();
        return res;
      }
      Triple new_link =
          group_detail::T_lit(instance_uri, state_pred, tr->to_state);
      if (!W->AddTriple(new_link)) {
        Fail(W->last_error());
        res.reason = W->last_error();
        return res;
      }
      if (!ApplyActions(W, instance_uri, author->did, tr->actions)) {
        res.reason = last_error_;
        return res;
      }
      // §6.2 step 7 — instantiate a sub-flow on the same instance, if triggered
      // and registered (its state is the flow-scoped predicate, so it does not
      // disturb the parent's state).
      if (tr->triggers_sub_flow) {
        FlowDefinition sub;
        std::string sub_node;
        if (GetFlowNodeAndDef(W, *tr->triggers_sub_flow, &sub_node, &sub)) {
          const std::string sub_pred = StatePredicate(*tr->triggers_sub_flow);
          if (!CurrentState(W, sub_pred, instance_uri)) {
            Triple sub_link = group_detail::T_lit(instance_uri, sub_pred,
                                                  sub.initial_state);
            if (!W->AddTriple(sub_link)) {
              Fail(W->last_error());
              res.reason = W->last_error();
              return res;
            }
          }
        }
      }
    }

    // §6.2 step 8 — success (the browser fires `transitionfired` here).
    res.success = true;
    res.new_state = tr->to_state;
    Ok();
    return res;
  }

  // §13.4 deadline: the name of an `onDeadline: "auto-transition"` transition out
  // of |instance_uri|'s current state whose `maxDelay` has elapsed under a
  // plausible state-entry timestamp, if any. The caller fires it via
  // ExecuteFlowTransition authored by the system identity (§8.4).
  std::optional<std::string> DueDeadlineTransition(
      Graph* W,
      const std::string& flow_name,
      const std::string& instance_uri) {
    FlowDefinition flow;
    std::string flow_node;
    if (!GetFlowNodeAndDef(W, flow_name, &flow_node, &flow))
      return std::nullopt;
    const std::string state_pred = StatePredicate(flow_name);
    auto cur = CurrentState(W, state_pred, instance_uri);
    if (!cur)
      return std::nullopt;
    auto ts = StateEntryTimestamp(W, state_pred, instance_uri, *cur);
    if (!ts || !TimestampPlausible(*ts))
      return std::nullopt;
    for (const FlowTransition& t : flow.transitions) {
      if (t.from_state != *cur)
        continue;
      if (t.temporal.on_deadline != OnDeadline::kAutoTransition ||
          !t.temporal.max_delay)
        continue;
      int64_t max_secs = 0;
      if (!ParseIso8601Duration(*t.temporal.max_delay, &max_secs))
        continue;
      int64_t left = 0;
      if (DelayElapsed(*ts, max_secs, &left))
        return t.name;
    }
    return std::nullopt;
  }

  // §13.2 concurrent-transition tie-break: reuse the DEFAULT-SYNC-MODULE §8.4 rule
  // verbatim — the commit with the lexicographically smaller reifier hash wins.
  static const std::string& ConcurrentTransitionWinner(
      const std::string& reifier_hash_a,
      const std::string& reifier_hash_b) {
    return default_sync::FlowStateWinner(reifier_hash_a, reifier_hash_b);
  }

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
  static std::string GraphId(Graph* g) { return g->did().value_or(g->id()); }

  // The flow-scoped current-state predicate (composite-flow amendment):
  // `flow://<name>/state`. Flow names are unique within a graph, so parent and
  // sub-flow states on one instance never collide.
  static std::string StatePredicate(const std::string& flow_name) {
    return FlowNodeIri(flow_name) + "/state";
  }

  bool CanUpdateFlow(Graph* W, const std::string& author_did) {
    if (!governance_)
      return true;
    return governance_->CanPerformAction(W, kActionUpdateFlow, author_did)
        .allowed;
  }

  // Find the flow node `flow://<name>` registered locally in |W| and parse its
  // stored `flow://definition` literal into |*out_def|.
  bool GetFlowNodeAndDef(Graph* W,
                         const std::string& name,
                         std::string* out_node,
                         FlowDefinition* out_def) {
    const std::string gid = GraphId(W);
    for (const ObjectTerm& o :
         group_detail::QueryObjects(W, gid, kFlowHasFlow)) {
      if (o.is_literal())
        continue;
      const std::string& node = o.iri_or_bnode;
      auto nm = group_detail::FirstLiteralOf(W, node, kFlowName);
      if (!nm || *nm != name)
        continue;
      auto raw = group_detail::FirstLiteralOf(W, node, kFlowDefinition);
      if (!raw)
        continue;
      FlowDefinition def;
      std::string err;
      if (!ParseFlowDefinition(*raw, &def, &err))
        continue;
      *out_def = std::move(def);
      *out_node = node;
      return true;
    }
    return false;
  }

  // The instance's current state under |state_pred|: the object of the most
  // recent (reifier-timestamp DESC) `<instance> <state_pred> ?state` link.
  static std::optional<std::string> CurrentState(Graph* W,
                                                 const std::string& state_pred,
                                                 const std::string& instance) {
    TripleQuery q;
    q.subject = instance;
    q.predicate = state_pred;
    std::vector<Triple> ts;
    if (!W->QueryTriples(q, &ts) || ts.empty())
      return std::nullopt;
    const Triple& latest = ts.front();  // QueryTriples: DESC(?ts) ASC(?s)
    return latest.object.is_literal() ? latest.object.literal->lexical
                                      : latest.object.iri_or_bnode;
  }

  // §8.2/§8.3 — the reifier timestamp on the instance's current state link (the
  // most recent, when several reifiers exist). nullopt if the link is unreified.
  static std::optional<std::string> StateEntryTimestamp(
      Graph* W,
      const std::string& state_pred,
      const std::string& instance,
      const std::string& state) {
    Triple link = group_detail::T_lit(instance, state_pred, state);
    std::vector<Reifier> reifs;
    if (!W->Provenance(link, &reifs) || reifs.empty())
      return std::nullopt;
    std::string best = reifs.front().timestamp;
    int64_t best_epoch = 0;
    bool have = constraint_vocab::ParseRfc3339ToEpoch(best, &best_epoch);
    for (const Reifier& r : reifs) {
      int64_t e = 0;
      if (!constraint_vocab::ParseRfc3339ToEpoch(r.timestamp, &e))
        continue;
      if (!have || e > best_epoch) {
        best = r.timestamp;
        best_epoch = e;
        have = true;
      }
    }
    return best;
  }

  // §5.3/§8.2 — a state-entry timestamp is usable only if it passes the future
  // bound (the local engine has no causal parents to compare against; the full
  // causal/per-author checks run at sync receipt, §13.4).
  bool TimestampPlausible(const std::string& ts) const {
    constraint_vocab::PlausibilityInput in;
    in.t = ts;
    in.now = graph_detail::NowRfc3339();
    return constraint_vocab::CheckTimestampPlausibility(in).ok;
  }

  // True iff at least |need_seconds| have elapsed since |entry_ts| under a
  // plausible timestamp. |*out_seconds_left| is the remaining wait (0 when
  // elapsed, |need_seconds| when the timestamp is unusable).
  bool DelayElapsed(const std::string& entry_ts,
                    int64_t need_seconds,
                    int64_t* out_seconds_left) const {
    *out_seconds_left = need_seconds;
    if (!TimestampPlausible(entry_ts))
      return false;
    int64_t entered = 0;
    if (!constraint_vocab::ParseRfc3339ToEpoch(entry_ts, &entered))
      return false;
    int64_t now = 0;
    if (!constraint_vocab::ParseRfc3339ToEpoch(graph_detail::NowRfc3339(), &now))
      return false;
    int64_t elapsed = now - entered;
    if (elapsed >= need_seconds) {
      *out_seconds_left = 0;
      return true;
    }
    *out_seconds_left = need_seconds - elapsed;
    return false;
  }

  // §6.2 steps 2-5 as a pure check (no writes) — shared by executeFlowTransition
  // and availableTransitions.
  TransitionCheck CheckTransition(Graph* W,
                                  const FlowDefinition& flow,
                                  const FlowTransition& tr,
                                  const std::string& instance,
                                  const std::string& author_did,
                                  const std::string& current_state) {
    TransitionCheck chk;
    // step 2 — the instance MUST be in the transition's fromState.
    if (current_state != tr.from_state) {
      chk.reason = "instance is not in the transition's fromState";
      chk.hard_error = "InvalidStateError";
      return chk;
    }
    // §4.2/§6.4 — a terminal state has no outgoing transitions.
    const FlowState* from = FindState(flow, tr.from_state);
    if (from && from->is_terminal) {
      chk.reason = "fromState is terminal";
      chk.hard_error = "InvalidStateError";
      return chk;
    }
    // step 3 — the §7 guard.
    if (tr.guard) {
      bool holds = false;
      if (!EvalGuard(W, instance, *tr.guard, &holds) || !holds) {
        chk.reason = "guard did not hold";
        chk.guard_description = tr.guard_description;
        return chk;
      }
    }
    // step 4 — the §8 minDelay temporal constraint.
    if (tr.temporal.min_delay) {
      int64_t need = 0;
      if (!ParseIso8601Duration(*tr.temporal.min_delay, &need)) {
        chk.reason = "malformed minDelay";
        chk.hard_error = "InvalidStateError";
        return chk;
      }
      auto ts = StateEntryTimestamp(W, StatePredicate(flow.name), instance,
                                    current_state);
      int64_t left = need;
      if (!ts || !DelayElapsed(*ts, need, &left)) {
        chk.reason = "minDelay has not elapsed";
        chk.seconds_until_allowed = std::to_string(left);
        return chk;
      }
    }
    // step 5 — the §9 role requirement under the §14.3 enforcement mode.
    if (!RoleAllowed(W, tr, author_did)) {
      chk.reason = "NotAllowedError";
      return chk;
    }
    chk.ok = true;
    return chk;
  }

  // §9 + §14.3 — GovernanceEngine::CanPerformAction already returns allowed==true
  // in open/announced mode and enforces only in enforced mode, so a single call
  // realises the §14.3 semantics. A null governance (or absent role) is open.
  bool RoleAllowed(Graph* W,
                   const FlowTransition& tr,
                   const std::string& author_did) {
    if (!tr.role)
      return true;
    if (!governance_)
      return true;
    return governance_->CanPerformAction(W, *tr.role, author_did).allowed;
  }

  // §7 — evaluate a SPARQL ASK guard with `$this` bound to |instance|. Returns
  // false (query error / unsafe) or sets |*out| to the ASK boolean.
  bool EvalGuard(Graph* W,
                 const std::string& instance,
                 const std::string& guard,
                 bool* out) {
    *out = false;
    if (!GuardIsSafe(guard))  // §7.4 — reject non-ASK / mutating / federated
      return false;
    const std::string q = SubstituteThis(guard, instance);
    SparqlResult r = W->QuerySparql(q, {}, /*timeout_ms=*/100);
    if (!r.ok)
      return false;
    std::string err;
    return DecodeSparqlBoolean(r.payload, out, &err);
  }

  // §7.4 — a guard MUST be a pure `ASK`. Reject any update/data-management or
  // federation keyword (case-insensitive, whole-word).
  static bool GuardIsSafe(const std::string& guard) {
    std::string up;
    up.reserve(guard.size());
    for (char c : guard)
      up += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (!ContainsWord(up, "ASK"))
      return false;
    static const char* kForbidden[] = {"INSERT", "DELETE", "LOAD",   "CLEAR",
                                       "DROP",   "CREATE", "SERVICE", "ADD",
                                       "MOVE",   "COPY"};
    for (const char* kw : kForbidden) {
      if (ContainsWord(up, kw))
        return false;
    }
    return true;
  }

  // Whole-word (non-alphanumeric-delimited) substring search in an
  // already-uppercased haystack.
  static bool ContainsWord(const std::string& hay, const std::string& word) {
    size_t pos = 0;
    while ((pos = hay.find(word, pos)) != std::string::npos) {
      const bool left_ok =
          pos == 0 || !IsWordChar(hay[pos - 1]);
      const size_t end = pos + word.size();
      const bool right_ok = end >= hay.size() || !IsWordChar(hay[end]);
      if (left_ok && right_ok)
        return true;
      pos = end;
    }
    return false;
  }

  static bool IsWordChar(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_';
  }

  // Replace every `$this` token with the instance's SPARQL IRI reference
  // (injection-safe via graph_detail::SparqlIriRef).
  static std::string SubstituteThis(const std::string& guard,
                                    const std::string& instance) {
    const std::string ref = graph_detail::SparqlIriRef(instance);
    std::string out;
    out.reserve(guard.size() + ref.size());
    const std::string token = "$this";
    size_t i = 0;
    while (i < guard.size()) {
      if (guard.compare(i, token.size(), token) == 0) {
        out += ref;
        i += token.size();
      } else {
        out += guard[i++];
      }
    }
    return out;
  }

  // §4.4 — run the transition's actions as governed writes on |instance|.
  bool ApplyActions(Graph* W,
                    const std::string& instance,
                    const std::string& agent_did,
                    const std::vector<FlowAction>& actions) {
    for (const FlowAction& a : actions) {
      const std::string subject =
          (a.subject == kFlowSubjectThis) ? instance : a.subject;
      ObjectTerm object = ResolveActionObject(a.kind, a.object, agent_did);
      Triple t{subject, a.predicate, object};
      switch (a.kind) {
        case FlowActionKind::kRemoveLink: {
          bool removed = false;
          if (!W->RemoveTriple(t, &removed))
            return Fail(W->last_error());
          break;
        }
        case FlowActionKind::kSetSingleTarget: {
          // Single-valued: remove any existing (subject, predicate, *) first.
          TripleQuery q;
          q.subject = subject;
          q.predicate = a.predicate;
          std::vector<Triple> existing;
          if (W->QueryTriples(q, &existing)) {
            for (const Triple& e : existing) {
              bool removed = false;
              if (!W->RemoveTriple(e, &removed))
                return Fail(W->last_error());
            }
          }
          if (!W->AddTriple(t))
            return Fail(W->last_error());
          break;
        }
        case FlowActionKind::kAddLink: {
          if (!W->AddTriple(t))
            return Fail(W->last_error());
          break;
        }
      }
    }
    return true;
  }

  // §4.4 object resolution: "now" → an xsd:dateTime literal of the current time;
  // "agent" → the firing agent's DID (an IRI); an `addLink` object is always an
  // IRI (a link target); otherwise a scheme-qualified value is an IRI and a bare
  // value is a plain xsd:string literal.
  static ObjectTerm ResolveActionObject(FlowActionKind kind,
                                        const std::string& raw,
                                        const std::string& agent_did) {
    if (raw == kFlowObjectNow) {
      LiteralValue lv;
      lv.lexical = graph_detail::NowRfc3339();
      lv.datatype = kXsdDateTime;
      return ObjectTerm::Literal(lv);
    }
    if (raw == kFlowObjectAgent)
      return ObjectTerm::Iri(agent_did);
    if (kind == FlowActionKind::kAddLink)
      return ObjectTerm::Iri(raw);
    if (HasUriScheme(raw))
      return ObjectTerm::Iri(raw);
    LiteralValue lv;
    lv.lexical = raw;
    lv.datatype = kXsdString;
    return ObjectTerm::Literal(lv);
  }

  // True iff |s| begins with an RFC 3986 scheme (`ALPHA *( ALPHA / DIGIT / "+" /
  // "-" / "." ) ":"`) — used to tell a URI object from a plain literal.
  static bool HasUriScheme(const std::string& s) {
    if (s.empty())
      return false;
    char c0 = s[0];
    if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z')))
      return false;
    for (size_t i = 1; i < s.size(); ++i) {
      char c = s[i];
      if (c == ':')
        return i > 0;
      const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
      if (!ok)
        return false;
    }
    return false;
  }

  static FlowInfo ToInfo(const FlowDefinition& def) {
    FlowInfo info;
    info.name = def.name;
    info.applies_to = def.applies_to;
    info.initial_state = def.initial_state;
    for (const FlowState& s : def.states)
      info.states.push_back(s.name);
    for (const FlowTransition& t : def.transitions)
      info.transitions.push_back(t.name);
    return info;
  }

  DIDKeyProvider* identity_;
  GovernanceEngine* governance_;  // may be null (open graphs)
  GroupManager* groups_;          // may be null
  std::string last_error_;
};

}  // namespace living_web

#endif  // LIVING_WEB_FLOW_PROVIDER_H_
