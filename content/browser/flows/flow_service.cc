// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/flows/flow_service.h"

#include <cctype>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <set>
#include <sstream>
#include <utility>

namespace content {

// Pull the Spec 10 flow-definition core (namespace living_web::flows) into scope:
// the §5.2 `flow://` vocabulary constants, the §4 grammar structs, and the parser
// / canonicaliser / node-IRI / duration helpers. No collision with any content
// symbol — the reused Spec 08 timestamp engine stays under
// living_web::constraint_vocab and the Spec 09 tie-break under
// living_web::default_sync.
using namespace living_web::flows;

using living_web::LiteralValue;
using living_web::ObjectTerm;
using living_web::Reifier;
using living_web::SparqlResult;
using living_web::Triple;
using living_web::TripleQuery;

namespace {

// Current time as an RFC 3339 UTC string (§8.2 "entered state at" / §4.4 `now`).
// Local to this translation unit, exactly like the other browser backends.
std::string NowRfc3339() {
  std::time_t now = std::time(nullptr);
  std::tm* tm = std::gmtime(&now);
  std::ostringstream ss;
  ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

// Escapes an IRI for a SPARQL IRIREF (`<...>`): every character disallowed in an
// IRIREF is emitted as a UCHAR (`\uXXXX`) escape, blocking query injection through
// the caller-supplied instance IRI substituted for `$this` (§7.3).
std::string SparqlIriEscape(const std::string& iri) {
  std::string out;
  out.reserve(iri.size());
  for (unsigned char c : iri) {
    if (c < 0x20 || c == '<' || c == '>' || c == '"' || c == '{' || c == '}' ||
        c == '|' || c == '^' || c == '`' || c == '\\' || c == ' ') {
      char b[8];
      std::snprintf(b, sizeof(b), "\\u%04X", c);
      out += b;
    } else {
      out += static_cast<char>(c);
    }
  }
  return out;
}

std::string SparqlIriRef(const std::string& iri) {
  return "<" + SparqlIriEscape(iri) + ">";
}

}  // namespace

// §5.2 addFlow.
bool FlowService::AddFlow(GraphBackend* W,
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
    triples.push_back(group_detail::T_iri(flow_node, kFlowHasTransition, t_node));
    triples.push_back(group_detail::T_lit(t_node, kFlowTransitionName, t.name));
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

// §5.3 removeFlow.
bool FlowService::RemoveFlow(GraphBackend* W,
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
  if (auto stored_def =
          group_detail::FirstLiteralOf(W, flow_node, kFlowDefinition)) {
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

// §5.4 getFlows.
std::vector<FlowInfo> FlowService::GetFlows(GraphBackend* W) {
  std::vector<FlowInfo> out;
  const std::string gid = GraphId(W);
  std::set<std::string> seen;
  for (const ObjectTerm& o : group_detail::QueryObjects(W, gid, kFlowHasFlow)) {
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

// getFlow.
bool FlowService::GetFlow(GraphBackend* W,
                          const std::string& name,
                          FlowDefinition* out) {
  std::string node;
  if (!GetFlowNodeAndDef(W, name, &node, out))
    return Fail("NotFoundError");
  return Ok();
}

// §6.1 creation.
bool FlowService::InitializeInstance(GraphBackend* W,
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
  if (governance_ && !governance_->CanAddTriple(W, link, author->did).allowed)
    return Fail("NotAllowedError");
  group_detail::ScopedActive active(identity_, author_cred_id);
  if (!W->AddTriple(link))
    return Fail(W->last_error());
  return Ok();
}

// §14.1 shape→flow auto-init.
std::vector<std::string> FlowService::AutoInitInstanceForClass(
    GraphBackend* W,
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

// §6.3 getFlowState.
bool FlowService::GetFlowState(GraphBackend* W,
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

// §11.4 availableTransitions.
bool FlowService::AvailableTransitions(GraphBackend* W,
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
    TransitionCheck chk =
        CheckTransition(W, flow, t, instance_uri, author->did, *cur);
    if (chk.ok)
      out->push_back(t.name);
  }
  return Ok();
}

// §6.2 / §11.3 executeFlowTransition.
FlowTransitionResult FlowService::ExecuteFlowTransition(
    GraphBackend* W,
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
    // §6.2 step 7 — instantiate a sub-flow on the same instance, if triggered and
    // registered (its state is the flow-scoped predicate, so it does not disturb
    // the parent's state).
    if (tr->triggers_sub_flow) {
      FlowDefinition sub;
      std::string sub_node;
      if (GetFlowNodeAndDef(W, *tr->triggers_sub_flow, &sub_node, &sub)) {
        const std::string sub_pred = StatePredicate(*tr->triggers_sub_flow);
        if (!CurrentState(W, sub_pred, instance_uri)) {
          Triple sub_link =
              group_detail::T_lit(instance_uri, sub_pred, sub.initial_state);
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

// §13.4 deadline.
std::optional<std::string> FlowService::DueDeadlineTransition(
    GraphBackend* W,
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

// static — §13.2 concurrent-transition tie-break.
const std::string& FlowService::ConcurrentTransitionWinner(
    const std::string& reifier_hash_a,
    const std::string& reifier_hash_b) {
  return living_web::default_sync::FlowStateWinner(reifier_hash_a,
                                                   reifier_hash_b);
}

// ---- private helpers --------------------------------------------------------

bool FlowService::CanUpdateFlow(GraphBackend* W,
                                const std::string& author_did) {
  if (!governance_)
    return true;
  return governance_->CanPerformAction(W, kActionUpdateFlow, author_did).allowed;
}

bool FlowService::GetFlowNodeAndDef(GraphBackend* W,
                                    const std::string& name,
                                    std::string* out_node,
                                    FlowDefinition* out_def) {
  const std::string gid = GraphId(W);
  for (const ObjectTerm& o : group_detail::QueryObjects(W, gid, kFlowHasFlow)) {
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

// static
std::optional<std::string> FlowService::CurrentState(
    GraphBackend* W,
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

// static — §8.2/§8.3 the reifier timestamp on the current state link.
std::optional<std::string> FlowService::StateEntryTimestamp(
    GraphBackend* W,
    const std::string& state_pred,
    const std::string& instance,
    const std::string& state) {
  Triple link = group_detail::T_lit(instance, state_pred, state);
  std::vector<Reifier> reifs;
  if (!W->Provenance(link, &reifs) || reifs.empty())
    return std::nullopt;
  std::string best = reifs.front().timestamp;
  int64_t best_epoch = 0;
  bool have = living_web::constraint_vocab::ParseRfc3339ToEpoch(best, &best_epoch);
  for (const Reifier& r : reifs) {
    int64_t e = 0;
    if (!living_web::constraint_vocab::ParseRfc3339ToEpoch(r.timestamp, &e))
      continue;
    if (!have || e > best_epoch) {
      best = r.timestamp;
      best_epoch = e;
      have = true;
    }
  }
  return best;
}

bool FlowService::TimestampPlausible(const std::string& ts) const {
  living_web::constraint_vocab::PlausibilityInput in;
  in.t = ts;
  in.now = NowRfc3339();
  return living_web::constraint_vocab::CheckTimestampPlausibility(in).ok;
}

bool FlowService::DelayElapsed(const std::string& entry_ts,
                               int64_t need_seconds,
                               int64_t* out_seconds_left) const {
  *out_seconds_left = need_seconds;
  if (!TimestampPlausible(entry_ts))
    return false;
  int64_t entered = 0;
  if (!living_web::constraint_vocab::ParseRfc3339ToEpoch(entry_ts, &entered))
    return false;
  int64_t now = 0;
  if (!living_web::constraint_vocab::ParseRfc3339ToEpoch(NowRfc3339(), &now))
    return false;
  int64_t elapsed = now - entered;
  if (elapsed >= need_seconds) {
    *out_seconds_left = 0;
    return true;
  }
  *out_seconds_left = need_seconds - elapsed;
  return false;
}

FlowService::TransitionCheck FlowService::CheckTransition(
    GraphBackend* W,
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
    auto ts =
        StateEntryTimestamp(W, StatePredicate(flow.name), instance, current_state);
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

bool FlowService::RoleAllowed(GraphBackend* W,
                              const FlowTransition& tr,
                              const std::string& author_did) {
  if (!tr.role)
    return true;
  if (!governance_)
    return true;
  return governance_->CanPerformAction(W, *tr.role, author_did).allowed;
}

bool FlowService::EvalGuard(GraphBackend* W,
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
  return living_web::DecodeSparqlBoolean(r.payload, out, &err);
}

// static — §7.4.
bool FlowService::GuardIsSafe(const std::string& guard) {
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

// static
bool FlowService::ContainsWord(const std::string& hay, const std::string& word) {
  size_t pos = 0;
  while ((pos = hay.find(word, pos)) != std::string::npos) {
    const bool left_ok = pos == 0 || !IsWordChar(hay[pos - 1]);
    const size_t end = pos + word.size();
    const bool right_ok = end >= hay.size() || !IsWordChar(hay[end]);
    if (left_ok && right_ok)
      return true;
    pos = end;
  }
  return false;
}

// static
bool FlowService::IsWordChar(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '_';
}

// static
std::string FlowService::SubstituteThis(const std::string& guard,
                                        const std::string& instance) {
  const std::string ref = SparqlIriRef(instance);
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
bool FlowService::ApplyActions(GraphBackend* W,
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

// static — §4.4 object resolution.
ObjectTerm FlowService::ResolveActionObject(FlowActionKind kind,
                                            const std::string& raw,
                                            const std::string& agent_did) {
  if (raw == kFlowObjectNow) {
    LiteralValue lv;
    lv.lexical = NowRfc3339();
    lv.datatype = living_web::kXsdDateTime;
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
  lv.datatype = living_web::kXsdString;
  return ObjectTerm::Literal(lv);
}

// static
bool FlowService::HasUriScheme(const std::string& s) {
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

// static
FlowInfo FlowService::ToInfo(const FlowDefinition& def) {
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

}  // namespace content
