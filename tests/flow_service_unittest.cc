// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for the Spec 10 browser-process flow port (content::FlowService)
// plus the shared Chromium-independent flow-definition core
// (content/browser/flows/flow_definition.{h,cc}) — Graph Flows. These exercise
// the same normative behaviour as the standalone Flow_* conformance harness, but
// against the browser port bound to content::DIDKeyProvider, content::
// GovernanceBackend and content::GraphBackendManager, so the full-tree
// content_unittests build has direct coverage of the §5.2 registration +
// storage, the §5.2/§11.2 updateFlow authorisation gate, the §6.1 instance
// creation + §6.3 state query, the §6.2 eight-step transition lifecycle (with its
// §7 guard, §8 temporal, and §9/§14.3 role checks), the §4.4 action execution,
// the §10 sub-flow instantiation, the §11.4 availableTransitions projection, the
// §13.4 deadline detection, and the §13.2 concurrent-transition tie-break. The
// byte-critical core (the §4 grammar, the §8.1 ISO 8601 durations, the §5.2
// `flow://` vocabulary, and the §5.1 JCS canonicalisation) is shared verbatim
// with the standalone harness, so the flow parsed, the duration decoded, and the
// definition canonicalised never diverge between the two build worlds.

#include "content/browser/flows/flow_service.h"

#include <optional>
#include <string>
#include <vector>

#include "content/browser/did/did_key_provider.h"
#include "content/browser/did/group_backend.h"
#include "content/browser/did/group_backend_manager.h"
#include "content/browser/flows/flow_definition.h"
#include "content/browser/governance/governance_backend.h"
#include "content/browser/graph/graph_backend.h"
#include "content/browser/graph/graph_backend_manager.h"
#include "content/browser/graph/rdf_serialization.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace content {
namespace {

// ---- §4 flow-definition JSON fixtures (identical to the standalone harness) --

// The minimal two-state Ticket flow: one non-guarded transition into a terminal.
constexpr char kTicketFlow[] = R"JSON({
  "name": "Ticket",
  "namespace": "https://example.org/flows/ticket",
  "appliesTo": "https://example.org/Ticket",
  "initialState": "open",
  "states": [
    {"name": "open"},
    {"name": "closed", "isTerminal": true}
  ],
  "transitions": [
    {"name": "close", "fromState": "open", "toState": "closed"}
  ]
})JSON";

// A §7 SPARQL-ASK guard: the transition fires only once the instance is marked
// ready. The IRIs carry no §7.4-forbidden keyword, so the guard is accepted.
constexpr char kReviewFlow[] = R"JSON({
  "name": "Review",
  "namespace": "https://example.org/flows/review",
  "appliesTo": "https://example.org/Doc",
  "initialState": "draft",
  "states": [
    {"name": "draft"},
    {"name": "published"}
  ],
  "transitions": [
    {"name": "publish", "fromState": "draft", "toState": "published",
     "guard": "ASK { $this <https://example.org/ready> <https://example.org/yes> }",
     "guardDescription": "the document must be marked ready"}
  ]
})JSON";

// Two §8 minDelay transitions out of one state: PT0S is immediately eligible,
// PT1H is not.
constexpr char kTimerFlow[] = R"JSON({
  "name": "Timer",
  "namespace": "https://example.org/flows/timer",
  "appliesTo": "https://example.org/Timer",
  "initialState": "waiting",
  "states": [
    {"name": "waiting"},
    {"name": "elapsed"}
  ],
  "transitions": [
    {"name": "advanceNow", "fromState": "waiting", "toState": "elapsed",
     "temporal": {"minDelay": "PT0S"}},
    {"name": "advanceLater", "fromState": "waiting", "toState": "elapsed",
     "temporal": {"minDelay": "PT1H"}}
  ]
})JSON";

// A §13.4 deadline transition: maxDelay PT0S with onDeadline auto-transition, so
// the runtime should fire it the moment the instance enters the source state.
constexpr char kDeadlineFlow[] = R"JSON({
  "name": "Deadline",
  "namespace": "https://example.org/flows/deadline",
  "appliesTo": "https://example.org/Task",
  "initialState": "active",
  "states": [
    {"name": "active"},
    {"name": "expired"}
  ],
  "transitions": [
    {"name": "expire", "fromState": "active", "toState": "expired",
     "temporal": {"maxDelay": "PT0S", "onDeadline": "auto-transition"}}
  ]
})JSON";

// A transition carrying §4.4 setSingleTarget actions with the "now" and "agent"
// object sentinels.
constexpr char kActionedFlow[] = R"JSON({
  "name": "Actioned",
  "namespace": "https://example.org/flows/actioned",
  "appliesTo": "https://example.org/Item",
  "initialState": "new",
  "states": [
    {"name": "new"},
    {"name": "done"}
  ],
  "transitions": [
    {"name": "finish", "fromState": "new", "toState": "done",
     "actions": [
       {"type": "flow://actions/setSingleTarget", "subject": "this",
        "predicate": "https://example.org/updatedAt", "object": "now"},
       {"type": "flow://actions/setSingleTarget", "subject": "this",
        "predicate": "https://example.org/updatedBy", "object": "agent"}
     ]}
  ]
})JSON";

// A §10 composite: the parent's "begin" transition triggers the "Shipment"
// sub-flow on the same instance.
constexpr char kParentFlow[] = R"JSON({
  "name": "Parent",
  "namespace": "https://example.org/flows/parent",
  "appliesTo": "https://example.org/Order",
  "initialState": "created",
  "states": [
    {"name": "created"},
    {"name": "processing"}
  ],
  "transitions": [
    {"name": "begin", "fromState": "created", "toState": "processing",
     "triggersSubFlow": "Shipment"}
  ]
})JSON";

constexpr char kShipmentFlow[] = R"JSON({
  "name": "Shipment",
  "namespace": "https://example.org/flows/shipment",
  "appliesTo": "https://example.org/Order",
  "initialState": "packing",
  "states": [
    {"name": "packing"},
    {"name": "delivered", "isTerminal": true}
  ],
  "transitions": [
    {"name": "ship", "fromState": "packing", "toState": "delivered"}
  ]
})JSON";

// A transition bearing a §9 role. In open mode the role requirement is inert.
constexpr char kRoleFlow[] = R"JSON({
  "name": "Roled",
  "namespace": "https://example.org/flows/roled",
  "appliesTo": "https://example.org/Thing",
  "initialState": "start",
  "states": [
    {"name": "start"},
    {"name": "finish"}
  ],
  "transitions": [
    {"name": "go", "fromState": "start", "toState": "finish",
     "role": "approveThing"}
  ]
})JSON";

// ---- §4/§8 flow-definition core (flow_definition.{h,cc}) --------------------
//
// The pure core is shared verbatim with the standalone harness; these mirror the
// standalone Flow_ core tests to prove the content build links against the same
// bytes.

TEST(FlowCoreTest, ParseIso8601Duration) {
  int64_t s = -1;
  EXPECT_TRUE(living_web::flows::ParseIso8601Duration("PT1H", &s));
  EXPECT_EQ(s, int64_t(3600));
  EXPECT_TRUE(living_web::flows::ParseIso8601Duration("PT0S", &s));
  EXPECT_EQ(s, int64_t(0));
  EXPECT_TRUE(living_web::flows::ParseIso8601Duration("P1D", &s));
  EXPECT_EQ(s, int64_t(86400));
  EXPECT_TRUE(living_web::flows::ParseIso8601Duration("PT1M", &s));
  EXPECT_EQ(s, int64_t(60));
  EXPECT_TRUE(living_web::flows::ParseIso8601Duration("PT1H30M", &s));
  EXPECT_EQ(s, int64_t(5400));
  // Empty durations and malformations are rejected.
  EXPECT_FALSE(living_web::flows::ParseIso8601Duration("P", &s));
  EXPECT_FALSE(living_web::flows::ParseIso8601Duration("PT", &s));
  EXPECT_FALSE(living_web::flows::ParseIso8601Duration("banana", &s));
}

TEST(FlowCoreTest, NodeIriConvention) {
  EXPECT_EQ(living_web::flows::FlowNodeIri("Ticket"),
            std::string("flow://Ticket"));
  EXPECT_EQ(living_web::flows::FlowStateNodeIri("Ticket", "open"),
            std::string("flow://Ticket/state/open"));
  EXPECT_EQ(living_web::flows::FlowTransitionNodeIri("Ticket", "close"),
            std::string("flow://Ticket/transition/close"));
}

TEST(FlowCoreTest, OnDeadlineTokens) {
  EXPECT_TRUE(living_web::flows::ParseOnDeadline("auto-transition") ==
              living_web::flows::OnDeadline::kAutoTransition);
  EXPECT_TRUE(living_web::flows::ParseOnDeadline("error-state") ==
              living_web::flows::OnDeadline::kErrorState);
  EXPECT_TRUE(living_web::flows::ParseOnDeadline("notify") ==
              living_web::flows::OnDeadline::kNotify);
  EXPECT_FALSE(living_web::flows::ParseOnDeadline("bogus").has_value());
  EXPECT_EQ(
      living_web::flows::OnDeadlineToken(
          living_web::flows::OnDeadline::kAutoTransition),
      std::string("auto-transition"));
  EXPECT_EQ(living_web::flows::OnDeadlineToken(
                living_web::flows::OnDeadline::kNone),
            std::string());
}

TEST(FlowCoreTest, ParseDefinitionValidatesGrammar) {
  living_web::flows::FlowDefinition def;
  std::string err;
  EXPECT_TRUE(living_web::flows::ParseFlowDefinition(kTicketFlow, &def, &err));
  EXPECT_EQ(def.name, std::string("Ticket"));
  EXPECT_EQ(def.initial_state, std::string("open"));
  EXPECT_EQ(def.states.size(), size_t(2));
  EXPECT_EQ(def.transitions.size(), size_t(1));
  EXPECT_TRUE(living_web::flows::FindState(def, "closed") != nullptr);
  EXPECT_TRUE(living_web::flows::FindState(def, "closed")->is_terminal);
  EXPECT_TRUE(living_web::flows::FindTransition(def, "close") != nullptr);

  // initialState MUST name a defined state.
  const char kBadInitial[] =
      R"({"name":"F","namespace":"n","appliesTo":"a","initialState":"nope",
          "states":[{"name":"s"}],"transitions":[]})";
  EXPECT_FALSE(
      living_web::flows::ParseFlowDefinition(kBadInitial, &def, &err));
  // No transition may leave a terminal state (§4.2/§6.4).
  const char kLeavesTerminal[] =
      R"({"name":"F","namespace":"n","appliesTo":"a","initialState":"s",
          "states":[{"name":"s","isTerminal":true},{"name":"t"}],
          "transitions":[{"name":"go","fromState":"s","toState":"t"}]})";
  EXPECT_FALSE(
      living_web::flows::ParseFlowDefinition(kLeavesTerminal, &def, &err));
  // Duplicate state names are rejected.
  const char kDupState[] =
      R"({"name":"F","namespace":"n","appliesTo":"a","initialState":"s",
          "states":[{"name":"s"},{"name":"s"}],"transitions":[]})";
  EXPECT_FALSE(living_web::flows::ParseFlowDefinition(kDupState, &def, &err));
}

TEST(FlowCoreTest, ActionKeyAliases) {
  // The §17 source/target aliases parse to the canonical subject/object fields.
  const char kAlias[] =
      R"({"name":"F","namespace":"n","appliesTo":"a","initialState":"s",
          "states":[{"name":"s"},{"name":"t"}],
          "transitions":[{"name":"go","fromState":"s","toState":"t",
            "actions":[{"type":"flow://actions/setSingleTarget",
              "source":"this","predicate":"p","target":"x"}]}]})";
  living_web::flows::FlowDefinition def;
  std::string err;
  EXPECT_TRUE(living_web::flows::ParseFlowDefinition(kAlias, &def, &err));
  EXPECT_EQ(def.transitions.size(), size_t(1));
  EXPECT_EQ(def.transitions[0].actions.size(), size_t(1));
  EXPECT_EQ(def.transitions[0].actions[0].subject, std::string("this"));
  EXPECT_EQ(def.transitions[0].actions[0].object, std::string("x"));
  EXPECT_TRUE(def.transitions[0].actions[0].kind ==
              living_web::flows::FlowActionKind::kSetSingleTarget);
}

TEST(FlowCoreTest, CanonicalizeStableAcrossKeyOrder) {
  auto c1 = living_web::flows::CanonicalizeFlowJson(
      R"({"name":"F","namespace":"n"})");
  auto c2 = living_web::flows::CanonicalizeFlowJson(
      R"({"namespace":"n","name":"F"})");
  EXPECT_TRUE(c1.has_value());
  EXPECT_TRUE(c2.has_value());
  EXPECT_EQ(*c1, *c2);  // JCS sorts keys → order-independent
  EXPECT_EQ(*c1, std::string(R"({"name":"F","namespace":"n"})"));
  // Malformed JSON has no canonical form.
  EXPECT_FALSE(
      living_web::flows::CanonicalizeFlowJson("{not json").has_value());
}

// ---- fixture ---------------------------------------------------------------

// A flow fixture mirroring the standalone GovFixture: a group W (a graph bearing
// a did:graph whose DID document holds the group key in every capability section)
// plus a GovernanceBackend and a FlowService over the same DIDKeyProvider /
// GraphBackendManager. Each write is authored by the group's constitutional key
// (gcred_, whose did == W's did:graph), so an open-mode graph authorises
// registration out of the box and the enforced-mode tests can mint a root that
// grants (or withholds) the §11.2 updateFlow action.
class FlowServiceTest : public testing::Test {
 protected:
  FlowServiceTest()
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
  FlowService svc_;
  std::unique_ptr<GroupBackend> group_;
  std::string gcred_;
};

// ---- §5 service: registration, storage, listing ----------------------------

TEST_F(FlowServiceTest, AddFlowStoresAndLists) {
  // Open mode: no capability constraint installed, so registration is allowed.
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));

  auto flows_out = svc_.GetFlows(W());
  EXPECT_EQ(flows_out.size(), size_t(1));
  EXPECT_EQ(flows_out[0].name, std::string("Ticket"));
  EXPECT_EQ(flows_out[0].applies_to,
            std::string("https://example.org/Ticket"));
  EXPECT_EQ(flows_out[0].initial_state, std::string("open"));
  EXPECT_EQ(flows_out[0].states.size(), size_t(2));
  EXPECT_EQ(flows_out[0].states[0], std::string("open"));
  EXPECT_EQ(flows_out[0].transitions.size(), size_t(1));
  EXPECT_EQ(flows_out[0].transitions[0], std::string("close"));
}

TEST_F(FlowServiceTest, AddFlowNameMismatchConstraintError) {
  // The registration name MUST equal the definition's own name (§4.1/§5.1).
  EXPECT_FALSE(svc_.AddFlow(W(), "Wrong", kTicketFlow, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("ConstraintError"));
}

TEST_F(FlowServiceTest, AddFlowMalformedSyntaxError) {
  EXPECT_FALSE(svc_.AddFlow(W(), "Bad", "{not a flow", gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("SyntaxError"));
}

TEST_F(FlowServiceTest, AddFlowDuplicateConstraintError) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  EXPECT_FALSE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("ConstraintError"));
}

TEST_F(FlowServiceTest, AddFlowUnknownAuthorInvalidState) {
  EXPECT_FALSE(svc_.AddFlow(W(), "Ticket", kTicketFlow, "urn:uuid:nope"));
  EXPECT_EQ(svc_.last_error(), std::string("InvalidStateError"));
}

TEST_F(FlowServiceTest, GetFlowResolvesDefinition) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  living_web::flows::FlowDefinition def;
  EXPECT_TRUE(svc_.GetFlow(W(), "Ticket", &def));
  EXPECT_EQ(def.name, std::string("Ticket"));
  EXPECT_EQ(def.states.size(), size_t(2));
  EXPECT_EQ(def.transitions.size(), size_t(1));
  // An unregistered name is a NotFoundError.
  EXPECT_FALSE(svc_.GetFlow(W(), "Ghost", &def));
  EXPECT_EQ(svc_.last_error(), std::string("NotFoundError"));
}

TEST_F(FlowServiceTest, RemoveFlow) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  EXPECT_EQ(svc_.GetFlows(W()).size(), size_t(1));
  EXPECT_TRUE(svc_.RemoveFlow(W(), "Ticket", gcred_));
  EXPECT_EQ(svc_.GetFlows(W()).size(), size_t(0));
  // Removing a flow that was never registered is a no-op success.
  EXPECT_TRUE(svc_.RemoveFlow(W(), "Ghost", gcred_));
}

// ---- §6 instance lifecycle -------------------------------------------------

TEST_F(FlowServiceTest, InitializeAndGetState) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  const std::string inst = "urn:uuid:ticket-1";

  EXPECT_TRUE(svc_.InitializeInstance(W(), "Ticket", inst, gcred_));
  std::string state;
  EXPECT_TRUE(svc_.GetFlowState(W(), "Ticket", inst, &state));
  EXPECT_EQ(state, std::string("open"));

  // Re-initialising the same instance for the same flow is an InvalidStateError.
  EXPECT_FALSE(svc_.InitializeInstance(W(), "Ticket", inst, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("InvalidStateError"));

  // An instance never entered into the flow has no state.
  EXPECT_FALSE(svc_.GetFlowState(W(), "Ticket", "urn:uuid:absent", &state));
  EXPECT_EQ(svc_.last_error(), std::string("NotFoundError"));

  // Initialising against an unregistered flow is a NotFoundError.
  EXPECT_FALSE(svc_.InitializeInstance(W(), "Ghost", inst, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("NotFoundError"));
}

// ---- §6.2 / §11.3 executeFlowTransition ------------------------------------

TEST_F(FlowServiceTest, ExecuteHappyPath) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  const std::string inst = "urn:uuid:ticket-happy";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Ticket", inst, gcred_));

  FlowTransitionResult r =
      svc_.ExecuteFlowTransition(W(), "Ticket", inst, "close", gcred_);
  EXPECT_TRUE(r.success);
  EXPECT_TRUE(r.new_state.has_value());
  EXPECT_EQ(*r.new_state, std::string("closed"));

  std::string state;
  EXPECT_TRUE(svc_.GetFlowState(W(), "Ticket", inst, &state));
  EXPECT_EQ(state, std::string("closed"));
}

TEST_F(FlowServiceTest, ExecuteWrongStateAndUnknownTransition) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  const std::string inst = "urn:uuid:ticket-wrong";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Ticket", inst, gcred_));
  EXPECT_TRUE(
      svc_.ExecuteFlowTransition(W(), "Ticket", inst, "close", gcred_)
          .success);

  // Firing "close" again: the instance is now in the terminal "closed" state,
  // not the transition's "open" fromState.
  FlowTransitionResult again =
      svc_.ExecuteFlowTransition(W(), "Ticket", inst, "close", gcred_);
  EXPECT_FALSE(again.success);
  EXPECT_EQ(svc_.last_error(), std::string("InvalidStateError"));

  // An unknown transition name is a NotFoundError.
  FlowTransitionResult unknown =
      svc_.ExecuteFlowTransition(W(), "Ticket", inst, "reopen", gcred_);
  EXPECT_FALSE(unknown.success);
  EXPECT_EQ(svc_.last_error(), std::string("NotFoundError"));
}

TEST_F(FlowServiceTest, GuardBlocksThenAllows) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Review", kReviewFlow, gcred_));
  const std::string inst = "urn:uuid:doc-1";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Review", inst, gcred_));

  // The guard does not hold yet: the instance is not marked ready.
  FlowTransitionResult blocked =
      svc_.ExecuteFlowTransition(W(), "Review", inst, "publish", gcred_);
  EXPECT_FALSE(blocked.success);
  EXPECT_TRUE(blocked.reason.has_value());
  EXPECT_TRUE(blocked.guard_description.has_value());

  // Mark the instance ready (a governed write), then the guard holds.
  {
    group_detail::ScopedActive active(&identity_, gcred_);
    EXPECT_TRUE(W()->AddTriple(group_detail::T_iri(
        inst, "https://example.org/ready", "https://example.org/yes")));
  }
  FlowTransitionResult allowed =
      svc_.ExecuteFlowTransition(W(), "Review", inst, "publish", gcred_);
  EXPECT_TRUE(allowed.success);
  EXPECT_EQ(*allowed.new_state, std::string("published"));
}

TEST_F(FlowServiceTest, MinDelayGate) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Timer", kTimerFlow, gcred_));

  // A PT1H minDelay cannot have elapsed on a just-initialised instance.
  const std::string slow = "urn:uuid:timer-slow";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Timer", slow, gcred_));
  FlowTransitionResult later =
      svc_.ExecuteFlowTransition(W(), "Timer", slow, "advanceLater", gcred_);
  EXPECT_FALSE(later.success);
  EXPECT_TRUE(later.seconds_until_allowed.has_value());
  EXPECT_TRUE(std::stoll(*later.seconds_until_allowed) > 0);

  // A PT0S minDelay is satisfied immediately.
  const std::string fast = "urn:uuid:timer-fast";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Timer", fast, gcred_));
  FlowTransitionResult now =
      svc_.ExecuteFlowTransition(W(), "Timer", fast, "advanceNow", gcred_);
  EXPECT_TRUE(now.success);
  EXPECT_EQ(*now.new_state, std::string("elapsed"));
}

TEST_F(FlowServiceTest, ActionsSetSingleTarget) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Actioned", kActionedFlow, gcred_));
  const std::string inst = "urn:uuid:item-1";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Actioned", inst, gcred_));
  EXPECT_TRUE(
      svc_.ExecuteFlowTransition(W(), "Actioned", inst, "finish", gcred_)
          .success);

  // "now" resolves to an xsd:dateTime literal.
  auto at = group_detail::QueryObjects(W(), inst,
                                       "https://example.org/updatedAt");
  EXPECT_EQ(at.size(), size_t(1));
  EXPECT_TRUE(at[0].is_literal());
  EXPECT_EQ(at[0].literal->datatype, std::string(living_web::kXsdDateTime));

  // "agent" resolves to the firing agent's DID (an IRI term).
  auto by = group_detail::QueryObjects(W(), inst,
                                       "https://example.org/updatedBy");
  EXPECT_EQ(by.size(), size_t(1));
  EXPECT_FALSE(by[0].is_literal());
  EXPECT_EQ(by[0].iri_or_bnode, Wdid());
}

TEST_F(FlowServiceTest, AvailableTransitions) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Timer", kTimerFlow, gcred_));
  const std::string inst = "urn:uuid:timer-avail";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Timer", inst, gcred_));

  // Only the PT0S transition is currently firable.
  std::vector<std::string> avail;
  EXPECT_TRUE(svc_.AvailableTransitions(W(), "Timer", inst, gcred_, &avail));
  EXPECT_EQ(avail.size(), size_t(1));
  EXPECT_EQ(avail[0], std::string("advanceNow"));

  // After advancing, the terminal-free "elapsed" state has no exits.
  EXPECT_TRUE(
      svc_.ExecuteFlowTransition(W(), "Timer", inst, "advanceNow", gcred_)
          .success);
  EXPECT_TRUE(svc_.AvailableTransitions(W(), "Timer", inst, gcred_, &avail));
  EXPECT_EQ(avail.size(), size_t(0));
}

TEST_F(FlowServiceTest, DueDeadlineTransition) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Deadline", kDeadlineFlow, gcred_));
  const std::string inst = "urn:uuid:task-1";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Deadline", inst, gcred_));

  // The PT0S maxDelay deadline is due immediately on entry.
  auto due = svc_.DueDeadlineTransition(W(), "Deadline", inst);
  EXPECT_TRUE(due.has_value());
  EXPECT_EQ(*due, std::string("expire"));

  // The runtime fires it (system-authored); the instance advances.
  EXPECT_TRUE(
      svc_.ExecuteFlowTransition(W(), "Deadline", inst, *due, gcred_)
          .success);
  std::string state;
  EXPECT_TRUE(svc_.GetFlowState(W(), "Deadline", inst, &state));
  EXPECT_EQ(state, std::string("expired"));

  // No further deadline is due from the terminal-free "expired" state.
  EXPECT_FALSE(svc_.DueDeadlineTransition(W(), "Deadline", inst).has_value());
}

TEST_F(FlowServiceTest, SubFlowInstantiation) {
  EXPECT_TRUE(svc_.AddFlow(W(), "Parent", kParentFlow, gcred_));
  EXPECT_TRUE(svc_.AddFlow(W(), "Shipment", kShipmentFlow, gcred_));
  const std::string inst = "urn:uuid:order-1";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Parent", inst, gcred_));

  // Firing "begin" advances the parent AND instantiates the sub-flow.
  EXPECT_TRUE(
      svc_.ExecuteFlowTransition(W(), "Parent", inst, "begin", gcred_)
          .success);

  // Parent and sub-flow states coexist on one instance via flow-scoped
  // predicates (the composite-flow amendment) — they do not collide.
  std::string parent_state;
  EXPECT_TRUE(svc_.GetFlowState(W(), "Parent", inst, &parent_state));
  EXPECT_EQ(parent_state, std::string("processing"));
  std::string sub_state;
  EXPECT_TRUE(svc_.GetFlowState(W(), "Shipment", inst, &sub_state));
  EXPECT_EQ(sub_state, std::string("packing"));

  // The sub-flow drives independently to its terminal state.
  EXPECT_TRUE(
      svc_.ExecuteFlowTransition(W(), "Shipment", inst, "ship", gcred_)
          .success);
  EXPECT_TRUE(svc_.GetFlowState(W(), "Shipment", inst, &sub_state));
  EXPECT_EQ(sub_state, std::string("delivered"));
  // The parent state is untouched by the sub-flow's progress.
  EXPECT_TRUE(svc_.GetFlowState(W(), "Parent", inst, &parent_state));
  EXPECT_EQ(parent_state, std::string("processing"));
}

// ---- §14.1 shape→flow auto-init (createShapeInstance) ----------------------

TEST_F(FlowServiceTest, AutoInitForShapeClass) {
  // Two flows bound to the SAME §4.1 target class, one bound to another class.
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  EXPECT_TRUE(svc_.AddFlow(W(), "Review", kReviewFlow, gcred_));  // Doc class
  constexpr char kTicketSla[] = R"JSON({
    "name": "TicketSla",
    "namespace": "https://example.org/flows/ticket-sla",
    "appliesTo": "https://example.org/Ticket",
    "initialState": "green",
    "states": [{"name": "green"}, {"name": "breached"}],
    "transitions": [
      {"name": "breach", "fromState": "green", "toState": "breached"}
    ]
  })JSON";
  EXPECT_TRUE(svc_.AddFlow(W(), "TicketSla", kTicketSla, gcred_));

  const std::string inst = "urn:uuid:ticket-instance-1";
  // Auto-init for the Ticket class applies EVERY Ticket-class flow (§14.1) and
  // leaves the Doc-class Review flow untouched.
  std::vector<std::string> got =
      svc_.AutoInitInstanceForClass(W(), "https://example.org/Ticket", inst,
                                    gcred_);
  EXPECT_EQ(got.size(), size_t(2));
  bool has_ticket = false, has_sla = false;
  for (const std::string& n : got) {
    if (n == "Ticket")
      has_ticket = true;
    if (n == "TicketSla")
      has_sla = true;
  }
  EXPECT_TRUE(has_ticket);
  EXPECT_TRUE(has_sla);

  // Each initialised flow now carries its own §4.2 initialState on the instance,
  // flow-scoped so the two states coexist (the composite-flow amendment).
  std::string state;
  EXPECT_TRUE(svc_.GetFlowState(W(), "Ticket", inst, &state));
  EXPECT_EQ(state, std::string("open"));
  EXPECT_TRUE(svc_.GetFlowState(W(), "TicketSla", inst, &state));
  EXPECT_EQ(state, std::string("green"));

  // The Doc-class flow was filtered out — the instance never entered it.
  EXPECT_FALSE(svc_.GetFlowState(W(), "Review", inst, &state));

  // Idempotent: a second auto-init initialises nothing (every matching flow
  // already carries a state → InitializeInstance InvalidStateError, swallowed)
  // and reports no error. This is what lets §14.1 coexist with a §10 sub-flow
  // instantiated on the same instance.
  std::vector<std::string> again =
      svc_.AutoInitInstanceForClass(W(), "https://example.org/Ticket", inst,
                                    gcred_);
  EXPECT_TRUE(again.empty());
  EXPECT_TRUE(svc_.last_error().empty());

  // A class no flow targets initialises nothing, no error.
  std::vector<std::string> none =
      svc_.AutoInitInstanceForClass(W(), "https://example.org/Unbound", inst,
                                    gcred_);
  EXPECT_TRUE(none.empty());
  EXPECT_TRUE(svc_.last_error().empty());
}

TEST_F(FlowServiceTest, RoleIgnoredInOpenMode) {
  // Open mode: §9 role requirements are inert (§14.3).
  EXPECT_TRUE(svc_.AddFlow(W(), "Roled", kRoleFlow, gcred_));
  const std::string inst = "urn:uuid:thing-1";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Roled", inst, gcred_));
  FlowTransitionResult r =
      svc_.ExecuteFlowTransition(W(), "Roled", inst, "go", gcred_);
  EXPECT_TRUE(r.success);
  EXPECT_EQ(*r.new_state, std::string("finish"));
}

TEST_F(FlowServiceTest, ConcurrentTransitionWinner) {
  // §13.2 reuses the DEFAULT-SYNC-MODULE §8.4 tie-break: smaller reifier hash.
  const std::string a = "00aa";
  const std::string b = "00bb";
  EXPECT_EQ(FlowService::ConcurrentTransitionWinner(a, b), a);
  EXPECT_EQ(FlowService::ConcurrentTransitionWinner(b, a), a);
}

// ---- §11.2 updateFlow authorisation under enforcement ----------------------

TEST_F(FlowServiceTest, UpdateFlowRequiredUnderEnforcement) {
  BootstrapEnforced();  // root holds the 8 core actions, NOT updateFlow
  EXPECT_FALSE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  EXPECT_EQ(svc_.last_error(), std::string("NotAllowedError"));
}

TEST_F(FlowServiceTest, UpdateFlowGrantedUnderEnforcement) {
  // Grant updateFlow (+ the write actions initialise/execute need and the
  // updateGovernance BootstrapEnforced's SetEnforcementMode requires).
  BootstrapEnforced(std::vector<std::string>{"createLink", "removeLink",
                                             "updateFlow", "updateGovernance"});
  EXPECT_TRUE(svc_.AddFlow(W(), "Ticket", kTicketFlow, gcred_));
  const std::string inst = "urn:uuid:ticket-enforced";
  EXPECT_TRUE(svc_.InitializeInstance(W(), "Ticket", inst, gcred_));
  EXPECT_TRUE(
      svc_.ExecuteFlowTransition(W(), "Ticket", inst, "close", gcred_)
          .success);
}

}  // namespace
}  // namespace content
