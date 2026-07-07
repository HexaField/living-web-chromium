# Spec Compliance Matrix

Alignment between the
[Living Web specifications](https://github.com/HexaField/w3c-living-web-proposals)
and this Chromium implementation.

**Legend:** ✅ Implemented & tested · 🔀 In review (PR open) · 🔲 Not yet started

The specs are implemented one-per-branch in dependency order (01 → 06, then
07–10), each independently auditable and landed as a staggered pull request.
This `main` branch is the base — no spec code — so every row below is pending
until its branch lands. **Each spec PR adds its own detailed compliance section
to this file** and flips its row to ✅.

---

## Specification index

| # | Specification | Primary surface | Branch | Status |
|---|--------------|-----------------|--------|--------|
| 01 | [Decentralised Identity](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/01_decentralised-identity-web-platform.md) | `navigator.credentials` + `DIDCredential` | `spec-01-identity` | 🔀 |
| 02 | [Personal Linked Data Graphs](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/02_personal-linked-data-graphs.md) | `navigator.graph`, `PersonalGraph` | `spec-02-graphs` | 🔲 |
| 03 | [Decentralised Group Identity](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/03_decentralised-group-identity.md) | Group DIDs | `spec-03-group-identity` | 🔲 |
| 04 | [Graph Capability Framework](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/04_graph-capability-framework.md) | ZCAP-LD capabilities | `spec-04-capabilities` | 🔲 |
| 05 | [Context Sync Protocol](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/05_context-sync-protocol.md) | `SharedGraph`, `graph.join()` | `spec-05-sync` | 🔲 |
| 06 | [Sync Module Architecture](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/06_sync-module-architecture.md) | Pluggable sync modules | `spec-06-sync-modules` | 🔲 |
| 07 | [Dynamic Graph Shape Validation](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/07_dynamic-graph-shape-validation.md) | `addShape()`, shape instances | `spec-07-shapes` | 🔲 |
| 08 | [Governance Constraint Vocabulary](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/08_governance-constraint-vocabulary.md) | `canAddTriple()`, constraints | `spec-08-governance` | 🔲 |
| 09 | [Default Sync Module](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/09_default-sync-module.md) | CRDT + MLS transport | `spec-09-default-sync` | 🔲 |
| 10 | [Graph Flows](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/10_graph-flows.md) | Reactive flow bindings | `spec-10-flows` | 🔲 |

---

## Build worlds

This repository is an **overlay**, not a full Chromium checkout. Two build worlds
exist:

- **Standalone harness** (`standalone/`, `tests/`, CMake) — the locally buildable
  and testable core. Each spec links its real backend logic (Ed25519 via the
  bundled `ed25519` library, JCS canonicalisation, the did:key codec, the triple
  store, and so on) and runs the normative behaviour under `living_web_tests`.
- **Renderer overlay** (`third_party/blink/…`, `content/browser/…`, `mojo/…`) — a
  reviewed mirror that compiles **only inside a full Chromium tree**. It is kept
  byte-faithful to the standalone core but is not compiled by the local CMake
  build.

When a change touches only the overlay, "green" means the standalone harness
still passes and the overlay has been reviewed against it — it does not mean the
overlay was locally compiled.
