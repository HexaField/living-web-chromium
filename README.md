# Living Web — Chromium Implementation

Native browser implementation of the [Living Web specifications](https://github.com/HexaField/w3c-living-web-proposals) for Chromium. Adds a local-first semantic graph store, decentralised identity, peer-to-peer sync, shape-driven CRUD, and governance to the web platform.

## Spec Status

| # | Specification | API Surface | Status |
|---|--------------|-------------|--------|
| 01 | [Personal Linked Data Graphs](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/01_personal-linked-data-graphs.md) | `navigator.graph`, `PersonalGraph` | ⚠️ Partial — IDL + C++ stubs |
| 02 | [Decentralised Identity](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/02_decentralised-identity-web-platform.md) | `navigator.credentials` + `DIDCredential` | 🔲 Planned — backend ready, IDL pending |
| 03 | [P2P Graph Sync](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/03_p2p-graph-sync.md) | `SharedGraph`, `graph.join()` | ⚠️ Partial — IDL + C++ stubs |
| 04 | [Dynamic Shape Validation](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/04_dynamic-graph-shape-validation.md) | `addShape()`, `createShapeInstance()`, etc. | ⚠️ Partial — IDL + C++ stubs |
| 05 | [Graph Governance](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/05_graph-governance.md) | `canAddTriple()`, `constraintsFor()` | ⚠️ Partial — IDL + C++ stubs |

Full API-by-API tracking: **[SPEC_COMPLIANCE.md](SPEC_COMPLIANCE.md)**

## Architecture

```
Renderer (Blink)                         Browser Process
┌────────────────────────┐              ┌──────────────────────────────┐
│ third_party/blink/     │              │ content/browser/             │
│  renderer/modules/     │              │                              │
│   graph/               │── Mojo ──→  │  graph/      (triple store)  │
│    navigator_graph.*   │              │  did/        (DID keys)      │
│    personal_graph.*    │              │  graph_sync/ (P2P sync)      │
│    shared_graph.*      │              │  graph_governance/ (rules)   │
│                        │←─ Mojo ───  │                              │
└────────────────────────┘              └──────────────────────────────┘
```

The renderer exposes Web IDL interfaces that communicate via Mojo IPC to browser-process backends. All methods are currently stubs that reject with `NotSupportedError: Not yet implemented`.

## Quick Start

### 1. Clone

```bash
git clone https://github.com/HexaField/living-web-chromium.git
```

### 2. Integrate into Chromium

```bash
# Check out Chromium (see https://chromium.googlesource.com/chromium/src/+/main/docs/get_the_code.md)
# Then copy overlay files:
cp -r third_party/blink/renderer/modules/graph/ ~/chromium/src/third_party/blink/renderer/modules/graph/
cp -r content/browser/graph/ ~/chromium/src/content/browser/graph/
cp -r content/browser/did/ ~/chromium/src/content/browser/did/
cp -r content/browser/graph_sync/ ~/chromium/src/content/browser/graph_sync/
cp -r content/browser/graph_governance/ ~/chromium/src/content/browser/graph_governance/
cp -r mojo/public/mojom/graph/ ~/chromium/src/mojo/public/mojom/graph/
```

Then add the BUILD.gn entries to the parent files (see each BUILD.gn for integration notes).

### 3. Build

```bash
cd ~/chromium/src
gn gen out/LivingWeb --args='is_debug=false is_component_build=true'
autoninja -C out/LivingWeb chrome
```

### 4. Run WPTs

Copy test files to the Chromium WPT directory and run:

```bash
third_party/blink/tools/run_web_tests.py --target=LivingWeb \
  third_party/blink/web_tests/external/wpt/graph/
```

## Directory Structure

```
third_party/blink/renderer/modules/graph/   — Blink IDL + C++ (Web API surface)
  navigator_graph.*                           — Navigator.graph partial interface
  personal_graph.*                            — PersonalGraph (Specs 01, 04)
  personal_graph_manager.*                    — PersonalGraphManager (Spec 01)
  shared_graph.*                              — SharedGraph (Specs 03, 05)
  semantic_triple.*                           — SemanticTriple (Spec 01 §3.1)
  signed_triple.*                             — SignedTriple (Spec 01 §3.2)
  content_proof.*                             — ContentProof (Spec 01 §3.2)
  graph_diff.*                                — GraphDiff (Spec 03 §5.4)

content/browser/graph/                       — Graph store backend (in-memory triple store)
content/browser/did/                         — DID key management (Ed25519 via BoringSSL)
content/browser/graph_sync/                  — P2P sync service (CRDT engine, peer management)
content/browser/graph_governance/            — Governance engine (scope, ZCAP, temporal, content, credential)

mojo/public/mojom/graph/                     — Mojo IPC interface definitions

tests/
  web_platform_tests/graph/                  — WPT tests for all 5 specs
  *_unittest.cc                              — C++ unit tests
```

## Web Platform Tests

| File | Spec | Tests |
|------|------|-------|
| `personal-graph-basic.html` | 01 — Personal Linked Data Graphs | 16 |
| `personal-graph-shapes.html` | 04 — Dynamic Shape Validation | 10 |
| `identity-create.html` | 02 — Decentralised Identity | 9 |
| `shared-graph-sync.html` | 03 — P2P Graph Sync | 8 |
| `governance-constraints.html` | 05 — Graph Governance | 9 |

**Total: 52 WPT tests** across all 5 specifications.

## Current Limitations

- **All methods are stubs.** They return rejected promises with `NotSupportedError`. This is a reference implementation skeleton — no data is persisted, no sync occurs, no signing happens.
- **Event handlers omitted from IDL.** Custom event types (`tripleadded`, `peerjoined`, etc.) require registration in Chromium's `event_type_names.json5`. Both interfaces extend `EventTarget`, so `addEventListener()` will work once types are registered.
- **DIDCredential not in IDL.** Spec 02 extends `navigator.credentials`, which requires modifying Chromium's `credentialmanagement` module. The backend (`content/browser/did/`) is implemented.
- **Types simplified to `any`.** Complex spec types (dictionaries, typed sequences) are represented as `any` in the IDL. See [SPEC_COMPLIANCE.md](SPEC_COMPLIANCE.md) for details.
- **No Mojo wiring.** Renderer stubs don't yet call browser-process backends via Mojo IPC.

## Related Repositories

- **[Specifications](https://github.com/HexaField/w3c-living-web-proposals)** — The 5 W3C-style spec drafts
- **[AD4M](https://github.com/coasys/ad4m)** — Reference implementation of the Living Web concepts as a layer above the browser

## Contributing

1. Pick an API from [SPEC_COMPLIANCE.md](SPEC_COMPLIANCE.md) marked as Stub or Deferred
2. Implement the browser-process backend in `content/browser/`
3. Wire it through Mojo to the renderer stub
4. Update the WPT test from "expect stub rejection" to "expect real behaviour"
5. Update SPEC_COMPLIANCE.md status

## License

BSD-style license (same as Chromium). See individual file headers.
