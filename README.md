# Living Web Chromium Implementation

Native browser implementation of the [Living Web specifications](https://github.com/HexaField/w3c-living-web-proposals) for Chromium.

## What This Is

This repository contains the **new files** that would be added to a Chromium checkout to implement the Living Web APIs natively. Files are structured to mirror Chromium's directory layout and can be dropped into a real Chromium source tree.

## Specifications Implemented

1. **Personal Linked Data Graphs** (`navigator.graph`) — Local-first semantic triple store
2. **Decentralised Identity** (`navigator.credentials` + DID) — Ed25519-backed `did:key` identities
3. **P2P Graph Synchronisation** (`SharedGraph`) — Peer-to-peer graph sync via CRDT
4. **Dynamic Graph Shape Validation** — SHACL shapes with action semantics (constructor/setter/collection)
5. **Graph Governance** — Constraint enforcement: scope, ZCAP, temporal, content, credential

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

## Integration with Chromium

1. Check out Chromium source (see [Chromium build instructions](https://chromium.googlesource.com/chromium/src/+/main/docs/get_the_code.md))
2. Copy directories from this repo into the Chromium source tree at matching paths
3. Add BUILD.gn entries to the appropriate parent BUILD.gn files
4. Add Mojo interface targets to `//mojo/public/mojom/BUILD.gn`
5. Build with `autoninja -C out/Default chrome`

## Directory Structure

```
content/browser/graph/           — Graph store backend (in-memory triple store)
content/browser/did/             — DID key management (Ed25519 via BoringSSL)
content/browser/graph_sync/      — P2P sync service (CRDT engine, peer management)
content/browser/graph_governance/ — Governance engine (scope, ZCAP, temporal, content, credential)
third_party/blink/renderer/modules/graph/ — Blink bindings (Web IDL + C++ implementations)
mojo/public/mojom/graph/         — Mojo IPC interface definitions
tests/                           — Unit tests and Web Platform Tests
```

## Current Status

- [x] Mojo interface definitions (complete API surface)
- [x] Blink Web IDL definitions (registered in idl_in_modules.gni)
- [x] Blink C++ renderer-side implementations
- [x] Browser-process graph store (in-memory)
- [x] Browser-process DID key provider (Ed25519)
- [x] Browser-process governance engine (all constraint types)
- [x] Browser-process sync service (in-process transport — spec is transport-agnostic per §6.5)
- [x] Unit tests (76 passing — standalone library)
- [x] Web Platform Tests
- [x] BUILD.gn files for Chromium integration
- [x] Integration script (`integrate.sh`) for automated Chromium patching
- [x] Full Chromium build (Linux x86_64 — chrome binary produced)
- [ ] Oxigraph integration (currently in-memory; Oxigraph for full SPARQL 1.2)
- [ ] Additional transport implementations (WebRTC, WebSocket — spec permits any transport per §6.5)
- [ ] Browser UI (permission prompts, DID picker)

## License

BSD 3-Clause (matching Chromium)
