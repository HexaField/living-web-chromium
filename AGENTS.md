# AGENTS.md — living-web-chromium

Native Chromium implementation of the [Living Web specs](https://github.com/HexaField/w3c-living-web-proposals)
(10 drafts). Read this before working in the repo.

## What this repo is

An **overlay**, not a full Chromium checkout. It contains:

- Curated files that drop into a real `chromium/src/` tree:
  `content/browser/{did,graph,graph_sync,graph_governance}/`,
  `third_party/blink/renderer/modules/graph/`, `mojo/public/mojom/graph/`.
- A **standalone CMake harness** (`standalone/`, `tests/`, `CMakeLists.txt`) that mirrors
  the browser-process backends and is the **only locally buildable/testable** part.

Chromium's `credentialmanagement` module is **absent** from the overlay. Spec 01's
canonical `navigator.credentials.create({ did })` surface is therefore declared as IDL
partials in `third_party/blink/renderer/modules/graph/credential_management_did.idl`
with an integration note; the same `DIDCredential` object is reachable via
`navigator.graph.createIdentity()`.

## Two build worlds — critical

| World | Path | Buildable locally? | Verifies |
|-------|------|--------------------|----------|
| Standalone harness | `standalone/`, `tests/` | ✅ CMake | The real crypto/store/sync/governance logic |
| Renderer overlay | `third_party/blink/…`, `content/browser/…`, `mojo/…` | ❌ only in a full Chromium tree | Web-facing IDL + Mojo glue (reviewed mirror) |

The overlay is kept byte-faithful to the standalone core. **"Tests pass" means the
standalone harness is green AND the overlay was reviewed against it — never that the
overlay was locally compiled.** When you change an overlay file, say so explicitly.

## Build & test

```bash
cmake -S . -B build          # first time
cmake --build build          # after every change to standalone/ or tests/
./build/living_web_tests     # must stay 100% green
```

There is no lint/format gate beyond Chromium style conventions; match the surrounding
code (Google C++ style, 2-space indent, `//`-comment file headers).

## Spec ↔ code map

Spec numbering (current, 10 specs):

| # | Spec | Where |
|---|------|-------|
| 01 | Decentralised Identity | `content/browser/did/`, `.../graph/did_credential.*`, `signed_content.*`, `content_proof.*` |
| 02 | Personal Linked Data Graphs | `.../graph/personal_graph*`, `content/browser/graph/` |
| 03 | Decentralised Group Identity | — (planned) |
| 04 | Graph Capability Framework | `content/browser/graph_governance/` (ZCAP) |
| 05 | Context Sync Protocol | `.../graph/shared_graph*`, `content/browser/graph_sync/` |
| 06 | Sync Module Architecture | — (planned) |
| 07 | Dynamic Graph Shape Validation | `.../graph/personal_graph*` (shape methods) |
| 08 | Governance Constraint Vocabulary | `content/browser/graph_governance/` |
| 09 | Default Sync Module | — (planned, CRDT + MLS) |
| 10 | Graph Flows | — (planned) |

`SPEC_COMPLIANCE.md` tracks per-API status. Keep it current as branches land.

## Conventions

- **One spec per branch**, in dependency order (01 → 06, then 07–10). Branch name
  `spec-NN-shortname` (e.g. `spec-01-identity`). Each PR must be independently auditable.
- **No subsets.** The spec is normative — implement exactly what it mandates. No mocks,
  stubs, or placeholders in landed work. Leverage real libraries (Ed25519, JCS, Oxigraph
  for SPARQL, etc.) rather than faking behaviour.
- **Every fix needs a test** in the standalone harness that would have caught the
  regression. The harness can construct negatives (tampered signatures, cross-key verify)
  that read-only WPT interfaces cannot — put those there.
- **Spec gaps** (genuinely undefined behaviour) are resolved by amending the spec repo
  (`w3c-living-web-proposals`, branch `spec-amendments`), never by weakening the
  implementation.

Each spec branch documents its own normative specifics (crypto parameters, error
behaviour, reference impl) in a section it adds here when it lands, so this file
stays the authoritative per-spec cheat-sheet as branches merge.

## Gotchas

- Don't add DIDCredential logic that isn't reachable — wire new methods through
  `personal_graph_manager.cc` (`MakeDIDCredential`) so WPT can hit them.
- Blink patterns: `ScriptWrappable` interfaces; `ScriptPromise<T>` / `ScriptPromiseResolver<T>`;
  `ToV8Traits<T>::ToV8`; `HeapMojoRemote`; `V8BufferSource` + `DOMArrayPiece` for
  `BufferSource`; `DOMArrayBuffer::Create(base::span(...))` to return an `ArrayBuffer`;
  `v8::JSON::Stringify`/`Parse` for `any` round-trips.
- Event-handler IDL attributes are omitted (they need `event_type_names.json5`, a core
  file). Interfaces extend `EventTarget`, so `addEventListener()` works post-integration.
- IDL files are **not** listed in `BUILD.gn` sources — they're wired separately during
  full-tree integration; only `.cc`/`.h` go in `blink_modules_sources`.
