# Living Web — Chromium Implementation

Native browser implementation of the
[Living Web specifications](https://github.com/HexaField/w3c-living-web-proposals)
for Chromium. It adds decentralised identity, a local-first semantic graph store,
peer-to-peer context sync, shape-driven CRUD, and governance to the web platform.

## How this repository is organised

The ten specifications are implemented **one per branch**, in dependency order,
and landed as **staggered pull requests** so each spec is independently
auditable. This `main` branch is the **base**: shared infrastructure, the build
skeleton, and the standalone test framework — and **no spec code**. Every spec
adds its own browser backend, renderer overlay, standalone mirror, and tests on
top of this base.

| # | Specification | Branch | Status |
|---|--------------|--------|--------|
| 01 | [Decentralised Identity](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/01_decentralised-identity-web-platform.md) | `spec-01-identity` | 🔀 In review |
| 02 | [Personal Linked Data Graphs](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/02_personal-linked-data-graphs.md) | `spec-02-graphs` | 🔀 In review |
| 03 | [Decentralised Group Identity](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/03_decentralised-group-identity.md) | `spec-03-group-identity` | 🔀 In review |
| 04 | [Graph Capability Framework](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/04_graph-capability-framework.md) | `spec-04-capabilities` | 🔀 In review |
| 05 | [Context Sync Protocol](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/05_context-sync-protocol.md) | `spec-05-sync` | 🔀 In review |
| 06 | [Sync Module Architecture](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/06_sync-module-architecture.md) | `spec-06-sync-modules` | 🔀 In review |
| 07 | [Dynamic Graph Shape Validation](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/07_dynamic-graph-shape-validation.md) | `spec-07-shapes` | 🔀 In review |
| 08 | [Governance Constraint Vocabulary](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/08_governance-constraint-vocabulary.md) | `spec-08-governance` | 🔀 In review |
| 09 | [Default Sync Module](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/09_default-sync-module.md) | `spec-09-default-sync` | 🔀 In review |
| 10 | [Graph Flows](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/10_graph-flows.md) | `spec-10-flows` | 🔀 In review |

Full API-by-API tracking: **[SPEC_COMPLIANCE.md](SPEC_COMPLIANCE.md)**.

The prior single-line prototype (which pre-dated the current 10-spec numbering)
is preserved on the `archive/prototype-history` branch. `main` was reset to this
clean base so each spec can be reviewed in isolation, with **no subsets** — every
branch implements exactly what its spec mandates.

## Two build worlds

This repository is an **overlay**, not a full Chromium checkout.

- **Standalone harness** — `standalone/` + `tests/`, built with CMake. This is the
  locally buildable and testable core: real Ed25519 crypto, JCS canonicalisation,
  the did:key codec, the triple store, sync CRDT and governance engine, each added
  by the spec that owns it and exercised by `living_web_tests`. Normative
  behaviour (e.g. Spec 01's §6–§7 signing) is verified here.
- **Renderer overlay** — `third_party/blink/…`, `content/browser/…`, `mojo/…`. A
  reviewed mirror of the Web-facing surface that compiles **only inside a full
  Chromium tree**. It is kept byte-faithful to the standalone core but is not
  built by the local CMake harness.

"Tests green" means the standalone harness passes and the overlay has been
reviewed against it — not that the overlay was locally compiled.

## Quick start (standalone harness)

```bash
cmake -S . -B build
cmake --build build
./build/living_web_tests
```

On the base branch this builds the framework and runs zero tests. Check out a
spec branch to build and run that spec's suite.

## Repository layout

The base ships:

```
CMakeLists.txt          — build skeleton (ed25519 primitive + test harness)
integrate.sh            — full-overlay integration script for a Chromium src/ tree
standalone/
  base_shim.h           — minimal base:: API shims (UUID, logging, JSON helpers)
  crypto_sha2.h         — SHA-256 (OpenSSL-backed)
  json_parser.h         — dependency-free JSON parser
  types.h               — shared value types (namespace scaffold; specs add structs)
  living_web_tests.cc   — self-registering test framework + runner
third_party/ed25519/    — vendored Ed25519 (OpenSSL EVP backend)
```

Each spec branch adds, as applicable:

```
content/browser/<module>/               — browser-process backend + BUILD.gn
third_party/blink/renderer/modules/graph/ — Blink IDL + C++ (Web API surface)
mojo/public/mojom/graph/                 — Mojo IPC interface definitions
standalone/<module>.h                    — Chromium-independent mirror of the backend
tests/<module>_unittest.cc               — C++ unit tests
tests/web_platform_tests/graph/*.html    — WPT (run in a full Chromium tree)
```

## Spec amendments

Under-specified areas found while implementing are resolved by **amending the
spec**, never by weakening the implementation. Amendments already landed on the
[specs repo](https://github.com/HexaField/w3c-living-web-proposals) `main`:

- **01** — `signRaw` verbatim-bytes signing (§6.5).
- **02** — blank-node `removeTriple` semantics (§4.2), JSON-LD as OPTIONAL and unadvertised
  via `supportedSnapshotFormats` (§5.3.4, §3.4), the N-Triples-1.2 signature pre-image
  (§3.2.1.1), and the `rdfc-1.0` triple-term canonicalisation profile (§5.2).
- **03** — self-certifying verification-method ids (fragment = `publicKeyMultibase`, §4.4)
  and `groupify(Graph)` keyed on the durable `did:graph` rather than the volatile
  content-address IRI (§4.3, §8.2.2).
- **04** — default root actions pinned to the eight framework-core actions plus mandatory
  local-root re-verification (§4.3), flattened ZCAP predicates pinned to the `zcap://` scheme
  (§4.5.3), the exact delegation-proof pre-image bytes (§4.5.3.1), and the `did://` predicate
  family mapping to `updateDIDDocument` (§4.5.4.1).
- **05** — the exact `revision`/`commitId` diff pre-image bytes and signature message
  (§5.2.2.1), graph invitation links (§12), reconnection / offline handling (§13), and
  the received-timestamp plausibility bound (§14.5).
- **06** — normative WIT interface for sync modules (§6). Landed ahead of the
  Spec 06 branch by the cross-cutting amendment `53ea1b2`; the branch introduced
  no further draft changes.
- **07** — canonical `subject`/`predicate`/`object` constructor-action keys with the
  deprecated `source`/`target` aliases retained for compatibility (§4.3, §12), the
  content address pinned to `sha256:` + lowercase-hex(SHA-256(JCS)) with the
  `has_shape` link subject as the graph's stable id (§6.2–§6.4), and the three
  accepted `datatype` forms — full XSD URI, `xsd:`-prefixed, or `"URI"` (§4.2).
- **08** — timestamp plausibility bound (§5.3).
- **09** — full MLS group-keying ceremony (§6.3).
- **10** — concurrent flow-state transitions (§13).

## Integrating into Chromium

```bash
# Check out Chromium (see https://chromium.googlesource.com/chromium/src/+/main/docs/get_the_code.md)
# From the Chromium src/ directory, run the integration script:
bash /path/to/living-web-chromium/integrate.sh "$(pwd)" /path/to/living-web-chromium
```

`integrate.sh` copies the overlay files into `src/`, patches the parent
`BUILD.gn` files, registers the Mojo interfaces and Blink IDL, and wires the
browser-side service factory. Then:

```bash
cd ~/chromium/src
gn gen out/LivingWeb --args='is_debug=false is_component_build=true'
autoninja -C out/LivingWeb chrome
third_party/blink/tools/run_web_tests.py --target=LivingWeb \
  third_party/blink/web_tests/external/wpt/graph/
```

## Related repositories

- **[Specifications](https://github.com/HexaField/w3c-living-web-proposals)** — the 10 W3C-style spec drafts.
- **[AD4M](https://github.com/coasys/ad4m)** — reference implementation of the Living Web concepts as a layer above the browser.

## License

BSD-style license (same as Chromium). See individual file headers.
