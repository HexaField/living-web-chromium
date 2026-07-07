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
| 01 | [Decentralised Identity](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/01_decentralised-identity-web-platform.md) | `navigator.credentials` + `DIDCredential` | `spec-01-identity` | ✅ |
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

## Spec 01 — Decentralised Identity ✅

Fully implemented and tested. The normative cryptography (§4 did:key, §6 signing,
§7 resolution) lives in the browser-process DID service and its Chromium-independent
mirror, and is exercised by the standalone C++ harness (`living_web_tests`, 30 tests);
the renderer exposes the complete `DIDCredential` method surface.

### Attributes (§3)

| Attribute | Spec | IDL | C++ | WPT | Status |
|-----------|------|-----|-----|-----|--------|
| `DIDCredential.did` | §3 | ✅ | ✅ | ✅ | ✅ |
| `DIDCredential.method` | §3 | ✅ | ✅ | ✅ | ✅ |
| `DIDCredential.algorithm` | §3 | ✅ | ✅ | ✅ | ✅ |
| `DIDCredential.displayName` | §3 | ✅ | ✅ | ✅ | ✅ |
| `DIDCredential.createdAt` | §3 | ✅ | ✅ | ✅ | ✅ |
| `DIDCredential.isLocked` | §5.3.2 | ✅ | ✅ | ✅ | ✅ |

### Creation & retrieval (§3.1, §3.2, §4)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `navigator.credentials.create({ did })` | §3.1 | ✅ | ✅ | — | ✅ | Canonical surface. IDL partial declared in `credential_management_did.idl`; the `create()` dispatch is a documented core-file patch (see [Credential Management](#credential-management-surface)). Backend reachable and tested. |
| `navigator.credentials.get({ did })` | §3.2 | ✅ | ✅ | — | ✅ | As above — retrieval / credential picker. |
| `CredentialsContainer.resolve(did)` | §4.2 | ✅ | ✅ | ✅ | ✅ | Resolution dispatcher (Supplement). |
| `CredentialsContainer.supportedMethods()` | §4.2 | ✅ | ✅ | ✅ | ✅ | Method registry (`["key"]`). |
| `navigator.graph.createIdentity(name)` | §3, §4.1 | ✅ | ✅ | ✅ | ✅ | Reachable creation surface; returns the identical `DIDCredential`. |
| `navigator.graph.listIdentities()` | §3 | ✅ | ✅ | ✅ | ✅ | |
| `navigator.graph.activeIdentity()` | §3 | ✅ | ✅ | ✅ | ✅ | |
| did:key generation (Ed25519) | §4.1 | — | ✅ | ✅ | ✅ | `did:key:z6Mk…` = base58btc(0xed01 ‖ 32-byte pubkey). Verified against the RFC 8032 §7.1 test vector. |

### Signing & resolution (§6, §7)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `sign(data)` → `SignedContent` | §6.1 | ✅ | ✅ | ✅ | ✅ | Locked → `InvalidStateError`. |
| `verify(content)` → `boolean` | §6.2 | ✅ | ✅ | ✅ | ✅ | Cross-key and tampered-signature negatives covered. |
| `signCapability(zcap)` → `SignedContent` | §6.3 | ✅ | ✅ | ✅ | ✅ | Structurally invalid ZCAP-LD → `SyntaxError`. |
| Signing algorithm (JCS ‖ SHA-256 ‖ Ed25519) | §6.4 | — | ✅ | ✅ | ✅ | Key-order-independent (JCS / RFC 8785 canonicalisation). |
| `signRaw(payload)` → `ArrayBuffer` | §6.5 | ✅ | ✅ | ✅ | ✅ | Verbatim bytes, raw 64-byte sig; locked → `InvalidStateError`. |
| `resolve()` → DID document | §7.1 | ✅ | ✅ | ✅ | ✅ | did:key ⇒ `trustLevel: "local"` (§7.2). |
| `lock()` / `unlock()` | §5.3.2 | ✅ | ✅ | ✅ | ✅ | Resolve with `undefined`; block signing while locked. |

### Supporting interfaces

| Interface | Spec | IDL | C++ | Status | Shape |
|-----------|------|-----|-----|--------|-------|
| `SignedContent` | §6.1 | ✅ | ✅ | ✅ | `{ author, timestamp, data, proof }` |
| `ContentProof` | §6.4 | ✅ | ✅ | ✅ | `{ method, signature, type }` — `Ed25519Signature2020`, multibase base58btc |

### Credential Management surface

The canonical creation path is `navigator.credentials.create({ did })` returning a
`DIDCredential : Credential` (§3.1). Chromium's `credentialmanagement` module is **not**
part of this overlay, so the partials that attach to it —
`CredentialCreationOptions.did`, `CredentialRequestOptions.did`, and the
`CredentialsContainer` `resolve()` / `supportedMethods()` extensions — are declared in
[`credential_management_did.idl`](third_party/blink/renderer/modules/graph/credential_management_did.idl)
with a precise integration note describing the `create()` / `get()` dispatch and the
`Supplement<CredentialsContainer>` wiring for a full-tree build.

The identical `DIDCredential` object and its **entire** §6–§7 signing surface are also
reachable — and tested — through the `navigator.graph` identity methods, so the
implementation contains no dead code.

### Cryptographic parameters (normative)

- **did:key** (§4.1): `did:key:z` ‖ base58btc(`0xed01` multicodec ‖ 32-byte Ed25519
  public key). Ed25519 keys always yield the `z6Mk…` prefix.
- **Signing** (§6.4): `Ed25519( SHA-256( JCS(data) ‖ timestamp ) )`, proof serialised as
  `{ method, signature: multibase(base58btc,'z'), type: "Ed25519Signature2020" }`.
- **signRaw** (§6.5): raw 64-byte Ed25519 signature over the verbatim payload — no
  canonicalisation, hashing, timestamp, or framing.
- **Resolution** (§7): local did:key resolution only, `trustLevel: "local"`; there is no
  global resolver (§7.3).

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
