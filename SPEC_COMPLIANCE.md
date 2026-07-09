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
| 02 | [Personal Linked Data Graphs](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/02_personal-linked-data-graphs.md) | `navigator.graph`, `Graph` | `spec-02-graphs` | ✅ |
| 03 | [Decentralised Group Identity](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/03_decentralised-group-identity.md) | `did:graph`, `navigator.graph` groups, `Group` | `spec-03-group-identity` | ✅ |
| 04 | [Graph Capability Framework](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/04_graph-capability-framework.md) | ZCAP-LD capabilities | `spec-04-capabilities` | ✅ |
| 05 | [Context Sync Protocol](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/05_context-sync-protocol.md) | `Graph.publish()`, `GraphManager.mount()` | `spec-05-sync` | ✅ |
| 06 | [Sync Module Architecture](https://github.com/HexaField/w3c-living-web-proposals/blob/main/drafts/06_sync-module-architecture.md) | `GraphManager.listModules()`, module runtime | `spec-06-sync-modules` | ✅ |
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

## Spec 02 — Personal Linked Data Graphs ✅

Fully implemented and tested. The `Graph` / `GraphManager` runtime (§4 API, §5
snapshots, §7 holonic SPARQL) is built on the RDF 1.2 quad store, RDF Dataset
Canonicalization (`rdfc-1.0`), and SPARQL 1.2 provided by **Oxigraph** — nothing
here is hand-rolled. Oxigraph is compiled to a static archive through a thin Rust
FFI (`third_party/oxigraph_ffi`, crate `oxigraph 0.5`, `features = ["rdf-12"]`)
and shared verbatim by the browser-process service and the standalone harness, so
the two never diverge on the bytes hashed, signed, or queried. The normative
behaviour is exercised by the `Graph_*` blocks of the C++ harness
(`living_web_tests`, 22 `Graph_*` tests, all green); the renderer exposes the
complete `Graph` method surface.

### Attributes (§3.3)

| Attribute | Spec | IDL | C++ | WPT | Status |
|-----------|------|-----|-----|-----|--------|
| `Graph.id` (stable `urn:graph:` URN) | §3.3 | ✅ | ✅ | ✅ | ✅ |
| `Graph.iri` (`graph://<content-hash>`) | §3.3, §5.2 | ✅ | ✅ | ✅ | ✅ |
| `Graph.did` (null until attached) | §3.3, §5.6 | ✅ | ✅ | ✅ | ✅ |
| `Graph.displayName` | §3.3 | ✅ | ✅ | ✅ | ✅ |
| `Graph.trustLevel` (`"local"` / `"external"`) | §3.3, §7.4 | ✅ | ✅ | ✅ | ✅ |

### Data model (§3.1, §3.2, §3.7)

| Interface | Spec | IDL | C++ | WPT | Status | Shape |
|-----------|------|-----|-----|-----|--------|-------|
| `Triple` (constructable) | §3.1 | ✅ | ✅ | ✅ | ✅ | `{ subject, predicate, object }` |
| `LiteralValue` (constructable) | §3.1 | ✅ | ✅ | ✅ | ✅ | `{ lexicalValue, datatype, language }` — defaults `xsd:string` |
| `Reifier` | §3.7 | ✅ | ✅ | ✅ | ✅ | `{ id, triple, author, timestamp, method, signature }` |
| RDF 1.2 reifier model | §3.2 | — | ✅ | ✅ | ✅ | 6 triples/assertion: 1 data + `rdf:reifies` triple-term + 4 `prov://*` |

### Creation & materialisation (§4.1, §5.5)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `navigator.graph.create(options?)` | §4.1 | ✅ | ✅ | ✅ | ✅ | Fresh `urn:graph:<UUIDv4>` id; empty-graph IRI; `did` null; `trustLevel "local"`. |
| `navigator.graph.fromSnapshot(snapshot, options?)` | §5.5 | ✅ | ✅ | ✅ | ✅ | Verifies proofs + hash invariant before persisting; defaults `trustLevel "external"`. |
| empty-graph IRI invariant | §3.3, §4.1 | — | ✅ | ✅ | ✅ | `graph://e3b0c442…7852b855` = graph:// + SHA-256(""); shared by every empty graph. |

### Triple operations (§4.2)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `addTriple(triple)` → `Triple` | §4.2 | ✅ | ✅ | ✅ | ✅ | Sign → reify → atomic commit → advance IRI → fire `tripleadded`. No active credential → `InvalidStateError`. |
| `addTriples(triples)` → `sequence<Triple>` | §4.2 | ✅ | ✅ | ✅ | ✅ | One atomic batch; IRI advances once; one `tripleadded` per triple, in input order. |
| `removeTriple(triple)` → `boolean` | §4.2 | ✅ | ✅ | ✅ | ✅ | Drops the data triple + all 4 reifier triples atomically (SPARQL 1.2 `DELETE`). See Amendment (i). |
| `queryTriples(query)` → `sequence<Triple>` | §4.2, §3.5 | ✅ | ✅ | ✅ | ✅ | Data triples only (never reifiers); ordered by reifier `timestamp` desc, subject asc; `subject`/`predicate`/`object`/`author`/`fromDate`/`untilDate`/`offset`/`limit` all AND-combine. |
| `snapshot()` → `sequence<Triple>` | §4.2 | ✅ | ✅ | ✅ | ✅ | Data triples ordered by reifier `timestamp` ascending. |
| `provenance(triple)` → `sequence<Reifier>` | §4.2, §3.2 | ✅ | ✅ | ✅ | ✅ | Reifiers whose `rdf:reifies` target matches the triple; signature verifies end-to-end against the §3.2.1 payload. |
| `dissolve()` → `undefined` | §4.3 | ✅ | ✅ | ✅ | ✅ | Terminal + idempotent; every other op then rejects `InvalidStateError`. |
| `ontripleadded` / `ontripleremoved` | §4.2 | ✅ | ✅ | ✅ | ✅ | `GraphTripleEvent` with a `Triple` payload; fired via `event_type_names::kTripleadded` / `kTripleremoved`. |

### Snapshots (§5)

| Capability | Spec | IDL | C++ | WPT | Status | Notes |
|------------|------|-----|-----|-----|--------|-------|
| Content-hash (`rdfc-1.0` ‖ SHA-256 ‖ lowercase hex) | §5.2 | — | ✅ | ✅ | ✅ | Deterministic; delegated to Oxigraph. |
| `getAsSnapshot(options?)` → `GraphSnapshot` | §5.4 | ✅ | ✅ | ✅ | ✅ | `proofPayload = SHA-256(graphIri ‖ "\|" ‖ timestamp)`; `signBy` `"agent"`/`"graph"`/`"both"`. |
| `"nquads-canonical"` (default) | §5.3.1 | ✅ | ✅ | ✅ | ✅ | Invariant `graphIri == "graph://" + hex(SHA-256(data))` — verifiable with no re-parse. |
| `"nquads"`, `"turtle"` | §5.3.2 | ✅ | ✅ | — | ✅ | Round-trip through `fromSnapshot()`; re-canonicalised on verify. |
| `"jsonld"` | §5.3.2 | ✅ | ✅ | — | ✅ | OPTIONAL producer-side; not advertised — `getAsSnapshot`/`fromSnapshot` reject with `NotSupportedError`. See Amendment (ii). |
| `signBy: "graph"` requires `graph.did == active.did` | §5.4 | — | ✅ | — | ✅ | Otherwise `NotAllowedError`. |
| `fromSnapshot` proof + hash checks | §5.5, §9.2 | — | ✅ | ✅ | ✅ | Empty `proofs` or tampered data → `DataError`; §9.7 size bound (100 MB) → `QuotaExceededError`. |
| `GraphSnapshot` / `SnapshotProof` | §5.3 | ✅ | ✅ | ✅ | ✅ | `{ graphIri, graphDid, format, timestamp, data, proofs }` · `{ role, author, method, signature }` |

### Holonic composition & SPARQL (§7)

| Capability | Spec | IDL | C++ | WPT | Status | Notes |
|------------|------|-----|-----|-----|--------|-------|
| `querySparql(sparql, options?)` → `SparqlResult` | §4.2, §7.2 | ✅ | ✅ | — | ✅ | SPARQL 1.2 (Oxigraph); result surfaced as `any` (SPARQL 1.1 Results JSON / N-Triples). |
| Dataset construction | §7.2 | — | ✅ | — | ✅ | Default graph = the callee; `options.namedGraphs` keyed by each graph's current IRI; `GRAPH <iri> { … }` bridges them. |
| Holonic query across graphs | §7.3 | — | ✅ | — | ✅ | Verified: community graph + channel named-graph resolved in one request. |
| Trust levels | §7.4 | ✅ | ✅ | ✅ | ✅ | `"local"` (create) / `"external"` (fromSnapshot); enum extensible by other specs. |

### Substrate (normative)

- **RDF 1.2 + rdfc-1.0 + SPARQL 1.2** (§5.2, §7): provided by **Oxigraph** (`oxigraph 0.5`,
  `features = ["rdf-12"]`) through the `oxigraph_ffi` static archive. RDF 1.2 triple terms
  (`<<( s p o )>>`), `rdfc-1.0` canonicalisation, and SPARQL 1.2 query/update are all
  Oxigraph functionality, wrapped by `content/browser/graph/oxigraph_store.*`. SHA-256 is
  the Spec 01 crypto core.
- **Reifier model** (§3.2): every `addTriple` writes **6 triples** — the data triple, an
  `rdf:reifies` triple whose object is the RDF 1.2 triple term of the data triple, and the
  four `prov://{author,timestamp,method,signature}` triples on the reifier blank node.
- **Signature payload** (§3.2.1): `SHA-256( canonical(triple) ‖ "|" ‖ timestamp ‖ "|" ‖
  graphIdentifier )`, signed with the active credential's `signRaw()`; `graphIdentifier` is
  `Graph.did` if set, else `Graph.id` (never the volatile `iri`).
- Authoritative reference impl: `standalone/graph_provider.h` over
  `content/browser/graph/{oxigraph_store,rdf_serialization,sparql_results}.*`, verified by
  the 22 `Graph_*` tests in `standalone/living_web_tests.cc`.

### Amendments

Four under-specified areas surfaced while implementing Spec 02 have been **folded
into draft 02 as normative detail** on `w3c-living-web-proposals` `main` (the same
practice used for Spec 01's `signRaw` §6.5), so the spec mandates exactly one
interoperable behaviour rather than leaving it to the implementer. None weakens the
implementation; two pin determinism, two reflect genuine limits of current stable
RDF 1.2 tooling:

- **(i) `removeTriple` on a blank-node data-triple subject is a no-op** — draft §4.2
  ("Blank-node subjects"). RDF Dataset Canonicalization relabels blank nodes, so a
  `_:label` a caller holds is not a durable name for a stored triple; such a triple cannot
  be uniquely targeted by subject/predicate/object match, and `removeTriple()` MUST resolve
  `false`. Removable blank-node-subject triples are deferred to removal by durable reifier
  identity (a §8.2 amendment point).
- **(ii) JSON-LD is OPTIONAL and the advertised-format set is discoverable** — draft §5.3.4
  ("Advertised Formats") + the new `static readonly attribute
  GraphManager.supportedSnapshotFormats` (§3.4). `nquads-canonical`, `nquads`, and `turtle`
  are REQUIRED; `"jsonld"` is OPTIONAL because RDF 1.2 triple terms (carried by every
  reifier) have no stable JSON-LD 1.2 `@triple` form in current tooling (verified against
  `oxjsonld 0.2.5`, which recognises no `@triple` keyword and cannot construct a triple-term
  object). This user agent advertises the three REQUIRED formats; `getAsSnapshot` /
  `fromSnapshot` of any unadvertised format reject with `NotSupportedError`.
- **(iii) `canonical(triple)` byte form is pinned** — draft §3.2.1.1 ("Canonical Triple
  Serialisation"). The exact one-line N-Triples 1.2 pre-image is fixed (term spacing, IRI
  `UCHAR`/literal `ECHAR` escaping, `^^`/`@lang` suffix rules, triple-term `<<( s p o )>>`
  spacing, blank-node handling) so independent implementations produce identical signatures.
- **(iv) `rdfc-1.0` + RDF 1.2 triple-term canonicalization profile is pinned** — draft §5.2
  ("Canonicalisation profile"). The March 2025 [[RDF-CANON]] Recommendation with SHA-256 is
  mandated, and triple-term canonicalisation is pinned to RDF-1.2 N-Quads term equality so
  the content hash is a pure function of the abstract dataset. This impl delegates both to a
  single pinned canonicaliser (Oxigraph 0.5, `rdf-12`).

---

## Spec 03 — Decentralised Group Identity ✅

Fully implemented and tested. A **group** is a groupified Spec 02 graph (§4.2): a
fresh Ed25519 keypair is minted, a `did:graph` is derived from it, and the DID
document — verification methods and their capability-section memberships — is
written as ordinary triples in the host graph and resolved back out of it. The
`did:graph` codec and the DID-document model (`content/browser/did/did_graph.*`,
namespace `living_web`) are Chromium-independent and shared verbatim by the
browser-process group service and the standalone harness, so the triples written,
signed, and projected never diverge. The normative behaviour is exercised by the
`Group_*` blocks of the C++ harness (`living_web_tests`, 15 `Group_*` tests, all
green); the renderer exposes the complete `Group` surface off `navigator.graph`.

### `did:graph` method (§4)

| Capability | Spec | C++ | WPT | Status | Notes |
|------------|------|-----|-----|--------|-------|
| `did:graph` identifier (Ed25519 multibase) | §4.1 | ✅ | ✅ | ✅ | `did:graph:z6Mk…` — same base58btc(`0xed01` ‖ pubkey) body as did:key; only the method prefix differs. Round-trips losslessly. |
| Groupification (one-way bootstrap) | §4.2 | ✅ | ✅ | ✅ | Atomic seed write: binding triple + seed DID document (creator holds all four sections) + `group://syncModule`. Re-groupify → `InvalidStateError`. `syncModule` REQUIRED → `SyntaxError`. |
| Binding triple `group://didIdentity` | §4.3 | ✅ | ✅ | ✅ | Locates a group's host graph by DID; the durable key is the DID, never the volatile `graph://` IRI. See Amendment (ii). |
| DID document as triples | §4.4 | ✅ | ✅ | ✅ | `did://verificationMethod` + per-section membership predicates; per-method `type`/`controller`/`publicKeyMultibase`. Method id = `<did>#<publicKeyMultibase>`. See Amendment (i). |
| Immutable seed predicates | §4.5 | ✅ | — | ✅ | `group://syncModule`, `group://forkedFrom`, `group://forkedAtRevision` — written at groupification/fork, never mutated. |
| Resolution → DID document | §4.7 | ✅ | ✅ | ✅ | Projects the triples to a [[DID-CORE]] JSON-LD document; local mount ⇒ `trustLevel: "local"`. |
| Forking | §4.8 | ✅ | ✅ | ✅ | Mints a new identity over a full N-Quads copy of the parent (`DumpNquads`), strips the parent identity, records `group://forkedFrom`/`forkedAtRevision`, and (default) announces `group://forkedTo` on the parent. |
| Deactivation | §4.9 | ✅ | ✅ | ✅ | Reflected in subsequent `resolve()` (`deactivated: true`). |

### DID-document delegates & capability sections (§5)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `addSigner(method, sections)` | §5.4, §8.1.4 | ✅ | ✅ | ✅ | ✅ | Adds a `DIDDocumentMethod` + its section memberships. Requires `capabilityDelegation` authorship → else `NotAllowedError`. |
| `removeSigner(methodId)` / `replaceSigner` | §5.4, §8.1.4 | ✅ | ✅ | ✅ | ✅ | Removing the sole `capabilityDelegation` method → `InvalidStateError` (brick guard). |
| `grantSection` / `revokeSection` | §5.4 | ✅ | ✅ | ✅ | ✅ | Revoking the sole `capabilityDelegation` membership → `InvalidStateError`. |
| `signers(section?)` / `isSigner(did, section?)` | §5.4, §8.1.4 | ✅ | ✅ | ✅ | ✅ | Enumerates / tests membership, optionally scoped to one section. |
| `signGraph(target)` → `SignedContent` | §5.4 | ✅ | ✅ | ✅ | ✅ | Requires `assertionMethod` authorship → else `NotAllowedError`. Reuses the Spec 01 `Ed25519Signature2020` proof shape; signature multibase base58btc. |
| `setActingCredential(id)` | §5.4 | ✅ | ✅ | ✅ | ✅ | Selects which held delegate credential authors subsequent governed writes; defaults to the creator key (group of one). |

The four capability sections are `capabilityInvocation`, `capabilityDelegation`,
`assertionMethod`, `authentication` (`DIDCapabilitySection`, §5.1).

### Participation vs signing authority (§6, §7)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `invite(did)` / `revokeParticipation(did)` | §7.1, §8.1.1–2 | ✅ | ✅ | ✅ | ✅ | Participation is structurally separate from signing authority (§7.3). Accepting participation requires `capabilityDelegation` authorship → else `NotAllowedError`. |
| `hasParticipant(did)` / `participants()` | §8.1.3 | ✅ | ✅ | ✅ | ✅ | Each participant carries `did`, `isGroup`, `joinedAt`, and (if locally resolvable) `name`. |
| `transitiveParticipants()` | §6.3, §8.1.3 | ✅ | ✅ | ✅ | ✅ | Descends into participating sub-groups, flattens to individuals; cycle-safe (mutual participation terminates). |
| `parentGroups()` / `childGroups()` | §6.3, §8.1.3 | ✅ | ✅ | ✅ | ✅ | Sub-group nesting via `group://` participation edges between locally-mounted groups. |

### GraphManager group surface (§8.2)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `createGroup(options)` → `Group` | §8.2.1 | ✅ | ✅ | ✅ | ✅ | Mints a host graph and groupifies it. `syncModule` REQUIRED (`TypeError` at bindings / `SyntaxError` in the port). |
| `groupify(graph, options)` → `Group` | §8.2.2 | ✅ | ✅ | ✅ | ✅ | Takes the **live `Graph`**, not an IRI — see Amendment (ii). Re-groupify → `InvalidStateError`. |
| `forkGroup(parentIriOrDid, options)` → `Group` | §8.2.4 | ✅ | ✅ | ✅ | ✅ | Inherits content + lineage; mints a fresh identity. |
| `openGroup(iriOrDid)` → `Group` | §8.2.3 | ✅ | ✅ | ✅ | ✅ | Reopens a locally-mounted group by DID or IRI; unknown → `NotFoundError`. |
| `listGroups()` → `sequence<Group>` | §8.2 | ✅ | ✅ | ✅ | ✅ | Enumerates the mounted groups. |

### Group interface (§8.1) & isomorphism (§11)

`Group` attributes: `did`, `iri`, `graph` (the host `Graph`), `name`,
`description`, `created`, `creator`. A **group of one** (§11) — the state right
after `createGroup` — has its single creator key in all four capability sections;
an individual identity and a group are therefore the same structure at different
cardinalities, and `resolve()` returns a one-verification-method DID document.

### Normative parameters

- **`did:graph`** (§4.1): `did:graph:z` ‖ base58btc(`0xed01` ‖ 32-byte Ed25519 public
  key). The codec reuses the Spec 01 did:key multibase machinery byte-for-byte; only the
  method prefix differs, so a group's initial key is an ordinary `DIDKeyPair` with
  `method = "graph"`.
- **Verification-method id** (§4.4): `<did> + "#" + publicKeyMultibase` — self-certifying,
  derivable from the key alone (Amendment (i)).
- **Authorship** (§5.4, §6.2): governed writes are gated on the acting delegate holding the
  required section — delegate management and accepting participation need
  `capabilityDelegation`; `signGraph` needs `assertionMethod`; failure is `NotAllowedError`.
- **Brick guards** (§5.4): the group MUST always retain at least one `capabilityDelegation`
  method; operations that would remove the last one fail with `InvalidStateError`.
- **Errors** map to DOMException names: missing `syncModule` → `SyntaxError`; re-groupify /
  brick / deactivated-state → `InvalidStateError`; missing section authority → `NotAllowedError`;
  unknown DID/IRI on open → `NotFoundError`.
- Authoritative reference impl: `standalone/group_provider.h` over
  `content/browser/did/did_graph.*`, verified by the 15 `Group_*` tests in
  `standalone/living_web_tests.cc`; the browser port
  (`content/browser/did/group_backend*.*`, `group_service.*`, `group_host.*`) and the
  renderer (`third_party/blink/renderer/modules/graph/group.*`) mirror it.

### Amendments

Two under-specified areas surfaced while implementing Spec 03 have been **folded
into draft 03 as normative detail** on `w3c-living-web-proposals` `main` (the same
practice used for Specs 01–02). Neither weakens the implementation; both remove an
interoperability hazard the draft left open:

- **(i) A verification-method id fragment is the key's `publicKeyMultibase`** — draft §4.4
  ("Verification-method identifiers"). The draft's algorithm (§4.2 step 4) constructs the
  creator's method id as `did + "#" + multibase_ed25519(pk)`, but §4.4's examples used
  arbitrary `#key-creator` / `#key-alice` labels. The amendment pins the fragment to the
  method's own `publicKeyMultibase`, so a method id is self-certifying (reconstructible from
  the key, collision-free, identical across implementations) and marks the `#key-*` labels
  elsewhere as non-normative mnemonics. This implementation uses `<did>#<publicKeyMultibase>`
  throughout (`group_detail::MethodId`).
- **(ii) `groupify` takes the live `Graph`, not a `graph://` IRI** — draft §4.3 ("Durable
  identity vs. content address") + §8.2.2. A graph's content-address IRI advances on every
  write, **including the groupification bootstrap itself** (§4.2 step 4), so an IRI captured
  before the call cannot identify the graph after it and an IRI-keyed lookup can race the
  bootstrap write. The amendment changes the `groupify(USVString graphIri, …)` signature to
  `groupify(Graph graph, …)`, pins the DID (content-independent) as the durable group key,
  and records that the binding triple's subject is the graph's pre-final-state IRI (a
  consumer MUST NOT assume it equals the current `iri`). The browser keys graphs by a stable
  internal id and the Blink `groupify(Graph)` binding hands that id straight through.

---

## Spec 04 — Graph Capability Framework ✅

Fully implemented and tested. The framework layers [[ZCAP-LD]] capability
delegation (§4.5.3) and a three-mode enforcement engine (§5) onto a groupified
Spec 03 graph. All governance state lives as ordinary `governance://` and
`zcap://` triples **inside the host graph it governs** — there is no side table —
so a capability minted by one engine verifies byte-for-byte under another. The
engine (`content/browser/governance/governance_backend.*` + `zcap.*`, namespace
`living_web`) is Chromium-independent and shared verbatim by the browser-process
governance host and the standalone harness. Normative behaviour is exercised by
the 24 `Cap_*`/`Zcap_*` blocks of the C++ harness (`living_web_tests`, 91 tests
total, all green), 26 `GovernanceBackend*` browser gtests
(`tests/governance_backend_unittest.cc`), and the 11-test WPT
(`tests/web_platform_tests/graph/graph-capabilities.html`). The §11 governance
surface is folded onto `Graph` and §8.1.5 `delegateCapability` onto `Group`, both
off `navigator.graph`.

### §11 renderer governance surface (partial interface `Graph`)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `enforcementMode()` → `EnforcementMode` | §5.1, §11.4 | ✅ | ✅ | ✅ | ✅ | Reads `governance://enforcement_mode`; a graph with no DID or no mode token reports `"open"`. |
| `setEnforcementMode(mode)` | §5.2, §11.4 | ✅ | ✅ | ✅ | ✅ | Round-trips `open`/`announced`/`enforced`; unknown token → `TypeError` (IDL enum). Guarded by `updateGovernance` **only once a capability constraint exists**; a DID-less graph → `InvalidStateError`. |
| `canAddTriple(triple)` → `GovernanceValidationResult` | §7, §11.1 | ✅ | ✅ | ✅ | ✅ | Derives the action from the predicate (§4.5.4.1) and runs §7; in `open` mode short-circuits to ACCEPT. Result echoes `{allowed, rejectedBy?, constraintKind?, reason?, mode}`. |
| `canPerformAction(action, authorDid, proof?)` | §7, §11 | ✅ | ✅ | ✅ | ✅ | Evaluates an explicit author against the graph's capabilities; unauthorised author under `enforced` → `{allowed:false, constraintKind:"capability"}`. Optional `CapabilityProofInput` carries an off-graph chain. |
| `myCapabilities()` → `sequence<CapabilityInfo>` | §4.3, §11.3 | ✅ | ✅ | ✅ | ✅ | Capabilities the active author holds (eligible, unrevoked, caveats satisfied, chain walks to a local root). Empty until the root is lazily minted. |
| `constraintsFor(contextDid)` → `sequence<GraphConstraint>` | §4.5.1, §11.2 | ✅ | ✅ | ✅ | ✅ | Reports `governance://has_constraint` bindings as `{id, kind, scope, properties}`; `entry_type`/`constraint_kind` are structural and excluded from `properties`. |

### ZCAP delegation & root capability (§4.3, §4.5.3, §8.1.5)

| Capability | Spec | IDL | C++ | WPT | Status | Notes |
|------------|------|-----|-----|-----|--------|-------|
| Lazy root minting | §4.3 | — | ✅ | ✅ | ✅ | The root is **not** minted at group creation; the first `delegateCapability` mints it via `EnsureRootCapability`. Invoker = resource = the group `did:graph`; the creator (in every capability section) then holds it. |
| Default root action set = 8 framework-core | §4.3, §4.5.4 | — | ✅ | ✅ | ✅ | `createLink, removeLink, updateGovernance, updateDIDDocument, delegateCapability, mountContext, forkGraph, announceFork` (`DefaultRootActions`). Extension actions excluded — see Amendment (i). |
| `Group.delegateCapability(options)` → `SignedContent` | §8.1.5 | ✅ | ✅ | ✅ | ✅ | Signs a ZCAP-LD delegation by the group DID (`Ed25519Signature2020`, `proof.method` = `<groupDid>#<multibase>`, `z`-prefixed base58btc signature). `DelegateOptions` = `{invoker, actions, resource, caveats?, expiresAt?}`. |
| Flattened ZCAP triples on the `zcap://` scheme | §4.5.3 | — | ✅ | ✅ | ✅ | `zcap://invoker/parentCapability/actions/resource/caveats/proofValue/proofPurpose/proofMethod/created` + `rdf:type zcap://Delegation`. Pinned by Amendment (ii). |
| Delegation-proof pre-image (exact bytes) | §4.5.3.1 | — | ✅ | ✅ | ✅ | `BuildDelegationProofPreimage`: versioned tag + 8 LF-joined signed fields, SHA-256-then-Ed25519. New §4.5.3.1 — Amendment (iii); covered by `Zcap_DelegationProofPreimageExactBytes`. |
| Attenuation (actions subset, resource fixed, caveats immutable) | §7, §8 | — | ✅ | — | ✅ | A child delegation's actions MUST be a subset of the parent's; resource escalation and caveat weakening are rejected (`Cap_DelegateAttenuatesActions`, `…RejectsResourceEscalation`, `…CaveatsAreImmutable`). |

### Enforcement modes (§5) & verification (§7)

| Behaviour | Spec | C++ | WPT | Status | Notes |
|-----------|------|-----|-----|--------|-------|
| `open` (default) skips capability checks | §5.1 | ✅ | ✅ | ✅ | §7 step 1 short-circuits to ACCEPT; writes ungated. |
| `announced` computes & audits, never rejects | §5.3 | ✅ | — | ✅ | Capability decision is computed for the audit record but the write is always admitted (`Cap_AnnouncedModeComputesButAccepts`). |
| `enforced` is a mandatory data-layer gate | §5, §11.5 | ✅ | ✅ | ✅ | `addTriple` runs §7 per triple; an unauthorised author → `NotAllowedError`. The root-holding creator's ordinary write is admitted. |
| Chain walk terminates at the local `BootstrapRoot` | §4.3, §7 | ✅ | — | ✅ | Local-root re-verification against the graph's own `governance://root_capability` — Amendment (i); `Cap_TwoLevelDelegationChainAuthorises`. |
| Eligibility: a `did:graph` invoker is eligible for its section members | §7 | ✅ | ✅ | ✅ | A capability whose invoker is a group DID is eligible for any author in that DID's `capabilityInvocation` section (group-of-one ⇒ the creator). |
| Deny-wins composition, greatest-id audit tiebreak | §4.4, §6.3 | ✅ | — | ✅ | Any rejecting same-kind constraint rejects the write; `rejectedBy` attributes to the lexicographically-greatest constraint id. |

### Caveats (§9), revocation (§4.5.5, §8) & constraints (§4.5.1, §10)

| Behaviour | Spec | C++ | WPT | Status | Notes |
|-----------|------|-----|-----|--------|-------|
| Expiry caveat | §9 | ✅ | — | ✅ | An expired capability is inert; a live one authorises (`Cap_ExpiryCaveatBlocksExpiredAllowsLive`). Carried verbatim as the `zcap://caveats` JSON literal. |
| Pluggable caveat & constraint-kind handlers | §9 | ✅ | — | ✅ | Applications register caveat/constraint-kind handlers; an unknown `constraint_kind` fails closed (`Cap_UnknownConstraintKindFailsClosed`, `…PluginCaveatHandler`, `…PluginConstraintKindHandler`). |
| Revocation by an authorised agent | §4.5.5 | ✅ | — | ✅ | Writes `governance://revokes_capability`; a revoked delegatee is denied (`Cap_RevokeBlocksDelegatee`). |
| Root is unrevokable; brick-guarded revocation | §4.5.5, §8 | ✅ | — | ✅ | The local root cannot be revoked; a revocation that would strip the last governance authority is refused (`Cap_RootCapabilityIsUnrevokable`, `…RefusedWhenItWouldBrickGovernance`). |
| Capability constraint definition + `constraintsFor` | §4.5.1 | ✅ | ✅ | ✅ | `entry_type = governance://constraint`, `constraint_kind = "capability"`, optional `capability_predicates`; bound to the graph DID via `has_constraint`. |
| Immutable seed predicates rejected in all modes | §10 | ✅ | ✅ | ✅ | A write to `group://syncModule`/`forkedFrom`/`forkedAtRevision` on the graph DID is rejected even for the creator; surfaces at `addTriple` as `NotAllowedError` (`Cap_ImmutableSeedPredicateRejectedInAllModes`). |

### Normative parameters

- **Framework-core actions** (§4.5.4): the eight in `DefaultRootActions()`. Extension
  actions (`updateSHACL`, `updateFlow`) are conservative-by-default — an unknown action
  requires an explicit capability.
- **Action derivation** (§4.5.4.1): predicate-prefix registry `governance://` →
  `updateGovernance`, `did-document://` **and** `did://` → `updateDIDDocument` (Amendment
  (iv)); otherwise `createLink` (add) / `removeLink` (remove).
- **Enforcement gate reach**: `setEnforcementMode` is authority-gated only once a capability
  constraint exists (§5.2); the data-layer `NotAllowedError` gate is reached only in
  `enforced` mode. A DID-less Spec 02 graph has nothing to govern — its surface is inert and
  `"open"`, and enabling enforcement is `InvalidStateError`.
- **Active author**: `createGroup` adopts the group key but leaves the human's `did:key`
  active, so `graph.addTriple`/`canAddTriple`/`myCapabilities` author as the creator; group
  governance ops scope-switch the active credential and restore it.
- Authoritative reference impl: `standalone/capability_provider.h` over
  `content/browser/governance/{governance_backend,zcap}.*`, verified by the 24
  `Cap_*`/`Zcap_*` tests in `standalone/living_web_tests.cc`; the browser port
  (`content/browser/graph/personal_graph_host.*` gating + `governance_backend.*`) and the
  renderer (`third_party/blink/renderer/modules/graph/graph.*` §11 surface,
  `group.*` `delegateCapability`) mirror it.

### Amendments

Four under-specified areas surfaced while implementing Spec 04 have been **folded
into draft 04 as normative detail** on `w3c-living-web-proposals` `main` (the same
practice used for Specs 01–03). None weakens the implementation; each removes an
interoperability hazard the draft left open:

- **(i) The default root action set is exactly the eight framework-core actions**, and
  local-root re-verification is mandatory — draft §4.3. The draft's §4.3 example listed
  **nine** actions including `updateSHACL`, contradicting §4.5.4 (which defines `updateSHACL`
  as an *extension* action from [[SHAPE-VALIDATION]]) and the §15 walkthrough. The amendment
  pins the freshly-minted root to the eight framework-core actions and forbids widening it;
  extension actions are conferred only by an extension's own bootstrap or an explicit
  delegation. It also makes **local-root re-verification** normative: a `BootstrapRoot`-parented
  capability MUST match the writing graph's own `governance://root_capability` or the walk
  fails closed. Implemented as `DefaultRootActions()` (8 actions) + the root-id check in the
  chain walk.
- **(ii) Flattened ZCAP predicates are pinned to the `zcap://` scheme** — draft §4.5.3. The
  draft showed the ZCAP triples with the JSON-LD compact prefix `zcap:` (namespace
  `https://w3id.org/zcap/v1#`) but never fixed the **substrate** predicate IRIs, leaving the
  intra-graph form implementation-defined. The amendment pins one predicate per field on the
  resolver-independent `zcap://` scheme (`zcap://invoker`, `zcap://actions`, …) as the
  canonical form the verification algorithm queries and the pre-image is computed over.
- **(iii) The delegation-proof pre-image is fixed byte-for-byte** — new draft §4.5.3.1. The
  draft left the exact bytes a delegation's `zcap://proofValue` signs unspecified, so ZCAPs
  could not verify across implementations. The amendment fixes the pre-image as a
  domain-separation tag (`living-web/zcap/delegation/v1`) followed by eight signed fields
  (`id`, `invoker`, `parentCapability`, `actions`, `resource`, `caveats`, `proofPurpose`,
  `created`), LF-joined with no trailer, hashed with SHA-256 and signed raw-Ed25519 —
  excluding `rdf:type`, `proofMethod`, and `proofValue`. Implemented as
  `BuildDelegationProofPreimage`; covered by `Zcap_DelegationProofPreimageExactBytes`.
- **(iv) The `did://` predicate family maps to `updateDIDDocument`** — draft §4.5.4.1. The
  action-derivation registry mapped only `did-document://`, but [[GROUP-IDENTITY]] §4.4 stores
  a group's live DID-document state as `did://*` triples in the host graph. Without this
  mapping, writes that mutate signing authority would derive `createLink` and escape the
  `updateDIDDocument` gate. The amendment adds `did://` → `updateDIDDocument` alongside
  `did-document://` (the two never overlap). Registered in the engine constructor's action
  prefixes.

---

## Spec 05 — Graph Synchronisation Protocol ✅

Fully implemented and tested. The protocol layers a peer-to-peer diff-gossip
session onto a groupified graph (Spec 03) governed by the capability framework
(Spec 04): a local mutation becomes a signed `GraphDiff`, gossiped to peers who
independently `validateDiff` it against the graph's own governance so every
honest peer reaches the same verdict (§9.2.1) and the DAG converges (§9.3). The
diff-identity and sync-space-derivation core
(`content/browser/graph_sync/graph_diff.*`, namespace `living_web`) has **no
Chromium dependencies** and is shared byte-for-byte by the browser sync backend
(`content/browser/graph_sync/sync_backend.*`) and the standalone harness
(`standalone/sync_provider.h`), so the bytes a diff is content-addressed and
signed over never diverge between build worlds. The §6 renderer surface is
**folded** onto `Graph` (a `partial interface Graph`: publish/unpublish +
syncState, peer inspection, pending-diff retrieval, ephemeral signalling) and
onto `GraphManager` (a `partial interface GraphManager`: mount/unmount + the
realm's listMounted / listModules / listSpaces inventory and the subscription
events) — not a separate service — because a realm keeps a single
`PersonalGraphManager`, which owns one shared `SyncBackend` and the mount table.
Normative behaviour is exercised by the 29 `Sync_*` blocks of the C++ harness
(`living_web_tests`, 120 tests total, all green), 29 browser gtests (6
`SyncGraphDiffCoreTest` + 23 `SyncBackendTest`,
`tests/sync_backend_unittest.cc`), and the 18-test WPT
(`tests/web_platform_tests/graph/graph-sync.html`).

The **live peer transport** — real peer lists, wire delivery of diffs and
signals, and sync-module installation — is [[SYNC-MODULE-ARCHITECTURE]] (Spec
06). Until a module is attached the session layer is trivially converged: peer
lists are empty, `peerCount` is 0, signalling is a validated no-op, and the
module inventory is empty. Everything the protocol layer itself owns — diff
construction, validation, space derivation, invitations, and the durable queue —
is complete here.

### §6 renderer sync surface (partial interface `Graph`)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `publish(options)` → `PublishedGraph` | §6.1 | ✅ | ✅ | ✅ | ✅ | Derives the `space://` URI (§7.3), marks the graph published + writable, advances to `synced`. A DID-less graph → `InvalidStateError`; an `options.moduleHash` disagreeing with the graph's `group://syncModule` binding → `InvalidStateError`. Returns `{graphDid, spaceUri, moduleHash, relays}`. |
| `unpublish()` | §6.1 | ✅ | ✅ | ✅ | ✅ | Tears the subscription down and returns to `idle`; idempotent (a never-published graph resolves). |
| `syncState()` → `GraphSyncState` | §5.5, §6.3 | ✅ | ✅ | ✅ | ✅ | `"idle"` until published or mounted, then `"synced"`; `onsyncstatechange` fires on transitions. |
| `peers()` / `onlinePeers()` → `sequence<Peer>` | §6.3 | ✅ | ✅ | ✅ | ✅ | Empty until a sync module supplies transport (Spec 06). |
| `currentRevision()` → `USVString` | §5.2.1, §6.3 | ✅ | ✅ | ✅ | ✅ | The local DAG head; `""` until the first local commit. |
| `pendingDiffs()` → `sequence<GraphDiff>` | §6.3, §13.1 | ✅ | ✅ | ✅ | ✅ | Readout of the durable local diff queue; empty when converged. |
| `sendSignal` / `sendSignalToSession` / `broadcast` | §6.3, §11 | ✅ | ✅ | ✅ | ✅ | `InvalidStateError` before publish/mount; after, a validated no-op success (the payload is dropped until a sync module supplies transport). |
| events `onpeerjoined` / `onpeerleft` / `onsyncstatechange` / `onsignal` / `ondiff` | §6.3 | ✅ | ✅ | ✅ | ✅ | Assignable `EventHandler`s dispatched off the host's subscribed client. |

### §6.2 / §6.4 realm sync inventory (partial interface `GraphManager`)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `mount(graphDid, options)` → `Graph` | §6.2 | ✅ | ✅ | ✅ | ✅ | One mount per DID per realm — a second → `InvalidStateError`. A read mount is authorised by the §9.2.2 `mountContext` gate, a write/governance mount by the `createLink` authority; an unauthorised mount → `NotAllowedError`. Materialises an external-trust backend the sync module fills. |
| `unmount(graphDid)` | §6.2 | ✅ | ✅ | ✅ | ✅ | `NotFoundError` when not mounted; drops the entry and announces `onsubscriptionlost`. A renderer dropping the mounted `Graph` is an implicit unmount. |
| `listMounted()` → `sequence<MountedGraphInfo>` | §6.4 | ✅ | ✅ | ✅ | ✅ | `{graphDid, mode, syncState, spaceUri, moduleHash, peerCount}`. |
| `listModules()` → `sequence<SyncModuleInfo>` | §6.4 | ✅ | ✅ | ✅ | ✅ | Inventory owned by the module runtime (Spec 06); empty at the protocol layer. |
| `listSpaces()` → `sequence<SyncSpaceInfo>` | §6.4, §7.2 | ✅ | ✅ | ✅ | ✅ | Aggregates the realm's active spaces from **both** the mount table and the local graphs its hosts have published; `graph_count` sums a unified topology, and a mount-backing host reports `published()==false` so the two sources never double-count. |
| events `onsubscriptiongained` / `onsubscriptionlost` | §6.4 | ✅ | ✅ | ✅ | ✅ | Fire as a mount gains or loses diff delivery in a space; a host disconnect emits a single `lost`. |

### §5 diff identity & construction (`graph_diff` core)

| Behaviour | Spec | C++ | Test | Status | Notes |
|-----------|------|-----|------|--------|-------|
| `revision` pre-image (exact bytes) | §5.2.2, §5.2.2.1 | ✅ | ✅ | ✅ | Length-framed: version tag, `graphDid`, then the byte-length-framed `rdfc-1.0` canonical N-Quads of the additions and removals, then the sorted dependency revisions; SHA-256 → lowercase hex. Framing is length-prefixed because N-Quads contain LF. Amendment (i); `Sync_RevisionPreimageExactBytes`. |
| `commitId` pre-image (exact bytes) | §5.2.2, §5.2.2.1 | ✅ | ✅ | ✅ | `tag ⧺ revision ⧺ author ⧺ timestamp ⧺ leafZcapId`, LF-joined, no trailer; SHA-256 → lowercase hex. `Sync_CommitIdPreimageExactBytes`. |
| `signature` over the commitId directly | §5.2.2, §5.2.2.1 | ✅ | ✅ | ✅ | Ed25519 over the UTF-8 bytes of the lowercase-hex `commitId` — signed directly, **not** re-hashed (Ed25519 hashes internally). Amendment (i); `Sync_SignatureMessageIsCommitIdDirect`. |
| Committer-authored reifiers | §5.1, §5.2.2 | ✅ | ✅ | ✅ | Every diff triple carries a reifier the committer signs over the Spec 02 §3.2.1 pre-image; canonicalised together with the triple, so a receiver reproduces the exact wire bytes. |
| `sort(dependencies)` | §5.2.1 | ✅ | ✅ | ✅ | Ascending lexicographic over the lowercase-hex revisions, de-duplicated. `Sync_SortDependenciesOrdersAndDedups`. |

### §9 validation (`validateDiff` steps 0–6, `validateReadAccess`)

| Step | Spec | C++ | Test | Status | Notes |
|------|------|-----|------|--------|-------|
| 0 — bundle signature | §9.2.1 | ✅ | ✅ | ✅ | Recomputes `revision` + `commitId` and verifies the Ed25519 bundle signature against the resolved author key; a tamper of any bound field → `revision_invalid` / `commit_invalid` / `signature_invalid` (kind `capability`). `Sync_BundleSignatureTamperRejected`, `…RevisionTamperRejected`. |
| authorKey resolution | §5.2.2 | ✅ | ✅ | ✅ | The author's `did:key`, or — for a graph-DID author — the current `capabilityDelegation` delegate keys projected from that DID's document in the target graph. |
| 1–3 — capability chain + caveats | §9.2.1, §9.4 | ✅ | ✅ | ✅ | Delegated to the Spec 04 `GovernanceEngine`: constraint collection (§6.2), chain-walk to `BootstrapRoot` (§7), content-caveat re-evaluation (§9), deny-wins (§6.3), enforcement-mode awareness (§9.4). |
| 4 — reifier signatures + author binding | §9.2.1, §5.2.2 | ✅ | ✅ | ✅ | Each reifier signature is verified; a reifier attributed to an agent other than the diff's committer is rejected before any key work → `reifier_signature_invalid`, closing the author-smuggle hole. `Sync_ReifierAuthorSmuggleRejected`. |
| 5 — dependencies | §5.2.1 | ✅ | ✅ | ✅ | The chain-root rule: a `deps=0` diff is valid only as the graph's first diff or when it advertises a snapshot promotion (else `chain_root_conflict`); an unknown named revision → `missing_dependency`. `Sync_ChainRootAndSnapshotPromotion`, `…MissingDependencyRejected`. |
| §14.5 timestamp plausibility | §14.5 | ✅ | ✅ | ✅ | Future bound (>300 s ahead → `timestamp_future`), causal monotonicity (≥ max dependency timestamp → `timestamp_causal`), and per-author monotonicity (`timestamp_monotonic`); malformed → `timestamp_malformed` (kind `temporal`). Amendment (iii); `Sync_TimestampFutureRejected`, `…CausalRejected`, `…MonotonicRejected`. |
| 6 — accept & record; §14.4 replay | §9.2.1, §14.4 | ✅ | ✅ | ✅ | An accepted revision enters the local chain; a re-delivered already-applied revision is an idempotent no-op accept. |
| `validateReadAccess` — the `mountContext` gate | §9.2.2 | ✅ | ✅ | ✅ | Accepts an unrestricted read; a graph bearing a capability constraint rejects a stranger. `Sync_ReadAccessOpenGraphAccepts`, `…ReadAccessRestrictedGraphRejectsStranger`. |

### §7 topology & sync-space derivation

| Behaviour | Spec | C++ | Test | Status | Notes |
|-----------|------|-----|------|--------|-------|
| Restricted classification | §7.2 | ✅ | ✅ | ✅ | A graph is *restricted* for read iff it binds a `capability` constraint (which covers the non-triple `mountContext` action) — keyed off the constraint's presence, **not** `enforcement_mode`. `Sync_IsRestrictedTracksCapabilityConstraint`. |
| Space derivation → `space://<sha256-hex>` | §7.3 | ✅ | ✅ | ✅ | Hashes `BuildSpaceDerivationInput` for the four topologies (unified `lwsync:unified:`, privacy-tiered → `public:`/`dedicated:` by restriction, fully-partitioned `dedicated:`, custom `named:`); the namespace id is the graph's `context://participates_in` root, falling back to the graph DID. `Sync_SpaceDerivationInputPerTopology`, `…DeriveSpaceProducesStableSpaceUri`, `…TopologyTokenRoundTrip`. |

### §12 invitations & §13 reconnection

| Behaviour | Spec | C++ | Test | Status | Notes |
|-----------|------|-----|------|--------|-------|
| Invitation link format + parse | §12.1, §12.2 | ✅ | ✅ | ✅ | `web+graph://<relay>/<space-uri-base64url>?did=&module=&name=`: `did` REQUIRED (missing → reject), `module`/`name` OPTIONAL and percent-encoded; a wrong scheme → reject. Amendment (ii); `Sync_InvitationFormatParseRoundTrip`, `…OptionalFieldsAbsent`, `…RequiresDid`, `…RejectsWrongScheme`. |
| Durable local diff queue | §13.1 | ✅ | ✅ | ✅ | Locally-committed, not-yet-acknowledged diffs indexed and de-duplicated by `commitId`, preserving commit order for the flush. Amendment (iv); `Sync_DiffQueueDedupesByCommitId`. |
| Batch policy | §13.4 | ✅ | ✅ | ✅ | Up to 100 diffs / 3000 ms per flush, commit-ordered. `Sync_DiffQueueBatchCapsAndOrders`. |
| Reconnect backoff | §13.3 | ✅ | ✅ | ✅ | 5 s initial, ×2 per failed attempt, capped at 300 s. `Sync_ReconnectBackoffDoublesAndCaps`. |

### Normative parameters

- **Canonicalisation** (§5.2.2): `rdfc-1.0` canonical N-Quads over the
  triples-with-reifiers block; the empty set canonicalises to the empty string.
  Identical to the Spec 02 §5.2 profile, so a diff's content address is
  reproducible on any peer.
- **Timestamp plausibility** (§14.5): future bound 300 s; a diff's timestamp MUST
  be ≥ every dependency's timestamp and ≥ the author's last applied timestamp.
- **Reconnection** (§13.3–§13.4): backoff 5000 ms initial, ×2, cap 300000 ms;
  batch cap 100 diffs / 3000 ms.
- **Session-layer scope**: publish/mount/syncState/peers/currentRevision/
  pendingDiffs/signalling are browser-only session glue over the shared
  validation core. Live peer transport, real peer lists, and module installation
  are Spec 06 — until a module is attached peers are empty, signalling is a
  no-op success, and the module inventory is empty. Everything the protocol layer
  owns (diff identity, validation, space derivation, invitations, the durable
  queue) is complete.
- Authoritative reference impl: `standalone/sync_provider.h` (`SyncEngine` +
  `DiffQueue`) over the shared `content/browser/graph_sync/graph_diff.*` and the
  browser `content/browser/graph_sync/sync_backend.*`, verified by the 29
  `Sync_*` tests in `standalone/living_web_tests.cc`; the browser port
  (`content/browser/graph/personal_graph_host.*` session surface +
  `personal_graph_manager.*` mount/inventory) and the renderer
  (`third_party/blink/renderer/modules/graph/graph.*` §6 surface,
  `graph_manager.*` mount/inventory) mirror it.

### Amendments

Four under-specified areas surfaced while implementing Spec 05 have been **folded
into draft 05 as normative detail** on `w3c-living-web-proposals` `main`. None
weakens the implementation; each removes an interoperability hazard the draft
left open:

- **(i) The `revision` / `commitId` pre-images and the signature message are
  fixed byte-for-byte** — new draft §5.2.2.1. The draft named the fields a diff is
  content-addressed and signed over but not the exact bytes, so two
  implementations could compute different `revision`/`commitId` for the same diff
  and never converge. The amendment pins: the `revision` pre-image (a
  domain-separation tag, the `graphDid`, and the **byte-length-framed** `rdfc-1.0`
  canonical N-Quads of the additions and removals, then the sorted dependency
  revisions — length-framed because N-Quads embed LF); the `commitId` pre-image
  (tag, `revision`, `author`, `timestamp`, leaf-capability id, LF-joined, no
  trailer); both SHA-256 → lowercase hex; and that the bundle `signature` is
  Ed25519 over the UTF-8 lowercase-hex `commitId` **directly** (no second
  SHA-256). It mirrors the Spec 04 §4.5.3.1 delegation-proof amendment.
  Implemented in `graph_diff.*` (`BuildRevisionPreimage` / `BuildCommitIdPreimage`
  / `BuildSignatureMessage`); covered by `Sync_RevisionPreimageExactBytes`,
  `…CommitIdPreimageExactBytes`, `…SignatureMessageIsCommitIdDirect`.
- **(ii) Graph invitation links have a fixed format and processing model** —
  draft §12. The draft described inviting a peer to a graph but left the link
  syntax unspecified. The amendment pins the `web+graph://` form
  (`<relay-host>/<space-uri-base64url>?did=&module=&name=`), makes `did` REQUIRED
  and `module`/`name` OPTIONAL, fixes `moduleHash` precedence (an explicit link
  module overrides the graph's `group://syncModule` default) and the
  percent-encoding of `name`. Implemented as `FormatInvitation` /
  `ParseInvitation`; covered by the four `Sync_Invitation*` tests.
- **(iii) Received timestamps have a plausibility bound** — draft §14.5. The draft
  trusted a diff's `timestamp` for causal ordering without bounding it, so a
  malicious or skewed committer could poison the DAG order. The amendment makes a
  future bound (300 s), causal monotonicity (≥ every dependency's timestamp), and
  per-author monotonicity normative on every path that trusts the timestamp.
  Implemented as `CheckTimestamp`; covered by `Sync_TimestampFutureRejected`,
  `…CausalRejected`, `…MonotonicRejected`.
- **(iv) Reconnection and offline handling are specified** — draft §13. The draft
  assumed continuous connectivity. The amendment adds the durable local diff queue
  (keyed by `commitId`), the exponential-backoff reconnection schedule (§13.3),
  and the batching policy (§13.4) a peer uses to catch up after a partition.
  Implemented as `DiffQueue` + `ReconnectBackoffMs` + the batch constants; covered
  by `Sync_DiffQueueDedupesByCommitId`, `…DiffQueueBatchCapsAndOrders`,
  `…ReconnectBackoffDoublesAndCaps`.

---

## Spec 06 — Sync Module Architecture ✅

Fully implemented and tested. Spec 06 is the **capability-scoped host runtime**
that installs, consents to, instantiates and mediates the pluggable WebAssembly
sync modules Spec 05 defers to — the layer that turns the trivially-converged
session surface into a live, module-driven one. A module is a WebAssembly
component that *imports* the eight §6.3 capability-scoped host surfaces
(host-graph, host-crypto, host-network, host-storage, host-clock, host-random,
host-log, host-consent) and *exports* the §5.1 `GraphSyncModule` contract; the
runtime authorises **every** host call against the module's §8 capability grants,
its per-instance scope, and its §8.1 storage quota before carrying it down to the
real browser backend, so a module cannot forge its way past a `not-authorised`
(§8.3). Installation, consent and instantiation are user-mediated browser
operations (§7.1, §7.2) with **no script surface** — a page cannot install a
module or grant its own consent — so the only renderer-visible face of the runtime
is the §6.4 read-only `listModules()` inventory already carried by `graph.mojom`
and the `GraphManager` partial interface (added with the Spec 05 seam).

The two byte-critical cores are Chromium-independent (namespace `living_web`,
pure-std): `content/browser/module_runtime/module_manifest.*` (the §4.2
content-address `"sha256-" + hex(SHA-256(wasm))`, the §8.2 manifest parse + its
§8.2 mutual-verifiability binding, and the §7.3 fork constraint-kind superset
check) and `content/browser/module_runtime/module_capabilities.*` (the §8
capability vocabulary, the §6.3 `host-error` variant, and the grant algebra every
host surface consults). They are shared **byte-for-byte** by the browser host
(`module_runtime_host.*` + the concrete backings `module_runtime_backends.*`:
`ModuleGraphAdapter` over a real `GraphBackendManager`, `ModuleCryptoAdapter` over
the §5.4 `DIDKeyProvider` scoped signer) and the standalone harness
(`standalone/module_runtime_provider.h`), so every content-hash, manifest binding,
capability-token parse and quota decision is identical between the two build
worlds. Normative behaviour is exercised by the 17 `Module_*` blocks of the C++
harness (`living_web_tests`, 137 tests total, all green) and mirrored by the 17
browser gtests (`tests/module_runtime_host_unittest.cc`,
`ModuleRuntimeHostTest.*`, bound to the real `DIDKeyProvider` +
`GraphBackendManager`); the §6.4 renderer surface is pinned by the WPT
(`tests/web_platform_tests/graph/sync-modules.html`).

The module-facing ABI is the **normative WIT world** `graph-sync-module`
(`content/browser/module_runtime/graph_sync_module.wit`, §6.3) — the WebIDL of §5
is illustrative and the WIT governs where the two disagree. It is checked in
verbatim beside the host as a reference asset a component toolchain binds against;
it is not compiled by the `module_runtime` source_set (a `.wit` is not C++). The
host implements the host side of the same seven §6.3 imports.

### §7 lifecycle — installation, consent, instantiation, suspend/resume/remove

| Behaviour | Spec | C++ | Test | Status | Notes |
|-----------|------|-----|------|--------|-------|
| §4.2 content-addressing | §4.2, §9.2 | ✅ | ✅ | ✅ | `content-hash = "sha256-" + hex(SHA-256(wasm))` (71 chars, lowercase hex); the runtime verifies it over the actual binary before install. `Module_ContentHash_FormatAndWellFormedness`. |
| §8.2 manifest parse + binding | §8.2, §7.1 | ✅ | ✅ | ✅ | Required `name`/`version`/`wasmContentHash`/`supportedConstraintKinds`/`capabilitiesRequired`; optional `publisher`/`description`; unknown top-level fields ignored. A manifest whose `wasmContentHash` does not bind the installed binary → `invalid-argument`. `Module_Manifest_*`. |
| §7.1 installation | §7.1 | ✅ | ✅ | ✅ | Verifies the content hash **and** rejects a manifest requiring any capability token outside the §8 vocabulary (`invalid-argument`); a fresh install lands consent-pending. `Module_Install_VerifiesContentHashAndCaps`. |
| §7.2 consent gating | §7.2, §8.3 | ✅ | ✅ | ✅ | Instantiation before `grantConsent` is `not-authorised`; a later `denyConsent` immediately closes every host surface — no forging past a revoked grant. `Module_Consent_GatesInstantiationAndSurfaces`. |
| §4.4 instancing | §4.4 | ✅ | ✅ | ✅ | One instance per (content-hash, space-uri), each carrying its own authorised graph-DID set; space A cannot reach a graph authorised only in space B (`unknown-scope`). `Module_Instancing_PerSpaceScope`. |
| §7.5 suspend / resume | §7.5 | ✅ | ✅ | ✅ | Suspension stops surface activity (`not-authorised`); resume restores it without re-instantiation, stores intact. `Module_Lifecycle_SuspendResumeRemovePreservesStores`. |
| §7.4 remove (stores preserved) | §7.4 | ✅ | ✅ | ✅ | Removal drops instances + grants but **preserves** the per-graph store across a grace period; `purgeStorage` truly clears it. Same test. |
| §7.3 fork precondition | §7.3, §8.2 | ✅ | ✅ | ✅ | A forked child module may replace the parent only if its `supportedConstraintKinds` is a superset of every kind in force on the parent; the missing kinds are the rejection reason. `Module_Fork_ConstraintKindSuperset`. |

### §8 capability + scope + quota enforcement (the seven §6.3 host imports)

| Host surface | Capability (§8) | C++ | Test | Status | Notes |
|--------------|-----------------|-----|------|--------|-------|
| host-graph reader/writer | `graph.read` / `graph.write` | ✅ | ✅ | ✅ | Real reads (query-triples / SPARQL / snapshot) and writes (a `GraphDiff` lands in the Spec 02 store) against the authorised graph; a graph outside the set → `unknown-scope`; a write without `graph.write` → `not-authorised`. `Module_HostGraph_*`. |
| host-storage | `storage.module.<size>` | ✅ | ✅ | ✅ | Keyed by (content-hash, graph-did); the declared byte cap counts key+value; one byte over → `quota-exceeded`; module B shares the graph but sees none of A's keys (§9.5 isolation); delete frees the accounting; prefix-filtered list-keys. `Module_HostStorage_QuotaScopeAndIsolation`. |
| host-network relay/peer/fetch | `network.relay.<endpoint>` / `network.peer.<protocol>` / `network.fetch.<origin>` | ✅ | ✅ | ✅ | Endpoint/protocol/origin-scoped over a real byte-stream transport with send/receive/close; an un-granted endpoint, mismatched protocol, or foreign fetch origin → `not-authorised`. `Module_HostNetwork_GatingAndTransport`. |
| host-clock / host-random | `time.wallclock` / `time.monotonic` / `random.csprng` | ✅ | ✅ | ✅ | Wall-clock coarsened to 1 s (fingerprinting countermeasure); a module without the grant is `not-authorised` on every clock/random surface. `Module_HostClockRandom_GatingAndCoarsening`. |

### §5.4 / §9.7 scoped signer (host-crypto)

| Behaviour | Spec | C++ | Test | Status | Notes |
|-----------|------|-----|------|--------|-------|
| commit signer + build ledger | §5.4, §9.7 | ✅ | ✅ | ✅ | A `commit-id` the module never built via `module.commit` cannot be signed (`signing-refused`); once the runtime observes the build it becomes eligible and the 64-byte Ed25519 signature verifies over the commit-id. Requires `crypto.commit-sign`. `Module_ScopedSigner_CommitLedgerAndVerify`. |
| signal signer | §5.4 | ✅ | ✅ | ✅ | A signal envelope is signed only with `crypto.signal-sign`; without it, `not-authorised`. `Module_ScopedSigner_SignalGatedByCapability`. |
| scoped-signer identity | §5.4 | ✅ | ✅ | ✅ | The browser `ModuleCryptoAdapter` signs "on behalf of the local agent" — the `DIDKeyProvider`'s active credential — and `verify` (a pure, key-free operation gated by `crypto.verify`) checks against its DID. The standalone provider uses a dedicated signer credential; both drive the identical grant algebra. |

### §6.4 module inventory (renderer surface, partial interface `GraphManager`)

| API | Spec | IDL | C++ | WPT | Status | Notes |
|-----|------|-----|-----|-----|--------|-------|
| `listModules()` → `sequence<SyncModuleInfo>` | §6.4 | ✅ | ✅ | ✅ | The read-only inventory: each `SyncModuleInfo` projects `{contentHash, name?, spaceCount, state, storageBytes}` where `state` ∈ `ModuleState` (`"running"`/`"suspended"`/`"error"`); a stable read on an unchanged realm. Installation being user-mediated, an unprivileged page observes an empty inventory (a `group://syncModule` reference is not an installed component), which the WPT tolerates. `Module_ListModules_Introspection`. |

### Normative parameters

- **Content address** (§4.2): `"sha256-"` prefix + 64 lowercase hex = one 32-byte
  SHA-256 digest of the WASM binary; the SHA-256 primitive resolves per build
  world (`//crypto` vs `standalone/crypto_sha2.h`), the format/binding core is
  shared.
- **Capability vocabulary** (§8): the fixed token set `graph.read`, `graph.write`,
  `crypto.commit-sign`, `crypto.signal-sign`, `crypto.verify`,
  `network.relay.<endpoint>`, `network.peer.<protocol>`, `network.fetch.<origin>`,
  `storage.module.<size>`, `signal.send`, `signal.receive`, `time.wallclock`,
  `time.monotonic`, `random.csprng`; any token outside it is rejected at install.
- **Host-error model** (§6.3): `not-authorised`, `unknown-scope`, `quota-exceeded`,
  `network-error`, `signing-refused`, `invalid-argument`, `budget-exceeded`,
  `internal` — capability/scope/quota failures all report here.
- **Instancing** (§4.4): one instance per (content-hash, space-uri); scope is the
  per-instance authorised graph-DID set. **Storage** (§8.1, §9.5): keyed by
  (content-hash, graph-did); the declared cap counts key+value bytes; per-module
  isolation within a shared graph.
- **Signer** (§5.4, §9.7): the module never touches key material; the scoped signer
  accepts only an exhaustive set of shapes and refuses a commit-id absent from the
  module's build ledger.
- Authoritative reference impl: `standalone/module_runtime_provider.h`
  (`ModuleRuntime`) over the shared `module_manifest.*` / `module_capabilities.*`,
  verified by the 17 `Module_*` tests; the browser port
  (`content/browser/module_runtime/module_runtime_host.*` +
  `module_runtime_backends.*`) mirrors it against the real graph/identity backends,
  and the normative ABI is `graph_sync_module.wit`.

### Amendments

**Spec 06 required no new draft amendments.** Unlike Specs 02–05, the module
boundary was already made implementation-complete on `w3c-living-web-proposals`
`main` *before* this branch, by the cross-cutting amendment
[`53ea1b2`](https://github.com/HexaField/w3c-living-web-proposals/commit/53ea1b2)
("Add normative detail closing implementation gaps across sync and identity
specs"). That commit added draft 06's entire §6 *Normative WIT Definition* — the
§6.1 IDL-to-WIT mapping (declaring the WIT authoritative where it and the §5
WebIDL disagree), the §6.2 asynchronous-operations model (synchronous host
imports typed `result<_, host-error>`, task suspension, the execution-budget
watchdog), the §6.3 WIT world `graph-sync-module` itself, and §6.4 conformance.
This branch implements that already-normative surface; it does not change the
draft. `graph_sync_module.wit` is checked in verbatim beside the host as the
reference asset and tracked against draft §6.3 (any drift without a matching
draft change is a bug).

One implementation-layering note, **not** a spec change: a real relay/peer
transport is asynchronous and needs the Component Model engine's task-suspension
bridge (draft §6.2), which no seam in this branch wires up, so
`PersonalGraphManager` constructs `ModuleRuntimeHost` with a **null** network
backend and the runtime answers every network import with `host-error/internal`
when it is null — a value already in the draft's error vocabulary. The graph,
crypto, storage, clock, random and consent surfaces are fully live and enforced
here; only the wire transport is deferred to the default sync module (Spec 09)
once the async engine lands, exactly as Spec 05's session layer stays trivially
converged until a module attaches. The gating, scoping and quota decisions the
host makes are unaffected — an un-null test transport (`LoopbackNetwork` in the
gtest, `ModNetworkBackend` in the harness) exercises the full network path
against the same grant algebra.

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
