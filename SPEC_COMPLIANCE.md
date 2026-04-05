# Spec Compliance Matrix

This document tracks the alignment between the [Living Web specifications](https://github.com/HexaField/w3c-living-web-proposals) and this Chromium implementation.

**Legend:** ✅ Present (even as stub) · ❌ Missing · ⚠️ Simplified (e.g., `any` instead of typed)

---

## Spec 01 — Personal Linked Data Graphs

| API | Spec Section | IDL | C++ | WPT | Status | Notes |
|-----|-------------|-----|-----|-----|--------|-------|
| `navigator.graph` | §4.1 | ✅ | ✅ | ✅ | Stub | |
| `graph.create(name)` | §4.1 | ✅ | ✅ | ✅ | Stub | Returns rejected promise |
| `graph.list()` | §4.1 | ✅ | ✅ | ✅ | Stub | |
| `graph.get(uuid)` | §4.1 | ✅ | ✅ | ✅ | Stub | |
| `graph.remove(uuid)` | §4.1 | ✅ | ✅ | ✅ | Stub | |
| `PersonalGraph.uuid` | §4.2 | ✅ | ✅ | ✅ | Stub | |
| `PersonalGraph.name` | §4.2 | ✅ | ✅ | ✅ | Stub | |
| `PersonalGraph.state` | §4.2 | ✅ | ✅ | ✅ | Stub | Returns `"private"` |
| `addTriple(triple)` | §4.2.1 | ⚠️ | ✅ | ✅ | Stub | Param: `any` instead of `SemanticTriple` |
| `addTriples(triples)` | §4.2.2 | ⚠️ | ✅ | ✅ | Stub | Param: `any` instead of `sequence<SemanticTriple>` |
| `removeTriple(triple)` | §4.2.3 | ⚠️ | ✅ | ✅ | Stub | Param: `any` instead of `SignedTriple` |
| `queryTriples(query)` | §4.2.4 | ⚠️ | ✅ | ✅ | Stub | Param: `any` instead of `TripleQuery` dictionary |
| `querySparql(sparql)` | §4.2.5 | ✅ | ✅ | ✅ | Stub | Return: `any` instead of `SparqlResult` |
| `snapshot()` | §4.2.6 | ✅ | ✅ | ✅ | Stub | Return: `any` instead of `sequence<SignedTriple>` |
| `grantAccess(origin, level)` | §6.3 | ✅ | ✅ | ✅ | Stub | At risk in spec |
| `revokeAccess(origin)` | §6.3 | ✅ | ✅ | ✅ | Stub | At risk in spec |
| `ontripleadded` | §4.2 | ❌ | ❌ | ❌ | Deferred | See [Event Handlers](#event-handlers) |
| `ontripleremoved` | §4.2 | ❌ | ❌ | ❌ | Deferred | See [Event Handlers](#event-handlers) |
| `SemanticTriple` interface | §3.1 | ✅ | ✅ | ✅ | Stub | Header-only impl |
| `SignedTriple` interface | §3.2 | ✅ | ✅ | ✅ | Stub | Header-only impl |
| `ContentProof` interface | §3.2 | ✅ | ✅ | — | Stub | Header-only impl |
| `SparqlResult` interface | §4.6 | ❌ | ❌ | — | Deferred | Would require FrozenArray; returns `any` |
| `TripleQuery` dictionary | §3.4 | ❌ | — | — | Deferred | Using `any` param instead |
| `GraphSyncState` enum | §3.3 | ✅ | ✅ | ✅ | Stub | |
| `GraphAccessLevel` enum | §6.3 | ❌ | — | — | Deferred | Using `DOMString` param |

## Spec 02 — Decentralised Identity

| API | Spec Section | IDL | C++ | WPT | Status | Notes |
|-----|-------------|-----|-----|-----|--------|-------|
| `DIDCredential` interface | §3.1 | ❌ | ❌ | ✅ | Planned | Requires Credential Management integration |
| `credentials.create({ did })` | §3.2 | ❌ | ❌ | ✅ | Planned | Extends CredentialCreationOptions |
| `credentials.get({ did })` | §3.3 | ❌ | ❌ | ✅ | Planned | Extends CredentialRequestOptions |
| `DIDCredential.did` | §3.1 | ❌ | ❌ | ✅ | Planned | |
| `DIDCredential.algorithm` | §3.1 | ❌ | ❌ | ✅ | Planned | |
| `DIDCredential.displayName` | §3.1 | ❌ | ❌ | ✅ | Planned | |
| `DIDCredential.createdAt` | §3.1 | ❌ | ❌ | ✅ | Planned | |
| `DIDCredential.isLocked` | §3.1 | ❌ | ❌ | ✅ | Planned | |
| `sign(data)` | §5.1 | ❌ | ❌ | ✅ | Planned | |
| `verify(signedContent)` | §5.2 | ❌ | ❌ | ✅ | Planned | |
| `lock()` / `unlock()` | §4.3.2 | ❌ | ❌ | ✅ | Planned | |
| `SignedContent` interface | §5.1 | ❌ | ❌ | — | Planned | |

**Note:** DIDCredential integration requires extending the existing `credentialmanagement` module in Chromium. This is a separate integration surface from the `graph/` module and is tracked as planned work. The WPTs are written to the spec and will pass once the DIDCredential type is registered.

## Spec 03 — P2P Graph Synchronisation

| API | Spec Section | IDL | C++ | WPT | Status | Notes |
|-----|-------------|-----|-----|-----|--------|-------|
| `graph.join(uri)` | §5.1 / §8.2 | ✅ | ✅ | ✅ | Wired | |
| `graph.listShared()` | §5.1 | ✅ | ✅ | ✅ | Wired | |
| `PersonalGraph.share()` | §5.1 / §8.1 | ✅ | ✅ | ✅ | Wired | Options param as `any` |
| `SharedGraph` interface | §5.2 | ✅ | ✅ | ✅ | Stub | Extends PersonalGraph |
| `SharedGraph.uri` | §5.2 | ✅ | ✅ | ✅ | Stub | |
| `SharedGraph.syncState` | §5.2 | ✅ | ✅ | ✅ | Wired | Returns `"idle"` |
| `peers()` | §5.2 | ✅ | ✅ | ✅ | Wired | Returns `any` instead of `sequence<USVString>` |
| `onlinePeers()` | §5.2 | ✅ | ✅ | ✅ | Wired | Returns `any` instead of `sequence<OnlinePeer>` |
| `sendSignal(did, payload)` | §9.1 | ✅ | ✅ | ✅ | Wired | |
| `broadcast(payload)` | §9.2 | ✅ | ✅ | ✅ | Wired | |
| `SyncState` enum | §5.5 | ✅ | ✅ | ✅ | Stub | |
| `GraphDiff` interface | §5.4 | ✅ | ✅ | — | Stub | Typed attributes + `any` for arrays |
| `GraphSyncProtocol` interface | §5.3 | ❌ | ❌ | — | Deferred | Internal protocol contract |
| `SharedGraphOptions` dictionary | §5.1 | ❌ | — | — | Deferred | Using `any` param |
| `SharedGraphInfo` dictionary | §5.1 | ❌ | — | — | Deferred | Returns `any` |
| `OnlinePeer` dictionary | §5.2 | ❌ | — | — | Deferred | Returns `any` |
| `SignalEvent` interface | §9.3 | ❌ | ❌ | — | Deferred | See [Event Handlers](#event-handlers) |
| `SyncEvent` interface | §7.4 | ❌ | ❌ | — | Deferred | Service Worker integration |
| `onpeerjoined` | §5.2 | ❌ | ❌ | — | Deferred | See [Event Handlers](#event-handlers) |
| `onpeerleft` | §5.2 | ❌ | ❌ | — | Deferred | See [Event Handlers](#event-handlers) |
| `onsyncstatechange` | §5.2 | ❌ | ❌ | — | Deferred | See [Event Handlers](#event-handlers) |
| `onsignal` | §5.2 | ❌ | ❌ | — | Deferred | See [Event Handlers](#event-handlers) |

## Spec 04 — Dynamic Graph Shape Validation

| API | Spec Section | IDL | C++ | WPT | Status | Notes |
|-----|-------------|-----|-----|-----|--------|-------|
| `addShape(name, shapeJson)` | §5.1 | ✅ | ✅ | ✅ | Stub | |
| `getShapes()` | §5.2 | ✅ | ✅ | ✅ | Stub | Returns `any` instead of `sequence<ShapeInfo>` |
| `createShapeInstance(name, address, values)` | §5.3 | ✅ | ✅ | ✅ | Stub | Returns `USVString` |
| `getShapeInstances(shapeName)` | §5.4 | ✅ | ✅ | ✅ | Stub | Returns `any` instead of `sequence<USVString>` |
| `getShapeInstanceData(shapeName, address)` | §5.5 | ✅ | ✅ | ✅ | Stub | Returns `any` instead of `record` |
| `setShapeProperty(name, addr, prop, val)` | §5.6 | ✅ | ✅ | ✅ | Stub | |
| `addToShapeCollection(name, addr, coll, val)` | §5.7 | ✅ | ✅ | ✅ | Stub | |
| `removeFromShapeCollection(name, addr, coll, val)` | §5.8 | ✅ | ✅ | ✅ | Stub | |
| `ShapeInfo` dictionary | §5.2 | ❌ | — | — | Deferred | Returns `any` |
| `PropertyInfo` dictionary | §5.2 | ❌ | — | — | Deferred | Returns `any` |

## Spec 05 — Graph Governance

| API | Spec Section | IDL | C++ | WPT | Status | Notes |
|-----|-------------|-----|-----|-----|--------|-------|
| `canAddTriple(triple)` | §9.1 | ⚠️ | ✅ | ✅ | Wired | Param: `any` instead of `SemanticTriple` |
| `constraintsFor(entityAddress?)` | §9.2 | ✅ | ✅ | ✅ | Wired | Returns `any` instead of `sequence<GraphConstraint>` |
| `myCapabilities()` | §9.3 | ✅ | ✅ | ✅ | Wired | Returns `any` instead of `sequence<CapabilityInfo>` |
| `ValidationResult` dictionary | §9.1 | ❌ | — | — | Deferred | Returns `any` |
| `GraphConstraint` dictionary | §9.2 | ❌ | — | — | Deferred | Returns `any` |
| `CapabilityInfo` dictionary | §9.3 | ❌ | — | — | Deferred | Returns `any` |

---

## Notes

### Type Simplifications

Many spec types are simplified to `any` in the IDL to keep the initial implementation buildable. Full typed interfaces would require:

- Dictionary types (`TripleQuery`, `SharedGraphOptions`, `OnlinePeer`, etc.) — straightforward but verbose
- `FrozenArray` for `SparqlResult.bindings` and `GraphDiff.additions/removals`
- `record<DOMString, any>` for shape instance data

These are planned for future iterations as the implementation moves beyond stubs.

### Event Handlers

The spec defines several `attribute EventHandler` properties:

- `PersonalGraph`: `ontripleadded`, `ontripleremoved`
- `SharedGraph`: `onpeerjoined`, `onpeerleft`, `onsyncstatechange`, `onsignal`

These are **omitted from the IDL** because Chromium's `attribute EventHandler` codegen requires event type names to be registered in `third_party/blink/renderer/core/event_type_names.json5`, which is a core Chromium file outside this overlay repository.

**Workaround:** Both `PersonalGraph` and `SharedGraph` extend `EventTarget`, so `addEventListener('tripleadded', callback)` will work once event types are registered during full Chromium integration. The event handler attributes (`ontripleadded = ...`) will be added at that time.

### DIDCredential

Spec 02 defines `DIDCredential` as an extension to the Credential Management API (`navigator.credentials`). This integration requires modifying Chromium's existing `credentialmanagement` module, which is outside the scope of the `graph/` overlay. The backend DID key management (Ed25519 via BoringSSL) is implemented in `content/browser/did/` and is ready for wiring.

### Return Types

All methods currently return `Promise<any>` (or `Promise<undefined>` for void operations). Spec return types like `Promise<SignedTriple>`, `Promise<sequence<SignedTriple>>`, `Promise<SparqlResult>`, etc. will be implemented as the stubs are replaced with real logic.
