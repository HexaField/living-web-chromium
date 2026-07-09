# AGENTS.md — living-web-chromium

Native Chromium implementation of the [Living Web specs](https://github.com/HexaField/w3c-living-web-proposals)
(10 drafts). Read this before working in the repo.

## What this repo is

An **overlay**, not a full Chromium checkout. It contains:

- Curated files that drop into a real `chromium/src/` tree:
  `content/browser/{did,graph,governance,graph_sync}/`,
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

The overlay is kept byte-faithful to the standalone core. The standalone harness is the
fast day-to-day gate (green in seconds, no Chromium tree needed). The overlay's web-facing
IDL + Mojo glue only compiles inside a full Chromium checkout — see **Full-Chromium overlay
build** below. That path now compiles clean under Chromium's strict plugin suite
(chromium-style + raw_ptr + unsafe-buffers, `-Werror`), so "the overlay compiles" is a
verifiable claim, not just a reviewed mirror. When you change an overlay file, re-integrate
and rebuild the two overlay targets before claiming it builds.

## Build & test

```bash
cmake -S . -B build          # first time
cmake --build build          # after every change to standalone/ or tests/
./build/living_web_tests     # must stay 100% green
```

There is no lint/format gate beyond Chromium style conventions; match the surrounding
code (Google C++ style, 2-space indent, `//`-comment file headers).

## Full-Chromium overlay build

The overlay compiles and links inside a real Chromium `src/` checkout. Prerequisites: a
Chromium checkout matching the overlay's Chromium version, `depot_tools` on PATH (`gn`,
`autoninja`), and a Rust toolchain (the `oxigraph_ffi` + `mls_ffi` staticlibs build via
`cargo`).

```bash
./integrate.sh <path-to-chromium>/src          # copy overlay + generate gni/BUILD.gn + patch shared files
cd <path-to-chromium>/src
gn gen out/LivingWeb --args='is_debug=false is_component_build=true \
    symbol_level=0 blink_symbol_level=0 use_remoteexec=false'
# Fastest failure surface — the two overlay targets (NO leading //):
autoninja -C out/LivingWeb -k 0 \
    third_party/blink/renderer/modules/graph:graph \
    content/browser:browser
# Full browser binary → out/LivingWeb/chrome :
autoninja -C out/LivingWeb chrome
```

- **Never edit the Chromium tree directly.** It is a throwaway integration target: all
  edits live in this overlay repo, then `integrate.sh` copies them across. `integrate.sh`
  is idempotent (sentinel-fenced in-place patches) — re-run it after every source edit.
- `gn gen` is only needed when a `.gni` / `BUILD.gn` / IDL / mojom **inventory** changes;
  pure `.cc` / `.h` edits just need `integrate.sh` + `autoninja`.
- **Core-split:** `living_web_core` compiles the 15 shared-core `.cc` files WITHOUT the
  chromium-style / raw_ptr / unsafe_buffers plugins (`configs -= [chromium_code,
  find_bad_constructs, unsafe_buffers]; configs += [no_chromium_code]`); overlay TUs compile
  WITH the full suite. **Limitation:** an overlay TU that includes a shared-core *header*
  gets the plugins applied to that header's content at the include site, so shared-core
  header fixes must be **harness-safe** (compile in both the CMake harness and Chromium).
  The core target has `base/memory/` on its include path but NOT `partition_alloc/`.

### FFI toolchain link — prebuilt cargo staticlibs vs. the sysroot

`liboxigraph_ffi.a` / `libmls_ffi.a` are built by `cargo build --release` against the
**host** toolchain, so the RocksDB C/C++ objects Oxigraph bundles import host-glibc/-libstdc++
symbols the browser's Chromium sysroot (Debian bullseye, **glibc 2.31**) does not export:
`__isoc23_strtol/strtoul/strtoll/strtoull/sscanf` (the glibc 2.38+ C23 parsers), the glibc
2.32+ `__libc_single_threaded` flag, and newer libstdc++ ABI symbols (`GLIBCXX_3.4.29+`,
`CXXABI_1.3.13`, e.g. `basic_string::_M_replace_cold`, `exception_ptr::_M_addref`). These are
undefined **only at the final `chrome` link** — invisible to the module-only `autoninja …
modules/graph:graph` target — and surface as `mold: undefined symbol: …`.

Fix (already wired into `integrate.sh`, keep the standard sysroot): the generated
`third_party/oxigraph_ffi/BUILD.gn` (a) adds `living_web_libc_compat.c`, which forwards the
`__isoc23_*` parsers to the sysroot's classic entry points (ABI-identical for the number
formats RocksDB parses) and provides a weak `__libc_single_threaded`; and (b) links the host
`libstdc++.so.6` by absolute path (resolved at integrate time via `cc -print-file-name`). The
host lib's SONAME makes the runtime loader select the same host libstdc++ the binary runs on
anyway. **Do NOT set `use_sysroot=false`** — it forces a whole-world recompile against host
(very new) headers *and* a cascade of missing `-dev` packages (`cups-config`, nss, gtk …).

### Blink overlay API cheat-sheet (verified against the real tree)

The standalone harness has no Blink bindings, so these only surface in the full build:

- **`blink::BindOnce()`** (`wtf/functional.h`) is the canonical same-thread bind. Bare
  `BindOnce` in namespace `blink` usually resolves to it, but goes **ambiguous** with
  `base::BindOnce` when a bound arg is a `base::` / `mojo::` type (ADL) — qualify
  `blink::BindOnce`.
- **Mojo reply-callback lambdas** must take each arg with the callback's exact type — by
  **const ref** for non-trivial types (`const Vector<String>&`, `const
  std::optional<Vector<String>>&`), never by value, or the `OnceCallback<UnboundRunType>`
  conversion fails.
- **mojom `string?`** → nullable `WTF::String` (null-state), NOT `std::optional<String>`
  and NOT a pointer. Use `.empty()` / `.IsNull()` and assign directly — never `->` / `*`.
- **mojom `uintN?`** → real `std::optional<uintN>` (`if (x)`, `*x`). A `uint64` field
  feeding an IDL `unsigned long` setter trips `-Wshorten-64-to-32` → `static_cast<uint32_t>`.
- **IDL `sequence<object>`** → `HeapVector<ScriptObject>` (NOT `ScriptValue`). The
  `ScriptObject(isolate, v8::Local<v8::Value>)` ctor `CHECK`s `IsObject() || IsNull()` —
  filter to objects before constructing. **IDL `object`** alone → `ScriptObject`.
- **IDL union `(USVString or LiteralValue)`** → generated class `V8UnionLiteralValueOrUSVString`
  (members alphabetised, regardless of source order) in file `v8_union_literalvalue_usvstring.h`.
  A dictionary member typed `USVString?` is a plain `String` accessor + `hasX()`, **not** the
  union — wrap it for a mojom union field (e.g. `TripleObject::NewIriOrBnode(str)`).
- **WTF `Vector` has no `AppendSpan`** — use `Append(const T*, wtf_size_t)`. The two-arg
  `base::span(ptr, size)` ctor is flagged by unsafe-buffers (`-Wunsafe-buffer-usage`); use
  the container ctor `base::span(container)`. Passing a raw pointer as a *function arg* is
  fine — it's pointer arithmetic and two-arg span construction that trip the plugin.
- **`V8BufferSource` = `V8UnionArrayBufferOrArrayBufferView`**; `DOMArrayPiece::Bytes()` →
  `unsigned char*`, `ByteLength()` → `size_t`; `NotShared<T>` in
  `core/typed_arrays/array_buffer_view_helpers.h`; `TaskType` in
  `third_party/blink/public/platform/task_type.h`.
- **Event names (modules):** an Event *interface* name (`SyncStateEvent` etc.) auto-generates
  from the IDL database into `modules/event_interface_modules_names.h` (namespace
  `event_interface_names`) — include THAT, not `core/event_interface_names.h`. An
  *EventTarget* name (`Graph`, `GraphManager`) comes from `modules/event_target_modules_names.h`
  (namespace `event_target_names`), fed by the **hand-maintained**
  `modules/event_target_modules_names.json5` — a new EventTarget must be registered there
  (`integrate.sh` does this via `patch_event_target_names`).
- **`raw_ptr_exclusion.h`:** guard the include on
  `#if __has_include("partition_alloc/pointers/raw_ptr_exclusion.h")` (`#else #define
  RAW_PTR_EXCLUSION`) so the base-free `living_web_core` target (no `partition_alloc/` on its
  path) still compiles.

#### IDL ↔ C++ binding drift (only caught at the full `chrome` link)

The generated `gen/…/bindings/modules/v8/v8_*.cc` bindings `static_assert` IDL↔C++ type
compatibility and call the getters/methods at exact arities, but they compile **only when
`chrome` links** — `autoninja … modules/graph:graph` builds the module `.cc` alone. A green
module build does NOT prove the IDL and C++ agree; always link `chrome` before trusting a
binding change.

- **`readonly attribute EnumType foo`** → the C++ getter MUST return the generated `V8EnumType`
  (e.g. `V8SnapshotFormat`), NOT `String`. Convert with
  `V8EnumType::Create(str).value_or(V8EnumType(V8EnumType::Enum::kDefault))` and keep the string
  form as the internal/Mojo representation. JS still surfaces the enum as a string.
- **`optional X` arg with no default value** → Blink emits a shorter call site
  (`if (arg_count <= N) { … method(fewer_args); break; }`), so the C++ method needs a **default
  value** (`= std::nullopt` / `= nullptr`) on its **header** declaration — a default on the `.cc`
  definition is a redefinition error → "too few arguments" at `v8_*.cc`.
- **`FrozenArray<T>` attr** → getter returns `const FrozenArray<T>&`; **`any`** → `ScriptValue`;
  **`unsigned long`** ← a mojom `uint64` field needs `static_cast<uint32_t>`. Keep every IDL in
  lock-step with its C++ getters *and* the mojom struct — a stale stub IDL (wrong types/arity)
  fails `IsReturnTypeCompatible<…>` in the binding TU.

## Spec ↔ code map

Spec numbering (current, 10 specs):

| # | Spec | Where |
|---|------|-------|
| 01 | Decentralised Identity | `content/browser/did/`, `.../graph/did_credential.*`, `signed_content.*`, `content_proof.*` |
| 02 | Personal Linked Data Graphs | `.../graph/{graph,graph_manager,triple,literal_value,reifier,graph_snapshot,graph_triple_event}.*`, `content/browser/graph/` |
| 03 | Decentralised Group Identity | `content/browser/did/{did_graph,group_backend,group_backend_manager,group_host,group_service}.*`, `.../graph/group.*` |
| 04 | Graph Capability Framework | `content/browser/governance/{governance_backend,zcap}.*` (ZCAP-LD + enforcement), `standalone/capability_provider.h`, `.../graph/graph.*` (§11 surface) + `group.*` (`delegateCapability`) |
| 05 | Context Sync Protocol | `content/browser/graph_sync/{graph_diff,sync_backend}.*`, `.../graph/{personal_graph_host,personal_graph_manager}.*` (§6 folded), `standalone/sync_provider.h` |
| 06 | Sync Module Architecture | `content/browser/module_runtime/{module_manifest,module_capabilities,module_runtime_host,module_runtime_backends}.*` + `graph_sync_module.wit`, `standalone/module_runtime_provider.h`; §6.4 `listModules` on `.../graph/personal_graph_manager.*` |
| 07 | Dynamic Graph Shape Validation | `content/browser/shapes/{shape_definition,shape_service}.*`, `standalone/shape_provider.h`; §5 folded onto `.../graph/personal_graph_host.*` + `.../graph/graph.*`; `graph_backend_manager.*` `LookupHost` (§7 parent resolution) |
| 08 | Governance Constraint Vocabulary | `content/browser/governance/{constraint_vocabulary,constraint_vocabulary_backend}.*` (shared core + `RegisterConstraintVocabulary`), `standalone/constraint_vocabulary_provider.h`; `ValidationContext::zcap_id` seam in `governance_backend.*` / `capability_provider.h`; §7.8 bound to `shapes/shape_service.*` `Conforms`; installed in `.../graph/personal_graph_manager.*` ctor |
| 09 | Default Sync Module | `content/browser/graph_sync/{cbor,default_sync_module}.*` (shared byte-critical cores) + `{default_sync_backend,default_sync_crypto,mls_engine}.*` (browser port), `standalone/{default_sync_provider,mls_engine}.h`, `third_party/mls_ffi/` (OpenMLS staticlib); folded into the Spec 05 publish path (no new mojom/blink) |
| 10 | Graph Flows | — (planned) |

`SPEC_COMPLIANCE.md` tracks per-API status. Keep it current as branches land.

## Conventions

- **One spec per branch**, in dependency order (01 → 07, then 08–10). Branch name
  `spec-NN-shortname` (e.g. `spec-01-identity`). Each PR must be independently auditable.
- **No subsets.** The spec is normative — implement exactly what it mandates. No mocks,
  stubs, or placeholders in landed work. Leverage real libraries (Ed25519, JCS, Oxigraph
  for SPARQL, etc.) rather than faking behaviour.
- **Every fix needs a test** in the standalone harness that would have caught the
  regression. The harness can construct negatives (tampered signatures, cross-key verify)
  that read-only WPT interfaces cannot — put those there.
- **Spec gaps** (genuinely undefined behaviour) are resolved by amending the spec repo
  (`w3c-living-web-proposals`, pushed direct to `main`), never by weakening the
  implementation. Each amendment is recorded under `SPEC_COMPLIANCE.md` → Amendments
  with the specs-repo commit that carries it.

Each spec branch documents its own normative specifics (crypto parameters, error
behaviour, reference impl) in a section it adds here when it lands, so this file
stays the authoritative per-spec cheat-sheet as branches merge.

## Spec 01 specifics (landed)

- **did:key** (§4.1): `did:key:z` + base58btc(`0xed01` ‖ 32-byte Ed25519 pubkey). Every
  Ed25519 did:key begins `did:key:z6Mk`.
- **Signing** (§6.4): `message = SHA-256(JCS(data) ‖ timestamp_utf8)`; Ed25519-Sign;
  `proof = { method: "<did>#<multibase-key>", signature: multibase-base58btc, type:
  "Ed25519Signature2020" }`. JCS (RFC 8785) makes signatures key-order-independent.
- **signRaw** (§6.5): signs bytes verbatim (no hash/timestamp/framing), raw 64-byte sig.
- **Locked** (§5.3.2): `sign`/`signRaw`/`signCapability` reject with `InvalidStateError`.
- **resolve** (§7): did:key ⇒ `trustLevel: "local"`; no global resolver (§7.3).
- `ContentProof` is `{ method, signature, type }` (`Ed25519Signature2020`, multibase
  base58btc).
- Authoritative reference impl: `standalone/did_key_provider.h` + `content/browser/did/`
  (`did_key_codec`, `jcs`), verified by 30 tests in `standalone/living_web_tests.cc`.

## Spec 02 specifics (landed)

- **Substrate is Oxigraph, not hand-rolled.** RDF 1.2, RDF Dataset Canonicalization
  (`rdfc-1.0`), and SPARQL 1.2 come from **Oxigraph** via a Rust FFI static lib in
  `third_party/oxigraph_ffi` (crate `oxigraph 0.5`, `features = ["rdf-12"]`). `CMakeLists.txt`
  builds it with a `cargo build --release` custom command and links `liboxigraph_ffi.a`
  plus its system deps (`stdc++ gcc_s util rt pthread m dl c`, RocksDB C++ backend).
- **Build gotcha: `cargo` must be on PATH.** CMake locates it via
  `find_program(CARGO cargo HINTS "$ENV{HOME}/.cargo/bin" REQUIRED)` and runs the build with
  `~/.cargo/bin` prepended to PATH. If `cargo` is missing, configuration fails at
  `find_program`; install the Rust toolchain (rustup) first. The archive is rebuilt only
  when `third_party/oxigraph_ffi/src/*.rs` or its `Cargo.toml` change.
- **Layering.** Shared Chromium-independent core = `content/browser/graph/{oxigraph_store,
  rdf_serialization,sparql_results}.*` (the quad store + `graph://` content address, RDF 1.2
  term syntax + §3.2.1 signature pre-image, SPARQL Results JSON decode). Browser-process
  overlay = `content/browser/graph/{graph_backend,graph_backend_manager,personal_graph_host,
  personal_graph_manager}.*` (Mojo hosts + manager). Standalone orchestration of the
  §4/§5/§7 `Graph`/`GraphManager` algorithms = `standalone/graph_provider.h`. Blink bindings
  = `third_party/blink/renderer/modules/graph/` (`graph.*`, `graph_manager.*`, `triple.*`,
  `literal_value.*`, `reifier.*`, `graph_snapshot.*`, `graph_triple_event.*`). The shared
  core is compiled by both worlds; the overlay only inside a full Chromium tree.
- **Content address** (§5.2): `iri = "graph://" + lowercasehex(SHA-256(rdfc-1.0(dataset)))`.
  The empty-graph IRI `graph://e3b0c442…7852b855` (= graph:// + SHA-256("")) is an invariant
  shared by every fresh graph; graphs are tracked by their stable `urn:graph:<UUIDv4>` id,
  not by IRI. The IRI is recomputed lazily and invalidated by every mutation.
- **Reifier model** (§3.2): `addTriple` writes **6 triples** — the data triple, an
  `rdf:reifies` triple whose object is the RDF 1.2 triple term `<<( s p o )>>`, and four
  `prov://{author,timestamp,method,signature}` triples on the reifier blank node. Signature
  payload (§3.2.1): `SHA-256(canonical(triple) ‖ "|" ‖ timestamp ‖ "|" ‖ graphIdentifier)`
  signed with the active credential's `signRaw()`; `graphIdentifier` = `Graph.did` if set,
  else `Graph.id` (never the volatile `iri`).
- **Snapshot formats** (§5.3): `nquads-canonical` (default, the hash form), `nquads`, and
  `turtle` are advertised via the static `GraphManager.supportedSnapshotFormats` accessor
  (§5.3.4) and round-trip through `fromSnapshot()`; `jsonld` is **not** advertised —
  `getAsSnapshot`/`fromSnapshot` reject it with `NotSupportedError`. `fromSnapshot` rejects
  empty/failed proofs and tampered data with `DataError`, and enforces a §9.7 size bound
  (`QuotaExceededError`).
- **Errors** map to DOMException names: dissolved / no active credential →
  `InvalidStateError`; `signBy:"graph"` without `graph.did == active.did` → `NotAllowedError`;
  bad snapshot proof/hash → `DataError`; unadvertised format → `NotSupportedError`.
- **Normative detail folded into draft 02** (on `main`, see `SPEC_COMPLIANCE.md`): (i) §4.2
  `removeTriple` on a blank-node subject resolves `false` (canonicalization relabels blank
  nodes); (ii) §5.3.4/§3.4 JSON-LD is OPTIONAL and unadvertised via `supportedSnapshotFormats`;
  (iii) §3.2.1.1 pins the `canonical(triple)` N-Triples-1.2 pre-image byte form; (iv) §5.2
  pins the `rdfc-1.0` triple-term canonicalisation profile.
- Authoritative reference impl: `standalone/graph_provider.h` over the shared core, verified
  by 22 `Graph_*` tests in `standalone/living_web_tests.cc`.

## Spec 03 specifics (landed)

- **A group is a groupified Spec 02 Graph.** Groupification (§4.2) is a one-way bootstrap:
  mint a fresh Ed25519 keypair, derive a `did:graph` from it, and write the binding triple +
  seed DID document + `group://syncModule` as ordinary triples into the host graph. The DID
  document **is** triples (`did://*`, `group://*`) in the host graph — no separate wire
  format: adding a delegate is authoring `did://verificationMethod` + section triples,
  resolving the DID is projecting them back (`group_detail::ProjectDidDocument`). Re-groupify
  → `InvalidStateError`; `syncModule` REQUIRED → `SyntaxError`.
- **did:graph codec** (§4.1): `did:graph:z` + base58btc(`0xed01` ‖ 32-byte Ed25519 pubkey).
  Reuses the Spec 01 did:key multibase machinery byte-for-byte; only the method prefix
  differs, so a group's initial key is an ordinary `DIDKeyPair` with `method = "graph"`.
  Shared codec + DID-document model = `content/browser/did/did_graph.*` (namespace
  `living_web`), compiled by both build worlds.
- **Verification-method id** (§4.4): `<did> + "#" + <publicKeyMultibase>` — self-certifying,
  reconstructible from the key alone (`group_detail::MethodId`). Each method carries
  `type`/`controller`/`publicKeyMultibase`; the controller is always the group DID.
- **Four capability sections** (§5.1): `capabilityInvocation`, `capabilityDelegation`,
  `assertionMethod`, `authentication`. The creator key holds all four, so a **group of one**
  (§11) is the same structure as an individual identity at cardinality one; `resolve()`
  returns a one-verification-method DID document.
- **Authorship rules** (§5.4, §6.2): governed writes are gated on the *acting* delegate
  holding the required section — delegate management and accepting participation need
  `capabilityDelegation`; `signGraph` needs `assertionMethod`. Failure → `NotAllowedError`.
  The acting credential defaults to the group's own initial key; `setActingCredential` hands
  off to another held delegate. A write is authored by temporarily making the acting key the
  provider's active credential (`ScopedActive` RAII), so the reifier signature (Spec 02
  §3.2.1) records the delegate as author.
- **Brick guards** (§5.4): the group MUST always retain ≥1 `capabilityDelegation` method —
  removing / revoking the last one → `InvalidStateError`.
- **Participation ≠ signing authority** (§7). Participation lives in
  `context://accepts_participation` / `context://participates_in` triples, kept structurally
  separate from the DID-document delegate sections. `transitiveParticipants` descends into
  participating sub-groups (cycle-safe, depth cap 16 per §6.3/§13.7) and flattens to
  individuals — group membership is not transitive for authority.
- **signGraph** (§5.4): signs `{ graphDid, graphIri, timestamp }` with the acting credential
  via the Spec 01 `sign()` path, yielding an `Ed25519Signature2020` proof (multibase
  base58btc). A target not locally mounted is signed as an opaque IRI with `graphDid: null`.
- **Forking** (§4.8): mints a fresh identity over a full N-Quads copy of the parent
  (`DumpNquads`/`LoadNquads`, so inherited history stays verifiable), strips the parent
  identity from the copy, records `group://forkedFrom`/`forkedAtRevision`, and (default)
  announces `group://forkedTo` on the parent. The root-capability mint (§4.8 step 5) and the
  constraint-kind superset check (§4.8.1 → `NotSupportedError`) belong to Spec 04 / Spec 08.
- **Errors** map to DOMException names: missing `syncModule` → `SyntaxError`; re-groupify /
  brick / deactivated-state → `InvalidStateError`; missing section authority →
  `NotAllowedError`; unknown DID/IRI on open/fork → `NotFoundError`.
- **Normative detail folded into draft 03** (on `main`, see `SPEC_COMPLIANCE.md`): (i) §4.4 a
  verification-method id fragment MUST be the method's own `publicKeyMultibase` (the `#key-*`
  labels in examples are non-normative mnemonics); (ii) §4.3/§8.2.2 `groupify` takes the live
  `Graph`, not a `graph://` IRI — the content-address IRI advances on every write including
  the bootstrap itself, so the DID (not the IRI) is the durable group key and an IRI-keyed
  lookup can race the bootstrap write.
- Authoritative reference impl: `standalone/group_provider.h` over
  `content/browser/did/did_graph.*`, verified by 15 `Group_*` tests in
  `standalone/living_web_tests.cc`; browser port = `content/browser/did/{group_backend,
  group_backend_manager,group_host,group_service}.*`, renderer = `.../graph/group.*`.

## Spec 05 specifics (landed)

- **Sync folds onto the existing graph hosts — no new service.** The §6 renderer surface is
  a `partial interface Graph` (`publish`/`unpublish`/`syncState`, `peers`/`onlinePeers`,
  `currentRevision`, `pendingDiffs`, `sendSignal`/`sendSignalToSession`/`broadcast`, and the
  `onpeerjoined`/`onpeerleft`/`onsyncstatechange`/`onsignal`/`ondiff` events) plus a
  `partial interface GraphManager` (`mount`/`unmount`, `listMounted`/`listModules`/
  `listSpaces`, `onsubscriptiongained`/`onsubscriptionlost`). The Mojo folds into the single
  `graph.mojom`. Backend: `PersonalGraphManager` owns **one** per-realm `SyncBackend` and
  shares it with every `PersonalGraphHost`; the host carries the per-graph session state
  (`published_`/`session_writable_`, the durable queue, `current_revision_`).
- **Shared identity core** = `content/browser/graph_sync/graph_diff.*` (namespace
  `living_web`, pure-std, **no Chromium deps** — like `did_graph`/`zcap`). It defines the
  `revision`/`commitId` pre-images, `sort(dependencies)`, and the four-topology
  space-derivation input, and is compiled by **both** build worlds so a diff's content
  address never diverges. It performs no hashing itself (the SHA-256 header differs per
  world); the caller applies `crypto::SHA256HashString` + `ToLowerHex`.
- **Diff identity** (§5.2.2, amendment §5.2.2.1): `revision =
  SHA-256(BuildRevisionPreimage)` — a domain tag, `graphDid`, the **byte-length-framed**
  `rdfc-1.0` canonical N-Quads of the additions then removals, then the sorted dependency
  revisions (length-framed because N-Quads embed LF). `commitId =
  SHA-256(BuildCommitIdPreimage)` — tag, `revision`, `author`, `timestamp`, leaf-capability
  id, LF-joined, no trailer. The bundle `signature` is Ed25519 over the UTF-8 lowercase-hex
  `commitId` **directly** (Ed25519 hashes internally — no second SHA-256). Both digests are
  lowercase hex.
- **validateDiff** (§9.2.1) steps 0–6: recompute `revision`+`commitId` and verify the bundle
  signature against the resolved author key; capability chain + caveats **delegated to the
  Spec 04 `GovernanceEngine`** (enforcement-mode-aware, §9.4); per-reifier signatures with an
  **author-binding** guard (a reifier attributed to an agent ≠ the diff's committer →
  `reifier_signature_invalid`, closing the smuggle hole); dependency validation (chain-root
  rule → `chain_root_conflict`, unknown revision → `missing_dependency`); §14.5 timestamp
  plausibility. An accepted revision enters the local chain; a replay is an idempotent no-op
  (§14.4). Rejection reasons carry `constraint_kind` `capability` (identity/signature/chain)
  or `temporal` (timestamp).
- **authorKey resolution** (§5.2.2): a `did:key` author resolves to its own key; a
  `did:graph` author resolves to the **current `capabilityDelegation` delegate keys**
  projected from that DID's document in the target graph — so a diff signed by a rotated
  group delegate still verifies.
- **Read access & topology** (§7, §9.2.2): `validateReadAccess` is the `mountContext` gate; a
  graph is *restricted* iff it binds a `capability` constraint (keyed off the constraint's
  presence, **not** `enforcement_mode`). `DeriveSpace` → `space://` + SHA-256 over the
  topology input; tokens `lwsync:{unified,public,dedicated,named}:`; namespace id =
  `context://participates_in` root, fallback the graph DID.
- **The session layer is browser-only glue** (publish/mount/peers/signalling/currentRevision/
  pendingDiffs); it has **no standalone counterpart**. Live peer transport, real peer lists,
  and module installation are **Spec 06** — until a module attaches, peer lists are empty,
  `peerCount` is 0, signalling is a validated no-op, and `listModules` is empty. `syncState`
  goes `idle` → `synced` on publish/mount.
- **Reconnection** (§13, amendment): the durable `DiffQueue` keys and de-dupes by `commitId`
  in commit order; `ReconnectBackoffMs` is 5 s initial, ×2, cap 300 s; the batch policy is
  100 diffs / 3000 ms. **Invitations** (§12, amendment):
  `web+graph://<relay>/<space-uri-base64url>?did=&module=&name=` — `did` REQUIRED,
  `module`/`name` OPTIONAL and percent-encoded.
- **Errors** map to DOMException names: DID-less publish/commit, an `options.moduleHash`
  disagreeing with `group://syncModule`, and a double-mount → `InvalidStateError`; a mount an
  agent may not read/write → `NotAllowedError`; `unmount` of an unmounted DID →
  `NotFoundError`.
- **Normative detail folded into draft 05** (on `main`, see `SPEC_COMPLIANCE.md`): (i)
  §5.2.2.1 the exact `revision`/`commitId` pre-image bytes and the commit-id-direct signature
  message; (ii) §12 invitation-link format + processing model; (iii) §14.5 received-timestamp
  plausibility (future 300 s + causal + per-author monotonic); (iv) §13 reconnection / offline
  handling (durable queue, backoff, batching).
- Authoritative reference impl: `standalone/sync_provider.h` (`SyncEngine` + `DiffQueue`) over
  the shared `graph_diff.*` and the browser `content/browser/graph_sync/sync_backend.*`,
  verified by 29 `Sync_*` tests in `standalone/living_web_tests.cc`; browser port =
  `content/browser/graph/{personal_graph_host,personal_graph_manager}.*` (session + mount /
  inventory), renderer = `.../graph/{graph,graph_manager}.*` (§6 surface).

## Spec 06 specifics (landed)

- **A capability-scoped WASM host, not a new service.** The runtime installs,
  consents to, instantiates and mediates pluggable WebAssembly sync modules
  (§6/§7). Installation, consent and instantiation are **user-mediated with no
  script surface** — a page cannot install a module or grant its own consent — so
  the only renderer-visible face is the §6.4 read-only `listModules()` inventory,
  already carried by `graph.mojom`'s `SyncModuleInfo` + the `GraphManager` partial
  interface (folded in with the Spec 05 seam). No new Mojo host: `ModuleRuntimeHost`
  is a per-realm object `PersonalGraphManager` constructs directly (as it constructs
  `SyncBackend`).
- **Two shared Chromium-independent cores** (namespace `living_web`, pure-std,
  compiled by **both** build worlds): `module_manifest.*` (§4.2 content-address
  `"sha256-" + hex(SHA-256(wasm))` = 71 chars; §8.2 manifest parse + the §8.2
  mutual-verifiability binding; §7.3 fork constraint-kind superset) and
  `module_capabilities.*` (the §8 capability vocabulary, the §6.3 `host-error`
  variant, and the grant algebra every host surface consults). Like `graph_diff`,
  they do **no hashing themselves** — the caller supplies the SHA-256 digest (the
  primitive differs per world). The browser host (`module_runtime_host.*` +
  `module_runtime_backends.*`) and the standalone provider
  (`module_runtime_provider.h`) consume them verbatim, so every grant/scope/quota
  decision is byte-identical.
- **Capability enforcement** (§8, §8.3): every §6.3 host call — graph read/write,
  crypto commit/signal sign + verify, network relay/peer/fetch, storage, clock,
  random — is authorised against the module's grant set, its per-instance scope,
  and its §8.1 storage quota **before** it reaches the real backend; a module
  cannot forge past a `not-authorised`. Vocabulary: `graph.read`, `graph.write`,
  `crypto.{commit-sign,signal-sign,verify}`, `network.relay.<endpoint>`,
  `network.peer.<protocol>`, `network.fetch.<origin>`, `storage.module.<size>`,
  `signal.{send,receive}`, `time.{wallclock,monotonic}`, `random.csprng`. An
  unknown token is rejected at install.
- **Scope + isolation** (§4.4, §9.5): one instance per (content-hash, space-uri),
  each with its own authorised graph-DID set; storage is keyed by
  (content-hash, graph-did) with the declared byte cap counting key+value, and one
  module cannot see another's keys within a shared graph. Wall-clock is coarsened
  to 1 s (§8 fingerprinting countermeasure).
- **Scoped signer** (§5.4, §9.7): key material never enters the module; the signer
  accepts only exhaustive shapes and refuses a `commit-id` absent from the module's
  build ledger (`signing-refused`). The browser `ModuleCryptoAdapter` signs on
  behalf of the local agent — the `DIDKeyProvider`'s **active** credential — so
  verify checks against its DID; the standalone provider uses a dedicated signer
  credential. Both drive the same algebra.
- **Browser graph binding.** `ModuleGraphAdapter` binds a module's authorised
  graph DIDs to real Spec 02 backends via `GraphBackendManager::CreateMounted(did)`
  (external-trust, DID bound up front) + `Bind(did, backend)` — the browser analogue
  of the standalone `ModGraphBackend::AddGraph`. `AddTriples` has no external-trust
  write guard, so a module's `WriterApply` lands in the real Oxigraph store.
- **Normative ABI is WIT, not WebIDL** (draft §6.3, already normative): the
  module-facing contract is the WIT world `graph-sync-module`
  (`graph_sync_module.wit`), checked in verbatim as a **reference asset** — it is
  NOT in the `module_runtime` BUILD.gn `sources` (a `.wit` is not C++). The §5
  WebIDL is illustrative; the WIT governs where they disagree. This branch made no
  draft change — the normative §6 WIT was folded into draft 06 ahead of it by the
  cross-cutting amendment `53ea1b2`. Keep the checked-in `.wit` in lockstep with
  draft 06 §6.3 (drift without a matching draft change is a bug).
- **Null host-network is a layering boundary, not a stub** (impl note, draft §6.2
  unchanged). A real relay/peer transport is asynchronous and needs the Component
  Model task-suspension bridge (draft §6.2), which no seam wires up in this branch;
  `PersonalGraphManager` constructs the host with a **null** network backend and the
  runtime answers every network import with `internal` (already in the draft's
  `host-error` vocabulary) when it is null. Graph, crypto, storage, clock, random
  and consent are fully live and enforced; only the wire transport is deferred to
  the Spec 09 default module. Tests drive the full network path with an in-process
  transport (`LoopbackNetwork` gtest, `ModNetworkBackend` harness) so the gating is
  still covered.
- Authoritative reference impl: `standalone/module_runtime_provider.h`
  (`ModuleRuntime`) over the two shared cores, verified by 17 `Module_*` tests
  (137 total, green); browser port = `content/browser/module_runtime/*` with 17
  gtests (`tests/module_runtime_host_unittest.cc`); §6.4 renderer surface pinned by
  `tests/web_platform_tests/graph/sync-modules.html`.

## Spec 07 specifics (landed)

- **A shape is content-addressed data stored in the graph it governs.** No schema
  registry: `addShape` writes the §6.4 triple shape (`rdf://type shape://Shape` +
  `name`/`targetClass`/`definition`) linked from the graph's stable id via
  `shape://has_shape`. The definition literal is the JCS-canonical JSON; the address
  is `sha256:` + lowercase-hex(SHA-256(JCS)) — **colon**, unlike Spec 06's hyphenated
  `sha256-` WASM hash.
- **Shared core never hashes.** `content/browser/shapes/shape_definition.*` (namespace
  `living_web`) owns the §4 grammar, `CanonicalizeShapeJson`, `FormatShapeAddress`,
  `NormalizeDatatype`/`ValidateLexicalForDatatype`, `SetterKindFor`, `ShapeNarrows`.
  The caller hashes with its build world's SHA-256 (`crypto::SHA256HashString` /
  `standalone/crypto_sha2.h`) and feeds the digest to `FormatShapeAddress`, so the
  core stays SHA-agnostic (same rule as Spec 02 content hashing).
- **Per-realm service, folded onto the personal host.** `PersonalGraphManager` owns one
  `content::ShapeService` (borrows identity + `&governance_` + `&backends_`), declared
  **after** them, threaded into every `PersonalGraphHost` (Create/FromSnapshot/Mount).
  The §5 API is per-graph so it folds onto `PersonalGraphHost` + `partial interface
  Graph` (the Spec 04 §11 / Spec 05 §6 seam), **not** a new mojo host. Every §5 method
  takes the target `GraphBackend* W` first; registration/instance writes author as
  `governance_->ActiveCredentialId()` (current identity, never renderer-named).
- **§7 inheritance walks `context://participates_in` up.** `GraphBackendManager::
  LookupHost(key)` resolves a parent by stable id / DID / content-IRI (added for this
  spec). Inheritance is **gated by acceptance (§10.5)**: the parent must carry a
  `context://accepts_participation` reifier whose author is one of its
  `capabilityDelegation` delegates, else the child sees nothing (`ParentAcceptsChild`).
  A same-name local shape that strictly narrows shadows the inherited one (§7.3).
- **Error vocabulary.** `SyntaxError`/`TypeError` are ECMAScript-native (blink rejects
  them off the `DOMException` path); `ConstraintError`/`NotAllowedError`/`NotFoundError`/
  `NoModificationAllowedError`/`InvalidAccessError`/`InvalidStateError` map to
  `DOMException` codes (`Graph::RejectWithName`). `addLink` constructor actions always
  emit an IRI object term (the §4.5 type discriminator); target setters type by the
  referenced property's datatype.
- **Governance gotcha (tests).** Under enforcement, once a capability constraint is
  installed `SetEnforcementMode` re-authorises via `updateGovernance`, so any
  `BootstrapEnforced` with a custom action set that also registers a shape must grant
  **both** `updateSHACL` and `updateGovernance`.
- Authoritative reference impl: `standalone/shape_provider.h` (`living_web::ShapeService`)
  over `shape_definition.*`, verified by 24 `Shape_*` tests (161 total, green); browser
  port = `content/browser/shapes/shape_service.*` with 16 gtests
  (`tests/shape_service_unittest.cc`); §5 renderer surface pinned by
  `tests/web_platform_tests/graph/personal-graph-shapes.html`.

## Spec 08 specifics (landed)

- **A vocabulary, not a subsystem.** Spec 08 plugs into Spec 04's seams
  (`ConstraintKindHandler` / `CaveatHandler`). `RegisterConstraintVocabulary(engine,
  opts)` installs three constraint kinds (`credential` §4, `temporal` §5, `content` §6)
  and ten caveat types (§7) in one call. Spec 04 already fails closed on unknown
  kinds/types, so this call is what turns those closed doors into policy. Installed in
  the `PersonalGraphManager` **constructor** (beside §04/§05/§07), so every realm graph
  carries it with no renderer ceremony.
- **Kinds vs caveats bite at different points.** A constraint **kind** is graph-scoped:
  collected from the scope chain and evaluated on **every** write regardless of mode —
  `open` mode gates only the `capability`/ZCAP check, so credential/temporal/content
  deny-win even in an open graph. A **caveat** attenuates one delegation: reached only
  in `enforced` mode through a capability constraint + a delegation carrying it. This is
  the key WPT gotcha — constraint-kind tests run in **open** mode; caveat tests need
  **enforced** mode + a capability constraint + `delegateCapability({…caveats})` +
  `setActiveIdentity(delegatee)`.
- **Shared core never hashes, never regexes, never touches the graph.**
  `content/browser/governance/constraint_vocabulary.*` (namespace
  `living_web::constraint_vocab`) owns the §11 predicate vocabulary, §7.4 glob, §7.2/§7.3
  deny-wins, RFC 3339→epoch + §5.3 plausibility, the §6.2 content policy, and the VC
  parse/pre-image. The regex matcher and SHA-256/Ed25519 are **injected per world**:
  browser = RE2 (linear-time, never `kTimeout`) + `//crypto`; standalone = `std::regex`
  on a 10 ms `std::async` worker + `crypto_sha2.h`. A malformed pattern is `kNoMatch`
  (blocks nothing) in both; verdicts never diverge for a well-formed pattern.
- **Living-web VC profile (amendment).** A credential is JCS-canonical JSON stored
  **inline at its own `sha256:` address** via `governance://credential_body` (content-
  address integrity enforced — body must hash to its address), issuer a `did:key`, proof
  an Ed25519 `proofValue` over `BuildVcProofPreimage` (versioned field projection, same
  construction as `zcap.cc`). Revocation is **local-state**: a `credentialStatus.id`
  subject bearing `governance://revoked "true"` revokes; absence = live. No JSON-LD /
  LD-Proofs stack.
- **`zcap_id` seam.** `rateLimit`/`cardinality` key their usage ledger on
  `(ctx.zcap_id, author)`; `ValidationContext::zcap_id` (added to `governance_backend.*`
  + `capability_provider.h`) carries the innermost delegation id, `""` for a
  root/non-delegated check. The ledger records a use on each admit.
- **§7.8 shape caveat reuses Spec 07.** The browser binds
  `ConstraintVocabOptions::shape_conforms` to `content::ShapeService::Conforms` (added
  this spec: resolves the shape by §7.2 name, checks the candidate subject's §4.3
  cardinality + §4.4 datatype over stored objects **plus** the advisory write); the
  standalone injects an equivalent lambda. Unresolvable shape → fail-closed (§9.6). The
  vocabulary never re-implements SHACL.
- **Credential deferral at the renderer.** No VC-*issuance* verb on the §11 renderer
  surface, so the credential kind (§4) and `credential` caveat (§7.10) are pinned at the
  standalone + gtest layers, not the WPT — a coverage placement, not a subset.
- Authoritative reference impl: `standalone/constraint_vocabulary_provider.h`
  (`RegisterConstraintVocabulary`) over `constraint_vocabulary.*`, verified by 25 `Gov_*`
  tests (**186 total, green**); browser backend =
  `content/browser/governance/constraint_vocabulary_backend.*` with 25 gtests
  (`tests/constraint_vocabulary_unittest.cc`); renderer surface pinned by
  `tests/web_platform_tests/graph/governance-constraint-vocabulary.html`.

## Spec 09 specifics (landed)

- **The default module *is* the Spec 05 publish path — no new script surface.**
  `urn:sync:module:default` (§4.1) is the sync module every group references unless it
  names another. Its entire ceremony (the §5 CBOR wire frames, the §6.3 per-space RFC
  9420 MLS group, the §6.3.9 key schedule, the §6.3.10 AES-128-GCM envelope, the §8
  OR-Set merge) runs in the browser process with **zero renderer visibility** — a page
  cannot touch a KeyPackage, a Commit, an exporter secret, or a ciphertext. So Spec 09
  adds **no mojom and no blink**: its renderer-visible face is exactly the Spec 05
  `publish()` producing a derived encrypted `space://` URI plus `PublishedGraph.moduleHash`.
  The WPT (`default-sync-module.html`) pins only that projection.
- **Two shared byte-critical cores, pure-std, no crypto, no Chromium.**
  `content/browser/graph_sync/cbor.*` (namespace `living_web::cbor`) is the deterministic
  §5 CBOR codec (canonical map order, strict reject on non-canonical input);
  `default_sync_module.*` (namespace `living_web::default_sync`) owns the §6.3.9 key
  schedule, the §6.3.10 frame envelope construction, the §8 OR-Set, `GroupIdFromSpaceUri`
  (§6.3.1), and `DefaultModuleContentHash` (§4.1, `"sha256-"` + lowercase-hex). Both are
  `#include`d **verbatim** by the standalone provider and the browser backend, so the wire
  frames, key schedule, AEAD envelope and OR-Set compute byte-identically in both worlds.
- **Eight crypto primitives injected per world via the `SyncCrypto` seam.** The cores do
  **no** crypto. `standalone/default_sync_provider.h::MakeOpenSslSyncCrypto()` binds them to
  OpenSSL; `content/browser/graph_sync/default_sync_crypto.*::MakeChromiumSyncCrypto()` binds
  the same eight (SHA-256/512, HMAC-SHA256, HKDF-Expand, X25519, AES-128-GCM seal/open, the
  did:key→X25519 edwards map) to `//crypto` + BoringSSL. Verdicts and bytes never diverge.
- **Real RFC 9420 MLS — one staticlib, two wrappers.** The group ceremony is genuine
  OpenMLS via the Rust staticlib `third_party/mls_ffi/` (cipher suite
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, 0x0001). Like `oxigraph_ffi`, it has **no
  BUILD.gn** — it is pulled into the `//content` build through its own third_party target,
  and both build worlds link the **same** staticlib, so every KeyPackage/Commit/Welcome byte
  is identical. Only the C++ wrapper differs: `standalone/mls_engine.h` throws;
  `content/browser/graph_sync/mls_engine.*` is exception-free (`bool` + out-params +
  `last_error()`), mirroring `OxigraphStore`.
- **The exporter seam (§6.3.9) is the real RFC 9420 §8.5 exporter, not a simulation.**
  `member.ExportSecret(kSpaceFrameExporterLabel, space_uri, 32)` — label
  `"lw-sync space frame"`, context = the full `space://…` URI — returns the space traffic
  secret **directly** from inside OpenMLS; the core then calls `DeriveFrameKeys(sts, crypto)`.
  `DeriveFrameKeysFromExporter` is the *simulated-exporter* path used only by the standalone
  known-answer test; the browser backend and the MLS end-to-end tests drive the real
  `ExportSecret → DeriveFrameKeys` seam.
- **Per-space backend.** `content/browser/graph_sync/default_sync_backend.*` (namespace
  `content`) owns one MLS group + one OR-Set per published space, drives seal/open + the §8
  merge, and derives the §6.3.1 space authority (64-char lowercase-hex SHA-256 group_id) from
  the graph DID. It is a peer of the Spec 05 `SyncBackend`, co-compiled in the single
  `source_set("graph_sync")` (Spec 09 sources folded into the Spec 05 target; `deps`
  unchanged — MLS + Ed25519 staticlibs arrive via their own third_party targets).
- **Two amendments (specs commit `5a2e94f`).** (i) §6.3.9 — the exporter gloss was replaced
  with the full RFC 9420 §8.5 two-step form (`MLS-Exporter = ExpandWithLabel(DeriveSecret(
  exporter_secret, Label), "exported", Hash(Context), Length)`), matching what OpenMLS
  actually computes. (ii) §4.2 — the capability column now uses the Spec 06 §8 grammar
  `crypto.commit-sign` / `crypto.signal-sign` / `crypto.verify`; the nonexistent `crypto.sign`
  token was removed.
- Authoritative reference impl: `standalone/default_sync_provider.h` +
  `standalone/mls_engine.h` over `default_sync_module.*` / `cbor.*`, verified by 26 `Sync09_*`
  tests (**212 total, green**); browser backend =
  `content/browser/graph_sync/{default_sync_backend,default_sync_crypto,mls_engine}.*` with 15
  gtests (`tests/default_sync_module_unittest.cc`); renderer projection pinned by
  `tests/web_platform_tests/graph/default-sync-module.html`.

## Gotchas

- Don't add DIDCredential logic that isn't reachable — wire new methods through
  `personal_graph_manager.cc` (`MakeDIDCredential`) so WPT can hit them.
- Blink patterns: `ScriptWrappable` interfaces; `ScriptPromise<T>` / `ScriptPromiseResolver<T>`;
  `ToV8Traits<T>::ToV8`; `HeapMojoRemote`; `V8BufferSource` + `DOMArrayPiece` for
  `BufferSource`; `DOMArrayBuffer::Create(base::span(...))` to return an `ArrayBuffer`;
  `v8::JSON::Stringify`/`Parse` for `any` round-trips.
- Event-name registration is a core-file delta. `Graph` declares `ontripleadded` /
  `ontripleremoved` (spec §4.2), so a full-tree build needs `tripleadded` and
  `tripleremoved` added to `event_type_names.json5` (a Chromium core file outside this
  overlay). Spec 01's DIDCredential had no events and needed no such entry; this is the
  first spec that does. All graph interfaces extend `EventTarget`, so `addEventListener()`
  works once the names are registered.
- IDL files are **not** listed in `BUILD.gn` sources — they're wired separately during
  full-tree integration (`idl_in_modules.gni` + `generated_in_modules.gni`); only `.cc`/`.h`
  go in `blink_modules_sources`.
