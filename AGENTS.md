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
