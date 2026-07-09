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
