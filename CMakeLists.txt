cmake_minimum_required(VERSION 3.16)
project(LivingWeb VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Find OpenSSL (Ed25519 signing/verification and SHA-256 are backed by it).
find_package(OpenSSL REQUIRED)

# Ed25519 implementation (uses OpenSSL EVP). A shared cryptographic primitive
# consumed by every spec that signs or verifies; it ships in the base.
add_library(ed25519 STATIC
    third_party/ed25519/ed25519.c
)
target_include_directories(ed25519 PUBLIC third_party/ed25519)
target_compile_definitions(ed25519 PRIVATE USE_OPENSSL)
target_link_libraries(ed25519 PRIVATE OpenSSL::Crypto)

# Spec 02 — the Oxigraph FFI static library.
#
# Spec 02 mandates an RDF 1.2 quad store, RDF Dataset Canonicalization (rdfc-1.0)
# and SPARQL 1.2; none of these is hand-rolled. They are provided by Oxigraph
# through a thin Rust cdylib/staticlib in third_party/oxigraph_ffi, built with
# cargo. The archive is produced by a custom command that reruns cargo whenever
# the crate sources change, and linked into the final binary together with the
# system libraries the Rust std + RocksDB C++ backend require.
find_program(CARGO cargo HINTS "$ENV{HOME}/.cargo/bin" REQUIRED)

set(OXIGRAPH_FFI_DIR ${CMAKE_SOURCE_DIR}/third_party/oxigraph_ffi)
set(OXIGRAPH_FFI_LIB ${OXIGRAPH_FFI_DIR}/target/release/liboxigraph_ffi.a)

file(GLOB OXIGRAPH_FFI_SRC ${OXIGRAPH_FFI_DIR}/src/*.rs)
list(APPEND OXIGRAPH_FFI_SRC ${OXIGRAPH_FFI_DIR}/Cargo.toml)

add_custom_command(
    OUTPUT ${OXIGRAPH_FFI_LIB}
    COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{HOME}/.cargo/bin:$ENV{PATH}"
            ${CARGO} build --release --manifest-path ${OXIGRAPH_FFI_DIR}/Cargo.toml
    DEPENDS ${OXIGRAPH_FFI_SRC}
    WORKING_DIRECTORY ${OXIGRAPH_FFI_DIR}
    COMMENT "Building Oxigraph FFI static library (cargo build --release)"
    VERBATIM
)
add_custom_target(oxigraph_ffi_build DEPENDS ${OXIGRAPH_FFI_LIB})

# The Rust staticlib pulls in the Rust standard library and the RocksDB C++
# backend, so the final link needs libstdc++ and these system libraries.
set(OXIGRAPH_FFI_SYSTEM_LIBS stdc++ gcc_s util rt pthread m dl c)

# Spec 09 — the OpenMLS (RFC 9420) FFI static library.
#
# Spec 09 §6.3 runs a real MLS group per encrypted space; the ceremony (group
# creation, Add/Remove/Update Commits, Welcomes, the ratchet tree) and the epoch
# key schedule / §8.5 exporter are provided by OpenMLS through a thin Rust
# staticlib in third_party/mls_ffi, built with cargo exactly as the Oxigraph FFI
# above. Only the standalone harness links it: the shared Spec 09 core is
# engine-agnostic (it consumes the exporter output through the §6.3.9 seam), so
# the harness drives a genuine RFC 9420 exporter into the core's key schedule
# and AEAD envelope end-to-end (see standalone/mls_engine.h).
set(MLS_FFI_DIR ${CMAKE_SOURCE_DIR}/third_party/mls_ffi)
set(MLS_FFI_LIB ${MLS_FFI_DIR}/target/release/libmls_ffi.a)

file(GLOB MLS_FFI_SRC ${MLS_FFI_DIR}/src/*.rs)
list(APPEND MLS_FFI_SRC ${MLS_FFI_DIR}/Cargo.toml)

add_custom_command(
    OUTPUT ${MLS_FFI_LIB}
    COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{HOME}/.cargo/bin:$ENV{PATH}"
            ${CARGO} build --release --manifest-path ${MLS_FFI_DIR}/Cargo.toml
    DEPENDS ${MLS_FFI_SRC}
    WORKING_DIRECTORY ${MLS_FFI_DIR}
    COMMENT "Building OpenMLS FFI static library (cargo build --release)"
    VERBATIM
)
add_custom_target(mls_ffi_build DEPENDS ${MLS_FFI_LIB})

# The OpenMLS staticlib pulls in the Rust standard library; the final link needs
# the same system libraries as any Rust staticlib.
set(MLS_FFI_SYSTEM_LIBS gcc_s util rt pthread m dl c)

# Spec 01 — Decentralised Identity + Spec 02 — Personal Linked Data Graphs +
# Spec 03 — Decentralised Group Identity + Spec 04 — Graph Capability Framework +
# Spec 05 — Graph Synchronisation Protocol + Spec 06 — Sync Module Architecture +
# Spec 07 — Dynamic Graph Shape Validation + Spec 08 — Governance Constraint
# Vocabulary + Spec 09 — Default Sync Module.
#
# The Chromium-independent cores shared by the browser-process services and the
# standalone harness: the did:key codec + JCS (Spec 01); the RDF 1.2 term
# serialisation, Oxigraph RAII wrapper, and SPARQL Results decoder (Spec 02);
# the did:graph codec + DID-document model (Spec 03), which reuses the did:key
# codec for the byte-level Ed25519 multibase work; the ZCAP-LD
# canonicalisation core (Spec 04) — the delegation-proof pre-image, the
# actions-subset / immutable-caveats attenuation tests, and the caveat-JSON
# scanner; the GraphDiff identity + sync-space derivation core (Spec 05) —
# the revision/commitId pre-images and the space:// derivation input; the
# WIT module manifest + capability grant model (Spec 06); the SHACL shape
# definition parser + content address (Spec 07); the governance constraint
# vocabulary core (Spec 08) — glob / allow-deny decisions, RFC-3339 plausibility,
# the content-policy evaluator, and the living-web VC proof pre-image; and the
# Default Sync Module core (Spec 09) — the deterministic CBOR codec, the wire
# frame envelopes, the OR-Set membership CRDT, the §6.3.3 DID↔X25519 map, the
# §6.3.9 MLS key schedule, and the §6.3.10 AEAD frame envelope — so the bytes a
# proof signs, the verdicts governance reaches, and the frames a space encrypts
# never diverge between the two build worlds.
add_library(living_web STATIC
    content/browser/did/did_key_codec.cc
    content/browser/did/did_graph.cc
    content/browser/did/jcs.cc
    content/browser/graph/rdf_serialization.cc
    content/browser/graph/oxigraph_store.cc
    content/browser/graph/sparql_results.cc
    content/browser/governance/zcap.cc
    content/browser/graph_sync/graph_diff.cc
    content/browser/module_runtime/module_capabilities.cc
    content/browser/module_runtime/module_manifest.cc
    content/browser/shapes/shape_definition.cc
    content/browser/governance/constraint_vocabulary.cc
    content/browser/graph_sync/cbor.cc
    content/browser/graph_sync/default_sync_module.cc
)
add_dependencies(living_web oxigraph_ffi_build)
target_include_directories(living_web PUBLIC
    standalone
    ${CMAKE_SOURCE_DIR}
    ${OXIGRAPH_FFI_DIR}/include
)
target_compile_definitions(living_web PRIVATE USE_OPENSSL)
target_link_libraries(living_web PUBLIC
    ed25519
    OpenSSL::Crypto
    ${OXIGRAPH_FFI_LIB}
    ${OXIGRAPH_FFI_SYSTEM_LIBS}
)

# Standalone test harness.
#
# The base ships the self-registering test framework and the runner; each
# per-spec branch adds its own Chromium-independent sources to the `living_web`
# library above and its TEST() blocks to living_web_tests.cc.
add_executable(living_web_tests
    standalone/living_web_tests.cc
)
add_dependencies(living_web_tests mls_ffi_build)
target_include_directories(living_web_tests PRIVATE
    standalone
    ${CMAKE_SOURCE_DIR}
    ${MLS_FFI_DIR}/include
)
target_compile_definitions(living_web_tests PRIVATE USE_OPENSSL)
target_link_libraries(living_web_tests PRIVATE
    living_web
    ed25519
    OpenSSL::Crypto
    ${MLS_FFI_LIB}
    ${MLS_FFI_SYSTEM_LIBS}
)

# This executable links two independent Rust staticlibs — liboxigraph_ffi.a (via
# living_web) and libmls_ffi.a — and each bundles its own copy of the Rust
# standard library, so std-internal symbols (rust_eh_personality,
# std::panicking::EMPTY_PANIC, the argv init_array) are defined in both archives.
# Both copies come from the same local toolchain, so first-definition-wins is
# safe. In the real Chromium build these are rust_static_library GN targets and
# the Rust std is deduplicated per final binary, so this only affects the
# standalone harness link.
target_link_options(living_web_tests PRIVATE -Wl,--allow-multiple-definition)
