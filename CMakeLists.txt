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

# Standalone test harness.
#
# The base ships the self-registering test framework and the runner only (zero
# tests). Each per-spec branch adds its own Chromium-independent sources — a
# `living_web` static library built from `standalone/` and the shared
# `content/browser/**` modules — and links it in here, alongside its TEST()
# blocks in living_web_tests.cc.
add_executable(living_web_tests
    standalone/living_web_tests.cc
)
target_include_directories(living_web_tests PRIVATE
    standalone
    ${CMAKE_SOURCE_DIR}
)
target_compile_definitions(living_web_tests PRIVATE USE_OPENSSL)
target_link_libraries(living_web_tests PRIVATE ed25519 OpenSSL::Crypto)
