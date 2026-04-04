cmake_minimum_required(VERSION 3.16)
project(LivingWeb VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Ed25519 implementation (uses OpenSSL EVP)
add_library(ed25519 STATIC
    third_party/ed25519/ed25519.c
)
target_include_directories(ed25519 PUBLIC third_party/ed25519)
target_compile_definitions(ed25519 PRIVATE USE_OPENSSL)
target_link_libraries(ed25519 PRIVATE OpenSSL::Crypto)

# Standalone library
add_library(living_web STATIC
    standalone/graph_store.cc
)
target_include_directories(living_web PUBLIC
    standalone
    ${CMAKE_SOURCE_DIR}
)
target_compile_definitions(living_web PRIVATE USE_OPENSSL)
target_link_libraries(living_web PUBLIC ed25519 OpenSSL::Crypto)

# Test binary
add_executable(living_web_tests
    standalone/living_web_tests.cc
)
target_include_directories(living_web_tests PRIVATE
    standalone
    ${CMAKE_SOURCE_DIR}
)
target_compile_definitions(living_web_tests PRIVATE USE_OPENSSL)
target_link_libraries(living_web_tests PRIVATE living_web ed25519 OpenSSL::Crypto)

# Install
install(TARGETS living_web ARCHIVE DESTINATION lib)
install(DIRECTORY standalone/ DESTINATION include/living_web
    FILES_MATCHING PATTERN "*.h")
