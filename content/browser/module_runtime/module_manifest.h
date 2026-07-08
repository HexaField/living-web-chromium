// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Sync Module Architecture (Spec 06) — module content-addressing + manifest.
//
// The Chromium-independent core (namespace `living_web`, pure-std, no Chromium
// and no standalone-shim dependencies) shared byte-for-byte by the browser
// module runtime (content/browser/module_runtime/module_runtime_host.*) and the
// standalone harness (standalone/module_runtime_provider.h). It defines:
//
//   * the §4.2 content-hash format `"sha256-" + hex(SHA-256(wasm-binary))` and
//     its well-formedness check (§9.2: the user agent MUST verify a module's
//     content hash before installation);
//   * the §8.2 JSON manifest — its required/optional fields parsed into a
//     structured `ModuleManifest`, the §8.2 mutual-verifiability binding between
//     a manifest and the specific WASM binary it describes, and the §7.3 /
//     [[GROUP-IDENTITY]] §4.8.1-step-2 fork constraint-kind superset check.
//
// Like module_capabilities.cc, graph_diff.cc and zcap.cc this translation unit
// performs no hashing itself: the SHA-256 primitive resolves to a different
// header in the two build worlds (standalone/crypto_sha2.h vs //crypto), so the
// caller hashes the WASM binary and hands the raw digest to
// FormatModuleContentHash. The JSON manifest is scanned by a small self-contained
// reader (no dependency on standalone/json_parser.h) so the same bytes parse in
// both worlds.

#ifndef CONTENT_BROWSER_MODULE_RUNTIME_MODULE_MANIFEST_H_
#define CONTENT_BROWSER_MODULE_RUNTIME_MODULE_MANIFEST_H_

#include <string>
#include <vector>

namespace living_web {

// §4.2 `content-hash = "sha256-" + hex(SHA-256(wasm-binary))`. Formats the
// canonical token from the raw 32-byte SHA-256 digest of the WASM binary. The
// caller supplies the digest (the SHA-256 primitive differs per build world), so
// this core only prefixes and lowercase-hex-encodes.
std::string FormatModuleContentHash(const std::string& raw_sha256_digest);

// True iff |s| is a well-formed §4.2 content hash: the literal "sha256-" followed
// by exactly 64 lowercase hex characters (one 32-byte SHA-256 digest). Used to
// reject a malformed `wasmContentHash` at install (§7.1) and to validate the
// `group://syncModule` seed value before content-hash verification (§9.2).
bool IsWellFormedContentHash(const std::string& s);

// A parsed §8.2 module manifest. `valid` is set true only when every required
// field parsed and `wasm_content_hash` is a well-formed §4.2 content hash.
struct ModuleManifest {
  std::string name;                                     // required (§8.2)
  std::string version;                                  // required (§8.2)
  std::string wasm_content_hash;                        // required; §4.2 form
  std::vector<std::string> supported_constraint_kinds;  // required (§8.2, §7.3)
  std::vector<std::string> capabilities_required;       // required; §8 tokens
  std::string publisher;                                // optional (§8.2)
  std::string description;                               // optional (§8.2)
  bool valid = false;
};

// Parse a §8.2 manifest JSON document into |*out|. Returns true iff every
// required field — name, version, wasmContentHash, supportedConstraintKinds,
// capabilitiesRequired — is present and well-typed (the two constraint/capability
// fields as arrays of strings) and wasmContentHash is a well-formed §4.2 content
// hash. On any failure returns false, sets |*error| (when non-null) to a
// human-readable reason, and leaves out->valid == false. Unknown top-level fields
// are ignored — §8.2 permits "additional implementation-defined metadata".
bool ParseModuleManifest(const std::string& json,
                         ModuleManifest* out,
                         std::string* error);

// §8.2 mutual verifiability: the manifest's declared `wasmContentHash` equals the
// hash the runtime computed over the actual WASM binary (§7.1 step 2, §9.2).
// |computed_content_hash| is FormatModuleContentHash(SHA-256(binary)). A manifest
// that does not bind the specific binary MUST be rejected at install.
bool ManifestBindsContentHash(const ModuleManifest& manifest,
                              const std::string& computed_content_hash);

// §7.3 / §8.2 fork constraint-kind compatibility ([[GROUP-IDENTITY]] §4.8.1
// step 2): the child module that a fork names may replace the parent's only if
// its `supportedConstraintKinds` is a superset of every constraint kind currently
// in force on the parent. Returns true iff every kind in |parent_in_force|
// appears in |child_supported|; the missing kinds (the reason a fork is rejected)
// are appended to |*missing| when non-null. The check is a one-time fork
// precondition, never a runtime concern (§4.5, §7.3).
bool ConstraintKindsCompatible(const std::vector<std::string>& child_supported,
                               const std::vector<std::string>& parent_in_force,
                               std::vector<std::string>* missing);

}  // namespace living_web

#endif  // CONTENT_BROWSER_MODULE_RUNTIME_MODULE_MANIFEST_H_
