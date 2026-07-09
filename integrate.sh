#!/bin/bash
# integrate.sh — overlay the Living Web browser onto a full Chromium checkout so
# `autoninja -C out/LivingWeb chrome` builds the real browser with
# navigator.graph, decentralised groups, and DID credentials native. The overlay
# lives in this repo (the source of truth); this script projects it onto a
# throwaway Chromium tree and never edits this repo.
#
# It is PAYLOAD-TOLERANT: this script and integrate_patches.py are the
# spec-agnostic build harness that lives on `main`. Every spec branch stacks its
# overlay on top of `main`, so a given branch tip carries only the cumulative
# subset of overlay files for the specs that have landed there. This script
# discovers what is actually present and integrates exactly that:
#   * bare main (no overlay) => a clean no-op.
#   * a spec-NN tip          => integrates specs 01..NN's cumulative overlay.
#   * the full stack         => integrates all ten specs.
#
# It does three kinds of work:
#   * copy   — brand-new files (mojom, blink graph module, browser services,
#              FFI crates) are rsync'd into the Chromium tree.
#   * generate — two GN files that are pure functions of what was copied:
#              content/browser/living_web_sources.gni (the folded browser
#              source list) and third_party/<crate>/BUILD.gn (prebuilt
#              staticlib wrappers). Rewritten every run.
#   * patch  — integrate_patches.py makes the in-place edits to shared
#              Chromium files, each fenced by a LIVING_WEB:<TAG> sentinel. It is
#              itself payload-tolerant (derives every edit from the overlay that
#              is present, and no-ops when the graph IDL overlay is absent).
#
# All three are idempotent, so the script is safe to re-run after pulling new
# overlay code.
#
# Usage:  integrate.sh <chromium-src-dir> [overlay-src-dir]
#   overlay-src-dir defaults to this script's own directory.

set -euo pipefail

die() { echo "integrate: $*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: integrate.sh <chromium-src-dir> [overlay-src-dir]"
DEST="$(cd "$1" 2>/dev/null && pwd)" || die "cannot cd to chromium src: $1"
SRC="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

[ -f "$DEST/BUILD.gn" ] && [ -e "$DEST/.gn" ] || die "$DEST is not a Chromium src/ checkout"
[ -f "$SRC/integrate_patches.py" ] || die "$SRC/integrate_patches.py missing"

# ---------------------------------------------------------------------------
# 0. Discover the overlay payload actually present in SRC. Every browser dir,
#    crate, and shared surface is optional: a spec branch only carries the
#    subset its specs introduced. Crate presence is gated on the crate SOURCE
#    (Cargo.toml), not just the dir, so a leftover cargo target/ tree on an
#    overlay-free branch does not register as payload.
# ---------------------------------------------------------------------------
ALL_BROWSER_DIRS=(did flows governance graph graph_sync living_web module_runtime shapes)
ALL_CRATES=(oxigraph_ffi mls_ffi)

BROWSER_DIRS=()
for d in "${ALL_BROWSER_DIRS[@]}"; do
  [ -d "$SRC/content/browser/$d" ] && BROWSER_DIRS+=("$d")
done
CRATES=()
for c in "${ALL_CRATES[@]}"; do
  [ -f "$SRC/third_party/$c/Cargo.toml" ] && CRATES+=("$c")
done

HAS_MOJOM=0;    [ -d "$SRC/mojo/public/mojom/graph" ] && HAS_MOJOM=1
HAS_BLINK=0;    [ -d "$SRC/third_party/blink/renderer/modules/graph" ] && HAS_BLINK=1
HAS_ED25519=0;  [ -d "$SRC/third_party/ed25519" ] && HAS_ED25519=1
HAS_OXIGRAPH=0; printf '%s\n' "${CRATES[@]:-}" | grep -qxF oxigraph_ffi && HAS_OXIGRAPH=1
HAS_MLS=0;      printf '%s\n' "${CRATES[@]:-}" | grep -qxF mls_ffi && HAS_MLS=1

echo "== Living Web overlay integration =="
echo "   DEST (chromium): $DEST"
echo "   SRC  (overlay) : $SRC"

# No overlay at all => this is bare main (the harness with no spec code). Nothing
# to integrate; leave the Chromium tree untouched and exit clean.
if [ "${#BROWSER_DIRS[@]}" -eq 0 ] && [ "$HAS_MOJOM" -eq 0 ] && [ "$HAS_BLINK" -eq 0 ]; then
  echo "-- no overlay present in SRC — nothing to integrate (bare harness)"
  echo "== integration complete (no-op) =="
  exit 0
fi

echo "   overlay dirs   : ${BROWSER_DIRS[*]:-(none)}"
echo "   FFI crates     : ${CRATES[*]:-(none)}"
echo "   mojom/blink/ed : $HAS_MOJOM/$HAS_BLINK/$HAS_ED25519"

# The shared spec kernel. These <dir>/<name> stems are the exact .cc set the
# standalone CMake harness compiles (see CMakeLists.txt add_library(living_web
# ...)); each also has a paired .h. They are base-free portable C++ and are
# compiled identically in both build worlds, so in the Chromium overlay they
# must NOT face the //base-only plugins (chromium-style complex-class,
# raw_ptr/raw_ref, unsafe-buffer-usage) — those flag idioms the harness has no
# way to satisfy. So they are split into their own source_set("living_web_core")
# with those plugin configs removed (see integrate_patches.py CORETARGET).
# Everything else under BROWSER_DIRS is the overlay (full Chromium code) folded
# into source_set("browser"). Stems for specs not present are simply never
# matched, so this list is a stable superset across all branch tips.
LIVING_WEB_CORE_STEMS=(
  did/did_key_codec did/did_graph did/jcs
  graph/rdf_serialization graph/oxigraph_store graph/sparql_results
  governance/zcap governance/constraint_vocabulary
  graph_sync/graph_diff graph_sync/cbor graph_sync/default_sync_module
  module_runtime/module_capabilities module_runtime/module_manifest
  shapes/shape_definition
  flows/flow_definition
)

# ---------------------------------------------------------------------------
# 1. FFI staticlibs. Each crate builds a self-contained cargo staticlib that
#    bundles the Rust std and any native backend (Oxigraph bundles RocksDB), so
#    the final Chromium link needs only the one archive per crate plus libstdc++
#    (for RocksDB's C++). Build in SRC only when the archive is missing, so a
#    warm worktree is a no-op. Skipped entirely when no crate is present.
# ---------------------------------------------------------------------------
if [ "${#CRATES[@]}" -gt 0 ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
  command -v cargo >/dev/null || die "cargo not on PATH (need ~/.cargo/bin)"
  for c in "${CRATES[@]}"; do
    lib="$SRC/third_party/$c/target/release/lib$c.a"
    if [ ! -f "$lib" ]; then
      echo "-- cargo build --release ($c)"
      cargo build --release --manifest-path "$SRC/third_party/$c/Cargo.toml"
    fi
    [ -f "$lib" ] || die "missing staticlib after build: $lib"
  done
fi

# ---------------------------------------------------------------------------
# 2. Copy overlay files into the Chromium tree. Every step is guarded on the
#    presence of its source, so each spec tip copies only its own subset.
# ---------------------------------------------------------------------------
echo "-- copying overlay sources"
# 2a. Mojo IPC module (graph.mojom + its BUILD.gn).
if [ "$HAS_MOJOM" -eq 1 ]; then
  rsync -a "$SRC/mojo/public/mojom/graph/" "$DEST/mojo/public/mojom/graph/"
fi
# 2b. Blink renderer module (all .cc/.h/.idl + BUILD.gn).
if [ "$HAS_BLINK" -eq 1 ]; then
  rsync -a "$SRC/third_party/blink/renderer/modules/graph/" \
           "$DEST/third_party/blink/renderer/modules/graph/"
fi
# 2c. Browser-process services — per-dir BUILD.gn dropped (sources are folded,
#     see step 3 + integrate_patches.py BROWSERFOLD).
for d in "${BROWSER_DIRS[@]}"; do
  rsync -a --exclude='BUILD.gn' "$SRC/content/browser/$d/" "$DEST/content/browser/$d/"
done
# 2c'. Ed25519 C shim (third_party) — the folded browser services call its
#      lowercase ed25519_{create_keypair,sign,verify} C ABI (extern "C"). Its
#      BUILD.gn is a real committed target (not generated), so copy the dir
#      as-is, BUILD.gn included.
if [ "$HAS_ED25519" -eq 1 ]; then
  rsync -a "$SRC/third_party/ed25519/" "$DEST/third_party/ed25519/"
fi
# 2d. FFI crates: sources (skip the bulky target/ tree) plus the one prebuilt
#     self-contained archive per crate, placed where the generated BUILD.gn
#     lib_dirs expects it.
for c in "${CRATES[@]}"; do
  rsync -a --exclude='target' "$SRC/third_party/$c/" "$DEST/third_party/$c/"
  mkdir -p "$DEST/third_party/$c/target/release"
  cp -f "$SRC/third_party/$c/target/release/lib$c.a" \
        "$DEST/third_party/$c/target/release/lib$c.a"
done

# ---------------------------------------------------------------------------
# 3. Generate content/browser/living_web_sources.gni — the browser source list
#    folded into source_set("browser"), plus the extra deps that fold needs.
#    Globbed from DEST after the copy so it is exactly what is on disk.
# ---------------------------------------------------------------------------
echo "-- generating content/browser/living_web_sources.gni"
GNI="$DEST/content/browser/living_web_sources.gni"

# Partition every copied browser source into the shared kernel (core) and the
# overlay, by exact <dir>/<name> stem match against LIVING_WEB_CORE_STEMS.
core_lines=""
browser_lines=""
if [ "${#BROWSER_DIRS[@]}" -gt 0 ]; then
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    rel="${path#"$DEST"/content/browser/}"   # e.g. graph/oxigraph_store.h
    stem="${rel%.*}"                          # e.g. graph/oxigraph_store
    line="  \"//${path#"$DEST"/}\","
    if printf '%s\n' "${LIVING_WEB_CORE_STEMS[@]}" | grep -qxF -- "$stem"; then
      core_lines+="$line"$'\n'
    else
      browser_lines+="$line"$'\n'
    fi
  done < <(
    for d in "${BROWSER_DIRS[@]}"; do
      find "$DEST/content/browser/$d" -type f \( -name '*.cc' -o -name '*.h' \)
    done | LC_ALL=C sort
  )
fi

# Deps are conditional on what the overlay actually pulls in. boringssl is always
# available in the Chromium tree; the FFI staticlibs and the graph mojom target
# only exist when their payload is present, so referencing them unconditionally
# would break gn on a partial tip.
core_dep_lines="  \"//third_party/boringssl\","$'\n'
[ "$HAS_ED25519" -eq 1 ]  && core_dep_lines+="  \"//third_party/ed25519\","$'\n'
[ "$HAS_OXIGRAPH" -eq 1 ] && core_dep_lines+="  \"//third_party/oxigraph_ffi\","$'\n'

browser_dep_lines=""
[ "$HAS_MOJOM" -eq 1 ]    && browser_dep_lines+="  \"//mojo/public/mojom/graph\","$'\n'
[ "$HAS_OXIGRAPH" -eq 1 ] && browser_dep_lines+="  \"//third_party/oxigraph_ffi\","$'\n'
[ "$HAS_MLS" -eq 1 ]      && browser_dep_lines+="  \"//third_party/mls_ffi\","$'\n'
[ "$HAS_ED25519" -eq 1 ]  && browser_dep_lines+="  \"//third_party/ed25519\","$'\n'
[ -n "$core_lines" ]      && browser_dep_lines+="  \":living_web_core\","$'\n'

{
  echo "# Generated by integrate.sh — do not edit."
  echo "#"
  echo "# The Living Web browser is built as two GN targets:"
  echo "#"
  echo "#   living_web_core_sources     — the base-free spec kernel. Built by"
  echo "#     source_set(\"living_web_core\") with the //base-only clang plugins"
  echo "#     removed (see integrate_patches.py CORETARGET), so the exact bytes"
  echo "#     the standalone CMake harness compiles also compile here."
  echo "#"
  echo "#   living_web_browser_sources  — the overlay (full Chromium code). The"
  echo "#     overlay dirs form a cyclic include graph, so their non-kernel"
  echo "#     sources are folded into content/browser's source_set(\"browser\")"
  echo "#     (one target => no cycle). See integrate_patches.py BROWSERFOLD."
  echo "living_web_core_sources = ["
  printf '%s' "$core_lines"
  echo "]"
  echo ""
  echo "living_web_browser_sources = ["
  printf '%s' "$browser_lines"
  echo "]"
  echo ""
  echo "# Deps the kernel needs to compile+link on its own (it does not inherit"
  echo "# content/browser's deps): BoringSSL for the Ed25519 EVP backend, the"
  echo "# Ed25519 C shim, and the Oxigraph quad-store FFI staticlib — each"
  echo "# included only when its payload is present at this tip."
  echo "living_web_core_deps = ["
  printf '%s' "$core_dep_lines"
  echo "]"
  echo ""
  echo "# Extra deps the folded overlay sources need beyond what"
  echo "# source_set(\"browser\") already links: the graph Mojo C++ bindings, the"
  echo "# Rust FFI staticlibs (Oxigraph quad store, OpenMLS group crypto), the"
  echo "# Ed25519 C shim, and the kernel target itself — each included only when"
  echo "# its payload is present at this tip."
  echo "living_web_browser_deps = ["
  printf '%s' "$browser_dep_lines"
  echo "]"
} > "$GNI"

# ---------------------------------------------------------------------------
# 4. Generate third_party/<crate>/BUILD.gn — a GN wrapper for each prebuilt
#    cargo staticlib. Both archives bundle their own copy of the Rust std, so
#    the final link needs --allow-multiple-definition (same toolchain =>
#    first-definition-wins is safe; this is the project's established two-
#    staticlib link pattern). The header is included by full src-root path, so
#    no include config is required — the wrappers are link-only, except that
#    oxigraph_ffi additionally carries the host-toolchain shims RocksDB needs.
# ---------------------------------------------------------------------------
if [ "${#CRATES[@]}" -gt 0 ]; then
  echo "-- generating FFI BUILD.gn wrappers"

  # The oxigraph archive bundles RocksDB (C++), whose objects cargo compiled
  # against the host glibc (2.43) + host libstdc++. The browser links the older
  # bullseye sysroot (glibc 2.31, no libstdc++), so RocksDB's C23 number parsers
  # (__isoc23_*), __libc_single_threaded, and the newer libstdc++ ABI symbols are
  # undefined at the final link. We keep the browser on its tested sysroot and
  # resolve just those: living_web_libc_compat.c forwards the glibc symbols, and
  # the link pulls the host libstdc++.so.6 by absolute path (its SONAME makes the
  # runtime loader select the same host library the binary runs against anyway).
  # Only needed when oxigraph_ffi is present.
  HOST_LIBSTDCXX=""
  if [ "$HAS_OXIGRAPH" -eq 1 ]; then
    HOST_LIBSTDCXX="$(cc -print-file-name=libstdc++.so.6 2>/dev/null || true)"
    case "$HOST_LIBSTDCXX" in
      /*) HOST_LIBSTDCXX="$(realpath "$HOST_LIBSTDCXX" 2>/dev/null || echo "$HOST_LIBSTDCXX")" ;;
      *)  HOST_LIBSTDCXX=/usr/lib/x86_64-linux-gnu/libstdc++.so.6 ;;
    esac
    [ -e "$HOST_LIBSTDCXX" ] || die "host libstdc++.so.6 not found (needed for the oxigraph_ffi RocksDB link): $HOST_LIBSTDCXX"
  fi

  for c in "${CRATES[@]}"; do
    if [ "$c" = oxigraph_ffi ]; then
      cat > "$DEST/third_party/$c/BUILD.gn" <<EOF
# Generated by integrate.sh — do not edit.
# Prebuilt cargo staticlib wrapper (oxigraph_ffi) with host-toolchain shims.
# The archive is self-contained (bundles the Rust std and RocksDB) and is
# produced by 'cargo build --release'; --allow-multiple-definition covers the
# two archives' duplicated libstd (same toolchain => first-definition-wins).
# RocksDB was built against the host glibc/libstdc++, so the browser's bullseye
# sysroot cannot satisfy its C23 parsers (__isoc23_*), __libc_single_threaded,
# or the newer libstdc++ ABI symbols: living_web_libc_compat.c forwards the
# former, and the host libstdc++.so.6 (linked by absolute path; resolved to the
# host copy at runtime via its SONAME) supplies the latter.
config("${c}_link") {
  lib_dirs = [ rebase_path("target/release", root_build_dir) ]
  libs = [ "$c" ]
  ldflags = [
    "-Wl,--allow-multiple-definition",
    "$HOST_LIBSTDCXX",
  ]
}

# Carries the libc compat shim as its single source; all_dependent_configs
# propagates the link flags transitively to whichever component/binary finally
# links the browser.
source_set("$c") {
  sources = [ "living_web_libc_compat.c" ]
  all_dependent_configs = [ ":${c}_link" ]
}
EOF
    else
      cat > "$DEST/third_party/$c/BUILD.gn" <<EOF
# Generated by integrate.sh — do not edit.
# Prebuilt cargo staticlib wrapper ($c). The archive is self-contained
# (bundles the Rust std and any native backend); it is produced by
# 'cargo build --release' and copied in by integrate.sh. Both Living Web FFI
# archives bundle libstd, so --allow-multiple-definition is required at the
# final link (same toolchain => first-definition-wins is safe). Any libstdc++
# ABI it needs is supplied by the host libstdc++ the oxigraph_ffi wrapper links
# into the same final binary.
config("${c}_link") {
  lib_dirs = [ rebase_path("target/release", root_build_dir) ]
  libs = [ "$c" ]
  ldflags = [ "-Wl,--allow-multiple-definition" ]
}

# Link-only: no sources. all_dependent_configs propagates the link flags
# transitively to whichever component/binary finally links the browser.
source_set("$c") {
  all_dependent_configs = [ ":${c}_link" ]
}
EOF
    fi
  done
fi

# ---------------------------------------------------------------------------
# 5. Patch shared Chromium files (idempotent, sentinel-fenced). integrate_patches
#    is itself payload-tolerant: it derives every binder/event/IDL edit from the
#    overlay present and no-ops when the graph IDL overlay is absent.
# ---------------------------------------------------------------------------
echo "-- patching shared Chromium files"
python3 "$SRC/integrate_patches.py" "$DEST"

# ---------------------------------------------------------------------------
# 6. Report + next steps.
# ---------------------------------------------------------------------------
ncore=$(sed -n '/^living_web_core_sources = \[/,/^\]/p' "$GNI" | grep -c '\.cc",\|\.h",' || true)
nover=$(sed -n '/^living_web_browser_sources = \[/,/^\]/p' "$GNI" | grep -c '\.cc",\|\.h",' || true)
echo ""
echo "== integration complete =="
echo "   kernel sources (living_web_core) : $ncore"
echo "   folded overlay sources (browser) : $nover"
echo "   generated              : content/browser/living_web_sources.gni"
for c in "${CRATES[@]}"; do echo "                            third_party/$c/BUILD.gn"; done
echo ""
echo "Next:"
echo "  cd $DEST"
echo "  gn gen out/LivingWeb --args='is_debug=false is_component_build=true \\"
echo "      symbol_level=0 blink_symbol_level=0 use_remoteexec=false'"
echo "  # validate the binding codegen output lists before the multi-hour build:"
echo "  autoninja -C out/LivingWeb \\"
echo "      third_party/blink/renderer/bindings:generate_bindings_all"
echo "  # then the browser:"
echo "  autoninja -C out/LivingWeb chrome"
