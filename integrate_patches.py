#!/usr/bin/env python3
# Copyright 2026 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# integrate_patches.py — the idempotent, in-place edits integrate.sh applies to
# shared Chromium build files so the Living Web overlay (Specs 01-10) compiles
# into the real browser. Everything here mutates a file that already exists in
# the vanilla tree; brand-new files (the graph module, the mojom, the FFI
# crates, living_web_sources.gni, the FFI BUILD.gn) are copied/written by
# integrate.sh instead.
#
# Each patch is guarded by a `LIVING_WEB:<TAG>` sentinel so re-running is safe:
# an existing region is replaced, never duplicated. Type/name inventories are
# derived by parsing the copied graph IDLs at DEST — the IDLs are the single
# source of truth, so the generated-binding output list can never drift from
# what the bindings generator actually emits.

import os
import re
import sys

DEST = os.path.abspath(sys.argv[1])
IDL_DIR = os.path.join(DEST, "third_party/blink/renderer/modules/graph")
GENV8 = "$root_gen_dir/third_party/blink/renderer/bindings/modules/v8"


def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def write(p, s):
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)


def snake(name):
    """Blink NameStyleConverter snake_case: acronym runs stay one token.
    DIDCredential->did_credential, GraphManager->graph_manager,
    GPUDevice->gpu_device (verified against the vanilla tree)."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    s2 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1)
    return s2.lower()


def decl_names(kind):
    """Non-partial top-level `<kind> Name` declarations across the graph IDLs.
    Lines beginning `partial <kind>` / `callback interface` are excluded — they
    augment existing types and emit no standalone V8 wrapper."""
    names = set()
    pat = re.compile(r"^%s\s+([A-Za-z_][A-Za-z0-9_]*)" % kind, re.M)
    for f in sorted(os.listdir(IDL_DIR)):
        if not f.endswith(".idl"):
            continue
        for m in pat.finditer(read(os.path.join(IDL_DIR, f))):
            names.add(m.group(1))
    return sorted(names)


def v8_pair(name):
    b = "%s/v8_%s" % (GENV8, snake(name))
    return ['  "%s.cc",' % b, '  "%s.h",' % b]


def gn_list(var, names):
    lines = ["%s += [" % var]
    for n in names:
        lines += v8_pair(n)
    lines.append("]")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Idempotent editing primitives. Every inserted region is fenced by a sentinel
# comment so a second run replaces rather than duplicates it.
# ---------------------------------------------------------------------------

def replace_or_append(path, tag, block, comment="#"):
    """Append `block` at EOF (used for the += .gni augmentations)."""
    s = read(path)
    begin = "%s LIVING_WEB:%s:BEGIN" % (comment, tag)
    end = "%s LIVING_WEB:%s:END" % (comment, tag)
    fenced = "%s\n%s\n%s\n" % (begin, block, end)
    pat = re.compile(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.S)
    if pat.search(s):
        s = pat.sub(fenced.rstrip("\n") + "\n", s)
    else:
        s = s.rstrip("\n") + "\n\n" + fenced
    write(path, s)


def insert_after_first(path, tag, needle, block, comment="//"):
    """Insert `block` on the line after the first line containing `needle`."""
    s = read(path)
    sentinel = "LIVING_WEB:%s" % tag
    if sentinel in s:
        return
    fenced = "%s %s\n%s" % (comment, sentinel, block)
    out, done = [], False
    for ln in s.split("\n"):
        out.append(ln)
        if not done and needle in ln:
            out.append(fenced)
            done = True
    if not done:
        raise SystemExit("integrate_patches: anchor not found in %s: %r" % (path, needle))
    write(path, "\n".join(out))


def insert_before_first(path, tag, needle, block, comment="//"):
    """Insert `block` immediately before the first line containing `needle`."""
    s = read(path)
    sentinel = "LIVING_WEB:%s" % tag
    if sentinel in s:
        return
    fenced = "%s %s\n%s" % (comment, sentinel, block)
    out, done = [], False
    for ln in s.split("\n"):
        if not done and needle in ln:
            out.append(fenced)
            done = True
        out.append(ln)
    if not done:
        raise SystemExit("integrate_patches: anchor not found in %s: %r" % (path, needle))
    write(path, "\n".join(out))


def inject_into_target(path, tag, target_decl, inject):
    """Insert `inject` just before the closing brace of the GN target whose
    declaration line contains `target_decl` (brace-matched, so nested blocks
    are handled)."""
    s = read(path)
    if "LIVING_WEB:%s" % tag in s:
        return
    i = s.index(target_decl)
    b = s.index("{", i)
    depth, j = 0, b
    while j < len(s):
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    s = s[:j] + inject + s[j:]
    write(path, s)


# ---------------------------------------------------------------------------
# Payload-derived inventories. Everything the patches register is read back from
# the copied overlay, so a partial overlay (one stacked spec branch) patches
# exactly its own surface and no more — the same self-scaling contract the IDL
# lists above already follow.
# ---------------------------------------------------------------------------

def doc_state_bind_interfaces():
    """Realm factory interfaces to register in browser_interface_binders, derived
    from the Bind<Name> methods LivingWebDocumentState actually declares. Each
    Bind<Name> binds graph::mojom::<Name>, so the set self-scales with whichever
    specs are present (Spec 01 -> DIDCredentialService; +Spec 02 ->
    PersonalGraphManager; +Spec 03 -> GroupManager). Order follows the header so
    a full-stack run reproduces the hand-written block. Empty when the document
    state is absent (the base build-infra layer)."""
    hdr = os.path.join(
        DEST, "content/browser/living_web/living_web_document_state.h")
    if not os.path.isfile(hdr):
        return []
    seen, out = set(), []
    for n in re.findall(r"\bBind([A-Za-z0-9]+)\s*\(", read(hdr)):
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def idl_event_handlers():
    """Event type names = the on<name> EventHandler attributes declared across
    the graph IDLs (ontripleadded -> 'tripleadded'). Sorted + de-duped; empty
    until an IDL that owns EventHandlers is present (Spec 02+)."""
    if not os.path.isdir(IDL_DIR):
        return []
    names = set()
    for f in sorted(os.listdir(IDL_DIR)):
        if not f.endswith(".idl"):
            continue
        for m in re.finditer(
                r"attribute EventHandler on([a-z]+)",
                read(os.path.join(IDL_DIR, f))):
            names.add(m.group(1))
    return sorted(names)


def idl_event_targets():
    """EventTarget subclasses declared in the graph IDLs (`interface X :
    EventTarget`) -> the event_target_modules_names entries. Sorted; empty until
    an EventTarget-derived interface is present (Graph/GraphManager, Spec 02+)."""
    if not os.path.isdir(IDL_DIR):
        return []
    names = set()
    pat = re.compile(r"^\s*interface\s+([A-Za-z0-9_]+)\s*:\s*EventTarget", re.M)
    for f in sorted(os.listdir(IDL_DIR)):
        if not f.endswith(".idl"):
            continue
        for m in pat.finditer(read(os.path.join(IDL_DIR, f))):
            names.add(m.group(1))
    return sorted(names)


# ---------------------------------------------------------------------------
# The patches.
# ---------------------------------------------------------------------------

def patch_browser_build():
    path = os.path.join(DEST, "content/browser/BUILD.gn")
    # Pull in the generated source/dep lists next to the other imports.
    insert_after_first(
        path, "IMPORT", 'import("//',
        'import("//content/browser/living_web_sources.gni")',
        comment="#")
    # The overlay's browser dirs form a fully cyclic include graph, so their
    # non-kernel sources cannot be separate source_sets; they are folded into
    # source_set("browser") (one target => no cycle). backends borrow each other
    # across dirs. living_web_browser_deps carries the :living_web_core dep.
    inject = (
        "\n  # LIVING_WEB:BROWSERFOLD Living Web (Specs 01-10) browser services.\n"
        "  sources += living_web_browser_sources\n"
        "  deps += living_web_browser_deps\n")
    inject_into_target(path, "BROWSERFOLD", 'source_set("browser")', inject)
    # The spec kernel is base-free portable C++ shared with the standalone CMake
    # harness. It cannot satisfy the //base-only clang plugins (chromium-style
    # complex-class, raw_ptr/raw_ref field checks, unsafe-buffer-usage), so it is
    # built as its own target with exactly those three plugin configs removed —
    # the same no-plugin regime the harness compiles it under. find_bad_constructs
    # transitively supplies raw_ptr_check, so dropping it drops the raw_ptr/raw_ref
    # checks too. source_set("browser") depends on it via living_web_browser_deps.
    core_target = "\n".join([
        '# LIVING_WEB:CORETARGET:BEGIN',
        'source_set("living_web_core") {',
        '  sources = living_web_core_sources',
        '  configs -= [',
        '    "//build/config/compiler:chromium_code",',
        '    "//build/config/clang:find_bad_constructs",',
        '    "//build/config/clang:unsafe_buffers",',
        '  ]',
        '  configs += [ "//build/config/compiler:no_chromium_code" ]',
        '  deps = living_web_core_deps',
        '}',
        '# LIVING_WEB:CORETARGET:END',
    ])
    s = read(path)
    if "LIVING_WEB:CORETARGET:BEGIN" not in s:
        write(path, s.rstrip("\n") + "\n\n" + core_target + "\n")


def patch_binders():
    interfaces = doc_state_bind_interfaces()
    if not interfaces:
        return  # No realm factory surface present (base build-infra layer).
    path = os.path.join(DEST, "content/browser/browser_interface_binders.cc")
    insert_after_first(
        path, "INCLUDE",
        '#include "content/browser/browser_interface_binders.h"',
        '#include "content/browser/living_web/living_web_document_state.h"\n'
        '#include "mojo/public/mojom/graph/graph.mojom.h"')
    lines = [
        "  // Living Web realm-scoped factory interfaces. Each is owned by the",
        "  // document's LivingWebDocumentState; this list tracks its Bind* methods.",
    ]
    for iface in interfaces:
        lines += [
            "  map->Add<graph::mojom::%s>(" % iface,
            "      [](RenderFrameHost* host,",
            "         mojo::PendingReceiver<graph::mojom::%s>" % iface,
            "             receiver) {",
            "        LivingWebDocumentState::GetOrCreateForCurrentDocument(host)",
            "            ->Bind%s(std::move(receiver));" % iface,
            "      });",
        ]
    lines.append("")
    insert_before_first(
        path, "BINDERS",
        "// This should be last to allow overrides of any interface.",
        "\n".join(lines))


def patch_modules_build():
    path = os.path.join(DEST, "third_party/blink/renderer/modules/BUILD.gn")
    insert_after_first(
        path, "MODULE",
        '"//third_party/blink/renderer/modules/gamepad",',
        '    "//third_party/blink/renderer/modules/graph",',
        comment="#")


def patch_idl_in_modules():
    path = os.path.join(DEST, "third_party/blink/renderer/bindings/idl_in_modules.gni")
    idls = sorted(f for f in os.listdir(IDL_DIR) if f.endswith(".idl"))
    body = "\n".join(
        '  "//third_party/blink/renderer/modules/graph/%s",' % f for f in idls)
    block = "static_idl_files_in_modules += [\n%s\n]" % body
    replace_or_append(path, "IDL", block)


def patch_generated_in_modules():
    path = os.path.join(DEST, "third_party/blink/renderer/bindings/generated_in_modules.gni")
    interfaces = decl_names("interface")
    dicts = decl_names("dictionary")
    enums = decl_names("enum")
    # The one union in the corpus: (USVString or LiteralValue). Blink names union
    # wrappers v8_union_<members lowercased, sorted, joined by _> (verified against
    # the vanilla tree, e.g. v8_union_arraybuffer_..._usvstring_writeparams).
    union = "\n".join([
        "generated_union_sources_in_modules += [",
        '  "%s/v8_union_literalvalue_usvstring.cc",' % GENV8,
        '  "%s/v8_union_literalvalue_usvstring.h",' % GENV8,
        "]",
    ])
    block = "\n\n".join([
        gn_list("generated_interface_sources_in_modules", interfaces),
        gn_list("generated_dictionary_sources_in_modules", dicts),
        gn_list("generated_enumeration_sources_in_modules", enums),
        union,
    ])
    replace_or_append(path, "GENERATED", block)


def patch_event_type_names():
    # The EventHandler attributes declared across the graph IDLs (e.g. the full
    # stack: diff, peerjoined, peerleft, signal, subscriptiongained,
    # subscriptionlost, syncstatechange, transitiondeadline, transitionfired,
    # tripleadded, tripleremoved). Derived so a partial overlay registers only
    # the events its own IDLs declare.
    events = idl_event_handlers()
    if not events:
        return
    path = os.path.join(DEST, "third_party/blink/renderer/core/events/event_type_names.json5")
    block = "\n".join('    "%s",' % e for e in events)
    insert_after_first(path, "EVENTS", "data: [", block)


def patch_event_target_names():
    # The graph IDL interfaces declared `: EventTarget` (Graph dispatches
    # triple/diff/sync/flow events; GraphManager dispatches subscription lifecycle
    # events). Their InterfaceName() returns event_target_names::k<Name>, emitted
    # from this static list — unlike event interface names, event target names are
    # not derived from the IDL database, so they are seeded here from the IDLs.
    targets = idl_event_targets()
    if not targets:
        return
    path = os.path.join(
        DEST,
        "third_party/blink/renderer/modules/event_target_modules_names.json5")
    block = "\n".join('    "%s",' % t for t in targets)
    insert_after_first(path, "EVENTTARGETS", "data: [", block)


def main():
    if not os.path.isdir(IDL_DIR):
        # No graph module overlay at this layer — nothing shared to patch. This
        # is the base build-infra state (main): the tooling is present but no
        # spec payload is stacked on it yet.
        print("integrate_patches: no graph IDL overlay at %s — nothing to patch"
              % IDL_DIR)
        return
    patch_browser_build()
    patch_binders()
    patch_modules_build()
    patch_idl_in_modules()
    patch_generated_in_modules()
    patch_event_type_names()
    patch_event_target_names()
    print("integrate_patches: patched content/browser/BUILD.gn, "
          "browser_interface_binders.cc, modules/BUILD.gn, idl_in_modules.gni, "
          "generated_in_modules.gni, event_type_names.json5, "
          "event_target_modules_names.json5")


if __name__ == "__main__":
    main()
