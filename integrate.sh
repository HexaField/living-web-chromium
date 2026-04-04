#!/bin/bash
# ==========================================================================
# Living Web Chromium Integration Script
# ==========================================================================
# This script integrates the Living Web APIs into a Chromium source checkout.
# Run from the Chromium src/ directory after `fetch chromium` and `gclient sync`.
#
# Usage:
#   cd ~/workspaces/chromium/src
#   bash ~/workspaces/hexafield/living-web-browser/integrate.sh
#
# What it does:
#   1. Copies Living Web source files into the Chromium tree
#   2. Patches existing BUILD.gn files to include Living Web modules
#   3. Registers Mojo interfaces
#   4. Registers Blink IDL files
#   5. Registers the browser-side service factory
# ==========================================================================

set -euo pipefail

CHROMIUM_SRC="${1:-$(pwd)}"
LIVING_WEB="${2:-$HOME/workspaces/hexafield/living-web-chromium}"

if [ ! -f "$CHROMIUM_SRC/BUILD.gn" ]; then
  echo "ERROR: Run from Chromium src/ directory, or pass it as first arg"
  echo "Usage: $0 [chromium_src_dir] [living_web_dir]"
  exit 1
fi

echo "=== Living Web Chromium Integration ==="
echo "Chromium: $CHROMIUM_SRC"
echo "Living Web: $LIVING_WEB"
echo ""

# ------------------------------------------------------------------
# Step 1: Copy source files
# ------------------------------------------------------------------
echo "[1/6] Copying source files..."

# Mojo interfaces
mkdir -p "$CHROMIUM_SRC/mojo/public/mojom/graph"
cp -v "$LIVING_WEB/mojo/public/mojom/graph/graph.mojom" \
      "$CHROMIUM_SRC/mojo/public/mojom/graph/"
cp -v "$LIVING_WEB/mojo/public/mojom/graph/graph_sync.mojom" \
      "$CHROMIUM_SRC/mojo/public/mojom/graph/"
cp -v "$LIVING_WEB/mojo/public/mojom/graph/graph_governance.mojom" \
      "$CHROMIUM_SRC/mojo/public/mojom/graph/"
cp -v "$LIVING_WEB/mojo/public/mojom/graph/BUILD.gn" \
      "$CHROMIUM_SRC/mojo/public/mojom/graph/"

# Browser-process graph store
mkdir -p "$CHROMIUM_SRC/content/browser/graph"
cp -v "$LIVING_WEB/content/browser/graph/"*.{cc,h} \
      "$CHROMIUM_SRC/content/browser/graph/"
cp -v "$LIVING_WEB/content/browser/graph/BUILD.gn" \
      "$CHROMIUM_SRC/content/browser/graph/"

# Browser-process DID provider
mkdir -p "$CHROMIUM_SRC/content/browser/did"
cp -v "$LIVING_WEB/content/browser/did/"*.{cc,h} \
      "$CHROMIUM_SRC/content/browser/did/"
cp -v "$LIVING_WEB/content/browser/did/BUILD.gn" \
      "$CHROMIUM_SRC/content/browser/did/"

# Browser-process graph sync
mkdir -p "$CHROMIUM_SRC/content/browser/graph_sync"
cp -v "$LIVING_WEB/content/browser/graph_sync/"*.{cc,h} \
      "$CHROMIUM_SRC/content/browser/graph_sync/"
cp -v "$LIVING_WEB/content/browser/graph_sync/BUILD.gn" \
      "$CHROMIUM_SRC/content/browser/graph_sync/"

# Browser-process governance
mkdir -p "$CHROMIUM_SRC/content/browser/graph_governance"
cp -v "$LIVING_WEB/content/browser/graph_governance/"*.{cc,h} \
      "$CHROMIUM_SRC/content/browser/graph_governance/"
cp -v "$LIVING_WEB/content/browser/graph_governance/BUILD.gn" \
      "$CHROMIUM_SRC/content/browser/graph_governance/"

# Blink renderer modules
mkdir -p "$CHROMIUM_SRC/third_party/blink/renderer/modules/graph"
cp -v "$LIVING_WEB/third_party/blink/renderer/modules/graph/"*.{cc,h,idl} \
      "$CHROMIUM_SRC/third_party/blink/renderer/modules/graph/"
cp -v "$LIVING_WEB/third_party/blink/renderer/modules/graph/BUILD.gn" \
      "$CHROMIUM_SRC/third_party/blink/renderer/modules/graph/"

echo ""

# ------------------------------------------------------------------
# Step 2: Patch content/browser/BUILD.gn to include Living Web deps
# ------------------------------------------------------------------
echo "[2/6] Patching content/browser/BUILD.gn..."

CONTENT_BROWSER_GN="$CHROMIUM_SRC/content/browser/BUILD.gn"
if ! grep -q "content/browser/graph" "$CONTENT_BROWSER_GN"; then
  # Find the deps = [ section in the main "browser" source_set and add our deps
  # We add after the last existing dep in the main browser target
  python3 -c "
import re

with open('$CONTENT_BROWSER_GN', 'r') as f:
    content = f.read()

# Add our source_sets as deps in the main browser target
# Look for the 'deps = [' block and add our entries
living_web_deps = '''
    # Living Web APIs
    \"//content/browser/graph\",
    \"//content/browser/did\",
    \"//content/browser/graph_sync\",
    \"//content/browser/graph_governance\",'''

# Find the first 'deps = [' in a source_set(\"browser\") context
# We'll add our deps right after 'deps = ['
if '# Living Web APIs' not in content:
    # Find the 'browser' source_set's deps
    # Strategy: find 'source_set(\"browser\")' then its 'deps = [' 
    pattern = r'(source_set\(\"browser\"\).*?deps\s*=\s*\[)'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        insert_pos = match.end()
        content = content[:insert_pos] + living_web_deps + content[insert_pos:]
        with open('$CONTENT_BROWSER_GN', 'w') as f:
            f.write(content)
        print('  Patched content/browser/BUILD.gn')
    else:
        print('  WARNING: Could not find browser source_set deps. Manual patching needed.')
else:
    print('  Already patched')
"
else
  echo "  Already patched"
fi

echo ""

# ------------------------------------------------------------------
# Step 3: Register Blink IDL files in modules
# ------------------------------------------------------------------
echo "[3/6] Registering Blink modules..."

# Add 'graph' to the list of blink modules
MODULES_GN="$CHROMIUM_SRC/third_party/blink/renderer/modules/BUILD.gn"
if ! grep -q '"graph"' "$MODULES_GN" 2>/dev/null; then
  python3 -c "
with open('$MODULES_GN', 'r') as f:
    content = f.read()

# The modules BUILD.gn has a list of module subdirectories as deps
# Add our 'graph' module
if '\"//third_party/blink/renderer/modules/graph\"' not in content:
    # Find the deps section and add our module
    # Usually looks like: deps = [ ... \"//third_party/blink/renderer/modules/foo\", ... ]
    import re
    # Find last module dep and add after it
    pattern = r'(\"//third_party/blink/renderer/modules/\w+\",)'
    matches = list(re.finditer(pattern, content))
    if matches:
        last = matches[-1]
        insert = last.end()
        content = content[:insert] + '\n    \"//third_party/blink/renderer/modules/graph\",' + content[insert:]
        with open('$MODULES_GN', 'w') as f:
            f.write(content)
        print('  Added graph module to modules/BUILD.gn')
    else:
        print('  WARNING: Could not find module deps pattern')
else:
    print('  Already registered')
"
else
  echo "  Already registered"
fi

# Register IDL files in the generated_in_modules list
IDL_LIST="$CHROMIUM_SRC/third_party/blink/renderer/modules/modules_idl_files.gni"
if [ -f "$IDL_LIST" ] && ! grep -q "graph/" "$IDL_LIST"; then
  python3 -c "
with open('$IDL_LIST', 'r') as f:
    content = f.read()

idl_entries = '''
  \"//third_party/blink/renderer/modules/graph/navigator_graph.idl\",
  \"//third_party/blink/renderer/modules/graph/personal_graph.idl\",
  \"//third_party/blink/renderer/modules/graph/semantic_triple.idl\",
  \"//third_party/blink/renderer/modules/graph/signed_triple.idl\",
  \"//third_party/blink/renderer/modules/graph/shared_graph.idl\",'''

if 'graph/navigator_graph.idl' not in content:
    # Find the last .idl entry and add after it
    import re
    pattern = r'(\"//third_party/blink/renderer/modules/\S+\.idl\",)'
    matches = list(re.finditer(pattern, content))
    if matches:
        last = matches[-1]
        insert = last.end()
        content = content[:insert] + '\n' + idl_entries + content[insert:]
        with open('$IDL_LIST', 'w') as f:
            f.write(content)
        print('  Added IDL files to modules_idl_files.gni')
    else:
        print('  WARNING: Could not find IDL entries')
else:
    print('  Already added')
"
elif [ ! -f "$IDL_LIST" ]; then
  echo "  WARNING: modules_idl_files.gni not found — IDL registration may need manual patching"
fi

echo ""

# ------------------------------------------------------------------
# Step 4: Register Mojo graph mojom in mojo's BUILD.gn
# ------------------------------------------------------------------
echo "[4/6] Registering Mojo interfaces..."

MOJO_PARENT_GN="$CHROMIUM_SRC/mojo/public/mojom/BUILD.gn"
if [ -f "$MOJO_PARENT_GN" ] && ! grep -q "graph" "$MOJO_PARENT_GN"; then
  python3 -c "
with open('$MOJO_PARENT_GN', 'r') as f:
    content = f.read()

if '\"//mojo/public/mojom/graph\"' not in content:
    import re
    # Find a deps or public_deps list and add our module
    pattern = r'(\"//mojo/public/mojom/\w+\",)'
    matches = list(re.finditer(pattern, content))
    if matches:
        last = matches[-1]
        insert = last.end()
        content = content[:insert] + '\n    \"//mojo/public/mojom/graph\",' + content[insert:]
        with open('$MOJO_PARENT_GN', 'w') as f:
            f.write(content)
        print('  Registered graph mojom')
    else:
        print('  WARNING: Could not find mojom deps pattern — may need manual registration')
else:
    print('  Already registered')
"
else
  echo "  Already registered (or parent BUILD.gn not found — will work anyway via direct deps)"
fi

echo ""

# ------------------------------------------------------------------
# Step 5: Register browser interface binder for PersonalGraphService
# ------------------------------------------------------------------
echo "[5/6] Registering browser interface binder..."

# The browser process needs to know how to create PersonalGraphService
# when a renderer requests it via Mojo. This is done in
# content/browser/browser_interface_binders.cc

BINDERS_CC="$CHROMIUM_SRC/content/browser/browser_interface_binders.cc"
if [ -f "$BINDERS_CC" ] && ! grep -q "PersonalGraphService" "$BINDERS_CC"; then
  python3 -c "
import re
with open('$BINDERS_CC', 'r') as f:
    content = f.read()

# Add include
include_line = '#include \"content/browser/graph/graph_manager.h\"  // Living Web'
if include_line not in content:
    # Add after the last #include
    includes = list(re.finditer(r'^#include .+$', content, re.MULTILINE))
    if includes:
        last = includes[-1]
        pos = last.end()
        content = content[:pos] + '\n' + include_line + content[pos:]
    
# Add binder registration
# Look for the pattern where frame binders are registered
# Usually: map.Add<mojom::SomeInterface>(...)
binder_code = '''
  // Living Web: PersonalGraphService
  map.Add<graph::mojom::PersonalGraphService>(
      base::BindRepeating(&content::GraphManager::BindForFrame));'''

if 'PersonalGraphService' not in content:
    # Find a good insertion point — after another map.Add call
    pattern = r'(map\.Add<[^>]+>\([^)]+\);)'
    matches = list(re.finditer(pattern, content))
    if matches:
        last = matches[-1]
        pos = last.end()
        content = content[:pos] + '\n' + binder_code + content[pos:]
    
with open('$BINDERS_CC', 'w') as f:
    f.write(content)
print('  Registered PersonalGraphService binder')
"
else
  echo "  Already registered or file not yet available (will patch after gclient sync)"
fi

echo ""

# ------------------------------------------------------------------
# Step 6: Summary
# ------------------------------------------------------------------
echo "[6/6] Integration complete!"
echo ""
echo "Files copied:"
find "$CHROMIUM_SRC/mojo/public/mojom/graph" -type f 2>/dev/null | wc -l | xargs echo "  Mojo interfaces:"
find "$CHROMIUM_SRC/content/browser/graph" "$CHROMIUM_SRC/content/browser/did" \
     "$CHROMIUM_SRC/content/browser/graph_sync" "$CHROMIUM_SRC/content/browser/graph_governance" \
     -type f 2>/dev/null | wc -l | xargs echo "  Browser-process files:"
find "$CHROMIUM_SRC/third_party/blink/renderer/modules/graph" -type f 2>/dev/null | wc -l | xargs echo "  Blink renderer files:"
echo ""
echo "Next steps:"
echo "  1. cd $CHROMIUM_SRC"
echo "  2. gn gen out/LivingWeb --args='is_debug=false target_cpu=\"arm64\" is_component_build=true symbol_level=0 blink_symbol_level=0 enable_nacl=false'"
echo "  3. autoninja -C out/LivingWeb chrome"
echo ""
echo "Build will take 2-4 hours on first run. Use -j flag to control parallelism."
echo "With 14 CPUs and 48GB RAM: autoninja -C out/LivingWeb chrome"
