#!/bin/bash
# Run Living Web E2E tests on the Ubuntu machine where the Chromium binary lives.
# Usage: ./run.sh [playwright args...]
#
# Environment:
#   CHROME_PATH  — path to the Living Web chrome binary
#                  (default: ~/chromium/src/out/LivingWeb/chrome)

set -euo pipefail

export CHROME_PATH="${CHROME_PATH:-$HOME/chromium/src/out/LivingWeb/chrome}"

if [ ! -f "$CHROME_PATH" ]; then
  echo "ERROR: Chrome binary not found at $CHROME_PATH"
  echo "Set CHROME_PATH or build the Living Web Chromium first."
  exit 1
fi

cd "$(dirname "$0")"

# Install deps if needed
if [ ! -d node_modules ]; then
  npm install
fi

npx playwright test "$@"
