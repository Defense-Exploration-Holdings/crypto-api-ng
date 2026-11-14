#!/usr/bin/env bash
# Puts the upstream crypto-api 0.8.5 checkout (the behavioral oracle) at crypto-api/.
#
# Pinned to the commit below ("Release 0.8.5", identical to the npm tarball of
# crypto-api@0.8.5). Safe to run repeatedly. It never touches anything outside crypto-api/.
# The parity tests, scripts/vendor-legacy.mjs, scripts/size-report.mjs and bench/ need it.
set -euo pipefail

UPSTREAM_URL="https://github.com/nf404/crypto-api.git"
UPSTREAM_SHA="d39f6cede07dcf55cbf884eb4e0fa27f6d1466eb"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$root/crypto-api"

if [ -d "$dir/.git" ] || [ -f "$dir/.git" ]; then
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)" = "$UPSTREAM_SHA" ]; then
    echo "crypto-api/ is already at ${UPSTREAM_SHA:0:7}"
    exit 0
  fi
elif [ -d "$dir" ] && [ -n "$(ls -A "$dir")" ]; then
  echo "error: $dir exists, is not empty and is not a git checkout; refusing to touch it" >&2
  exit 1
fi

mkdir -p "$dir"
if [ ! -e "$dir/.git" ]; then
  git -C "$dir" init -q
  git -C "$dir" remote add origin "$UPSTREAM_URL"
fi
git -C "$dir" fetch -q --depth 1 origin "$UPSTREAM_SHA"
git -C "$dir" checkout -q --detach "$UPSTREAM_SHA"
echo "crypto-api/ is now at ${UPSTREAM_SHA:0:7}"
