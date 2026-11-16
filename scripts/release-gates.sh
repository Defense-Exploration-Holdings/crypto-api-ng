#!/usr/bin/env bash
# Release checks: the full test matrix over every Zig optimize mode.
#
# For every Zig optimize mode this embeds the wasm built in that mode and runs
#   1. zig build check        (native Zig tests + Node tests against the wasm)
#   2. npm run test:parity    (original 286 tests + compat + differential fuzz)
#   3. npm run test:package   (bundles, npm pack, smoke imports, Chromium)
# and writes one log per step plus a summary table.
#
# Usage: scripts/release-gates.sh [--modes "debug safe fast small"] [--out DIR]
# Env:   FUZZ_ITERS (default 200; 100000 for a release), FUZZ_SEED
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
modes="debug safe fast small"
out="$root/release-gates-out"
while [ $# -gt 0 ]; do
  case "$1" in
    --modes) modes="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$out"
summary="$out/summary.tsv"
: > "$summary"

fail=0
run() { # run <mode> <step> <command...>
  local mode="$1" step="$2"; shift 2
  local log="$out/$mode-$step.log" t0 rc
  t0=$(date +%s)
  "$@" > "$log" 2>&1; rc=$?
  printf '%s\t%s\t%s\t%ss\n' "$mode" "$step" "$([ $rc -eq 0 ] && echo PASS || echo "FAIL($rc)")" "$(( $(date +%s) - t0 ))" | tee -a "$summary"
  [ $rc -eq 0 ] || fail=1
}

for mode in $modes; do
  flag=()
  [ "$mode" = debug ] || flag=("--release=$mode")
  run "$mode" embed zig build js "${flag[@]}"
  run "$mode" check zig build check "${flag[@]}"
  run "$mode" parity npm run test:parity
  # The package size budget is for the shipped wasm (--release=small, see publish.yml); the other modes are larger.
  budget=0; case "$mode" in small) ;; *) budget=1 ;; esac
  run "$mode" package env CRYPTO_API_SKIP_SIZE_BUDGET=$budget npm run test:package
done

echo; echo "summary: $summary"
exit $fail
