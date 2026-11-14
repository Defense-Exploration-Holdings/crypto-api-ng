# v1 release gates (WP-I)

How to run the gates, what the last run showed, and what is still open. Spec: `docs/PORT_PLAN.md`, WP-I.

## Running them

```sh
scripts/install-zig.sh && npm ci && scripts/fetch-upstream.sh
scripts/release-gates.sh                      # debug, safe, fast, small: check + parity + package
FUZZ_ITERS=100000 FUZZ_ONLY=sha512 node --test test/compat/diff-hashers.test.js   # release-volume fuzz, one family
node test/runtimes/smoke.mjs                  # every published vector on this runtime (NO_WASM=1: legacy fallback)
node scripts/size-report.mjs                  # bundle sizes against 0.8.5
```

`.github/workflows/release-gates.yml` runs the same on GitHub (manual, or on a `v*` tag): all four optimize modes, the fuzz sharded per family, and the smoke test on Node 18/20/22/24, Bun and Deno, with and without WebAssembly. **That workflow has not run yet**; this document records only what was run locally.

`release-gates.sh` writes one log per step. The package size budget in `test/package/pack.test.js` is for the shipped wasm, so debug and safe builds skip that one assertion (`CRYPTO_API_SKIP_SIZE_BUDGET=1`); everything else in `test:package` runs in every mode.

## Results (integration branch, Node 22.23.4, Zig 0.17.1)

| Gate | Result |
|---|---|
| `zig build check` (Zig tests + Node tests) in debug, safe, fast, small | pass in all four (the debug run counted 1080 Node tests, 0 failed) |
| `npm run test:parity` (original 286 tests, compat, fuzz at 200 iterations) in all four modes | pass |
| `npm run test:package` (bundles vs original, tarball, smoke imports, Chromium served / no WebAssembly / CSP) | pass in fast and small; debug and safe pass except the size budget, now skipped for them |
| Differential fuzz, 100 000 iterations per cell, 12 families, seed 1, small wasm | 0 mismatches |
| HMAC, encoders and facade differential at 100 000 iterations | 0 mismatches |
| Smoke test on Node 22, 428 vectors, wasm on (11 modules instantiated) and with WebAssembly removed | pass |

## Not run here, still open

- Node 18/20/24, Bun and Deno: the local run was Node 22 only (the other runtimes could not be run in this sandbox). The workflow covers them.
- Firefox and WebKit: `test/package/browser.test.js` only drives Chromium, and only Chromium is installed here. A Worker page and a `WebAssembly.Module`-refusing (Workers-like) host are also not covered; the no-WebAssembly and CSP cases in Chromium are the nearest tests.
- `npm publish --dry-run`: `package.json` is `private: true` on purpose, so publish refuses; `npm pack` is covered by `test:package`. Provenance settings and the `v1.0.0` tag wait for the maintainers and the npm name decision.
- Fuzz seeds other than 1 and a second run on the fast build.

## Bundle size against 0.8.5 (esbuild, minified, gzip level 9)

The port ships the original JavaScript as the fallback engine plus the wasm bytes inline, so every import is larger. Throughput is for the benchmark thread to report.

| Import | 0.8.5 min | 0.8.5 gzip | port min | port gzip | gzip ratio |
|---|---:|---:|---:|---:|---:|
| Has160 | 3.8 KB | 1.2 KB | 10.4 KB | 4.5 KB | 3.66x |
| Md2 | 2.8 KB | 1.2 KB | 7.2 KB | 3.5 KB | 2.96x |
| Md4 | 4.2 KB | 1.1 KB | 14.3 KB | 5.7 KB | 5.20x |
| Md5 | 5.1 KB | 1.3 KB | 14.1 KB | 5.5 KB | 4.08x |
| Ripemd | 6.8 KB | 1.9 KB | 22.2 KB | 8.5 KB | 4.37x |
| Sha0 | 2.8 KB | 0.9 KB | 12.6 KB | 5.1 KB | 5.37x |
| Sha1 | 2.8 KB | 1.0 KB | 12.6 KB | 5.1 KB | 5.34x |
| Sha256 | 3.9 KB | 1.5 KB | 11.2 KB | 5.2 KB | 3.43x |
| Sha512 | 7.3 KB | 2.8 KB | 15.4 KB | 7.4 KB | 2.65x |
| Sm3 | 3.3 KB | 1.1 KB | 10.4 KB | 4.5 KB | 3.92x |
| Snefru | 58.5 KB | 28.0 KB | 87.9 KB | 48.8 KB | 1.74x |
| Whirlpool | 5.1 KB | 2.0 KB | 21.8 KB | 11.7 KB | 5.86x |
| Hmac | 0.5 KB | 0.3 KB | 0.5 KB | 0.3 KB | 1.00x |
| full facade (all hashers, HMAC, encoders) | 91.3 KB | 37.1 KB | 187.2 KB | 87.6 KB | 2.36x |

## Findings from assembling the stack

The ten pull requests are not a single stack, and merging them in order conflicts:

- #4 (MD5) is based on #1, not on #3, so it collides with #3 (harness): `packages/crypto-api/src/hasher/md5.mjs` (the harness vendored the original, #4 replaced it with the facade; the facade is right) and `test/vectors/md5.json`, `hmac-md5.json` (same cases, the harness version also carries `inputHex`/`keyHex`; the harness version is right).
- #5 vs #4: comment and doc text in `.github/workflows/ci.yml`, `docs/test-harness.md`, `test/compat/shape.test.js`.
- #7, #8, #9 vs the SHA PRs (#5, #6): the known `families` list in `build.zig`, the `src/root.zig` imports, plus `README.md` status line and `docs/porting-guide.md` (both sections kept). All are unions.
- #3's `docs/PORT_PLAN.md` comes from #2 and does not conflict.
