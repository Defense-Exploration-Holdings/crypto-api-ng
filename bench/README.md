# bench/

Reproducible benchmarks of v1 (`packages/crypto-api`) against the original crypto-api 0.8.5 (the `crypto-api/` submodule). Results and how to read them: [`docs/benchmarks.md`](../docs/benchmarks.md). Zero npm dependencies; Node 22 or Bun.

```sh
git submodule update --init crypto-api
scripts/install-zig.sh && export PATH="$HOME/.local/bin:$PATH"
zig build js --release=small                    # the wasm the facades import (gitignored)

node bench/run.mjs --quick                      # smoke test, a few minutes
node bench/run.mjs --full --label node22        # everything incl. 16 MiB and parity, ~20 min
bun  bench/run.mjs --full --label bun           # same suites under Bun
node bench/report.mjs                           # bench/results/*.json -> docs/benchmarks.md + chart
```

`run.mjs` options: `--suites throughput,construct,api,hmac,state,startup,sizes,parity` (default all), `--variants md5,sha256`, `--label`, `--out file.json`, `--quick`, `--full`. Run it on a quiet machine and keep the label per environment; `report.mjs` takes the median of medians when a label has several runs.

## What is measured

| Suite | What |
|---|---|
| `throughput` | `new` + `update` + `finalize` for each of the 24 named variants at 0 B, 16 B, 64 B, 1 KiB, 64 KiB, 1 MiB (16 MiB with `--full`), in one call and streamed in 4 KiB chunks |
| `construct` | `new Hasher(options)` |
| `api` | `CryptoApi.hash(name, message)` (getHasher, UTF encode, hex) |
| `hmac` | `new Hmac(key, hasher)` + `update` + `finalize`, 64 B and 1 KiB |
| `state` | `getState()` / `setState()` after 1 KiB |
| `startup` | fresh process: `import()` and first digest, 0.8.5 vs v1 alternating |
| `sizes` | wasm bytes per family (`small` and `fast`, gzip), unminified JS closure per deep import |
| `parity` | runs `test:legacy-suite` and `test:compat` and records the counts |

Contenders per cell: `orig` (0.8.5), `v1`, `raw` (v1's wasm called directly with a `Uint8Array`, the ceiling for a bytes API) and `node` (node:crypto, where OpenSSL has the algorithm). Each cell checks every contender's digest against 0.8.5 before timing; a mismatch aborts the run (v1) or drops the reference contender (raw, node).

## Files

- `lib/stats.mjs`: calibrated, interleaved sampling; median and p95.
- `lib/trees.mjs`: loads both implementations without any loader hook. 0.8.5 is the submodule copied to `bench/.cache` with only `.mjs` appended to relative imports (same rewrite as `scripts/vendor-legacy.mjs`), because Node's hook would add a per-import cost the original does not pay in a bundled app.
- `lib/contenders.mjs`, `lib/suites.mjs`: what is timed. `startup*.mjs`, `sizes.mjs`, `parity.mjs`: the other suites.
- `results/`: raw JSON per run (`<date>-<label>.json`). `chart.mjs`, `report.mjs`: output.
