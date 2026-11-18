# bench/compare/

crypto-api-ng against other JavaScript hash libraries: node:crypto, hash-wasm, @noble/hashes, the js-sha* family (js-sha256, js-sha512, js-sha3, js-sha1, js-md5), hash.js, crypto-js and xxhash-wasm. Results: [`docs/benchmarks-compare.md`](../../docs/benchmarks-compare.md).

The libraries are pinned in `package.json` here, so the repository itself keeps no runtime dependencies. Install them with `--ignore-scripts`; none of them needs an install script.

```sh
scripts/fetch-upstream.sh
scripts/install-zig.sh && export PATH="$HOME/.local/bin:$PATH"
zig build js --release=small                      # the wasm crypto-api-ng imports (gitignored)
npm ci --prefix bench/compare --ignore-scripts

node bench/compare/run.mjs --quick                # one runtime, a few seconds per algorithm
node bench/compare/run-all.mjs --machine mypc     # node, bun and deno in turn, then the report
node bench/compare/report.mjs                     # bench/results/compare-*.json -> docs/benchmarks-compare.md
```

Run each runtime directly with `node bench/compare/run.mjs`, `bun bench/compare/run.mjs` or `deno run -A bench/compare/run.mjs`. On Windows the same commands work from PowerShell.

`run.mjs` options: `--quick` (1 KiB and 1 MiB, fewer samples), `--algorithms md5,sha256`, `--sizes 32,1024,65536,1048576` (the default), `--label name`, `--note "text shown with the results"`, `--out file.json`. `run-all.mjs` adds `--machine name` (used as the label prefix, default the host name) and `--runtimes node,bun,deno`, and passes everything else to each run.

## What is measured

One call that hashes a `Uint8Array` and returns the digest, for 15 algorithms (MD5, SHA-1, SHA-256, SHA-512, SHA3-256, Keccak-256, BLAKE2b-512, BLAKE2s-256, BLAKE3, RIPEMD-160, MD4, SM3, Whirlpool, CRC-32, xxHash64) at 32 B, 1 KiB, 64 KiB and 1 MiB. Each library is called the way its documentation shows for bytes; `libs.mjs` has the exact calls and the reasons. Before a cell is timed, every library's digest is compared with the others: a library that disagrees with the majority is not timed and is listed in the report, and crypto-api-ng disagreeing stops the run.

The `ng core` row is not a public API. It calls crypto-api-ng's WebAssembly exports directly (the `raw` contender of `bench/`), to show how much of the time is spent in the JavaScript around them.

Timing uses `bench/lib/stats.mjs`: libraries are sampled in round-robin order, and the report shows medians. Close other programs, keep the machine on mains power, and run more than once (`report.mjs` merges runs with the same label by the median).
