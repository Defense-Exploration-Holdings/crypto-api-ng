# Contributing

## Setup

You need Zig 0.17.1 (pinned in `.zig-version`; `scripts/install-zig.sh` installs it from a wheel whose hash is pinned in `scripts/zig-requirements.txt`; update both files together) and Node.js 22 or newer (`.nvmrc`). Zig 0.17 differs from most tutorials: the optimize modes are `debug|safe|fast|small`, and `std.Io` and `std.process.Init` replace the older IO APIs. When in doubt, read the toolchain's own `lib/std`.

```sh
npm ci
scripts/fetch-upstream.sh         # checks out crypto-api 0.8.5 into crypto-api/, the reference for parity tests
zig build check                   # Zig tests, then Node tests against the built WebAssembly
zig build check --release=small   # the same in the shipped mode
```

Other commands:

```sh
zig build wasm --release=small    # zig-out/wasm/crypto-api.wasm
zig build families                # one module per algorithm family
zig build js                      # embed the modules for the JavaScript facades (check does this)
npm run test:parity               # the original's tests and the differential fuzzer (needs zig build js and crypto-api/)
npm run build:package             # ES5 bundles and example vectors in packages/crypto-api
npm run test:package              # bundles, tarball contents, smoke imports, Chromium (needs playwright)
npm run pack -- --name <name>     # stage and `npm pack`; the package name is configurable on purpose
```

Run `zig build check` in debug and with `--release=small` before sending a change. Do not commit `zig-out/` or `.zig-cache/`.

## Ground rules for v1

Version 1 behaves exactly like `crypto-api` 0.8.5, bugs included. Do not improve outputs while porting; fixes and API changes belong to version 2. If you touch anything under `packages/crypto-api/`, keep `npm run test:parity` green. Hand-written files there start with `// crypto-api-ng:facade`; the rest are vendored from the original by `scripts/vendor-legacy.mjs`. The package name is configurable at pack time (`npm run pack -- --name <name>` replaces `crypto-api-ng` in the staged README and examples), so keep the README and examples using the committed name consistently.

## Adding or changing an algorithm

MD5 is the template; copy its files (`src/hash/md5.zig`, `src/wasm/md.zig`, `packages/crypto-api/src/hasher/md5.mjs`, `test/md5.test.js`) and change what the algorithm needs.

- `src/hash/<algo>.zig`: the core. Target-agnostic, no wasm or OS code, with `test` blocks. Re-export it from `src/root.zig`.
- `src/wasm/<family>.zig`: the wasm exports for the algorithm family (the only files with `export fn`, besides `src/wasm.zig`). Add new families to `families` in `build.zig`.
- `packages/crypto-api/src/hasher/<algo>.mjs`: the facade. It extends the verbatim 0.8.5 class and overrides only `process()` and `finalize()`; everything else, including `this.state`, stays the original's. It falls back to the original code for any input or option the wasm code does not model exactly.
- `test/<algo>.test.js` and `test/vectors/`: differential tests against the original class.
- [docs/abi.md](docs/abi.md): calling conventions between JavaScript and WebAssembly.
- [docs/test-harness.md](docs/test-harness.md): the parity tests; new algorithms and options are registered in `test/harness/catalog.mjs`.

## Benchmarks

`bench/` has the suite and [docs/benchmarks.md](docs/benchmarks.md) the results. See `bench/README.md` for how to run it.

## Release checks

`scripts/release-gates.sh` runs the whole matrix (check, parity and package tests) in all four optimize modes. Use `FUZZ_ITERS=100000` for release-volume fuzzing. The release-gates workflow runs the same on GitHub, plus a smoke test on Node 18, 20, 22 and 24, Bun and Deno with and without WebAssembly (`test/runtimes/smoke.mjs`), and is started manually or by a `v*` tag.

## Licensing

Contributions are accepted under the MIT license of the project (see [LICENSE](LICENSE)). Test vectors from standards (NIST, RFCs) can be reused freely; vectors copied from the original's tests fall under the original's license, which the repository already carries.
