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
npm run test:package              # bundles, tarball contents, TypeScript declarations, smoke imports, Chromium (needs playwright)
npm run test:runtimes             # the packed tarball installed and imported under Node, Bun and Deno (whichever are on PATH)
npm run pack -- --name <name>     # stage and `npm pack`; the package name is configurable on purpose
```

Run `zig build check` in debug and with `--release=small` before sending a change. Do not commit `zig-out/` or `.zig-cache/`.

## Ground rules for v1

Version 1 behaves exactly like `crypto-api` 0.8.5, bugs included. Do not improve outputs while porting; fixes and API changes belong to version 2. If you touch anything under `packages/crypto-api/`, keep `npm run test:parity` green. Hand-written files there start with `// crypto-api-ng:facade`; the rest are vendored from the original by `scripts/vendor-legacy.mjs`. The package name is configurable at pack time (`npm run pack -- --name <name>` replaces `crypto-api-ng` in the staged README and examples), so keep the README and examples using the committed name consistently.

## TypeScript declarations

The declarations are hand-written: `packages/crypto-api/types.d.ts` and `index.d.ts` for the `CryptoApi` object, and a `.d.mts` file next to each module under `src/`. When you add an algorithm or an option, update them and `docs/api.md`; `test/package/types.test.js` compiles sample programs against the packed package in a strict project and fails when a module has no declaration.

## Adding or changing an algorithm

MD5 is the template; copy its files (`src/hash/md5.zig`, `src/wasm/md.zig`, `packages/crypto-api/src/hasher/md5.mjs`, `test/md5.test.js`) and change what the algorithm needs.

- `src/hash/<algo>.zig`: the core. Target-agnostic, no wasm or OS code, with `test` blocks. Re-export it from `src/root.zig`.
- `src/wasm/<family>.zig`: the wasm exports for the algorithm family (the only files with `export fn`, besides `src/wasm.zig`). Add new families to `families` in `build.zig`.
- `packages/crypto-api/src/hasher/<algo>.mjs`: the facade. It extends the verbatim 0.8.5 class and overrides only `process()` and `finalize()`; everything else, including `this.state`, stays the original's. It falls back to the original code for any input or option the wasm code does not model exactly.
- `test/<algo>.test.js` and `test/vectors/`: differential tests against the original class.
- `packages/crypto-api/package.json`: the per-algorithm entry point (`exports` and `typesVersions`), plus `scripts/package-entries.mjs` and the README size table (`node scripts/size-report.mjs --write`). `test/package/exports.test.js` fails until they agree.
- [docs/abi.md](docs/abi.md): calling conventions between JavaScript and WebAssembly.
- [docs/test-harness.md](docs/test-harness.md): the parity tests; new algorithms and options are registered in `test/harness/catalog.mjs`.

## Benchmarks

`bench/` has the suite and [docs/benchmarks.md](docs/benchmarks.md) the results. See `bench/README.md` for how to run it.

## Release checks

`scripts/release-gates.sh` runs the whole matrix (check, parity and package tests) in all four optimize modes. Use `FUZZ_ITERS=100000` for release-volume fuzzing. The release-gates workflow runs the same on GitHub, plus a smoke test on Node 18, 20, 22 and 24, Bun and Deno with and without WebAssembly (`test/runtimes/smoke.mjs`), and is started manually or by a `v*` tag. Every pull request also runs `npm run test:runtimes` (the packed tarball installed into Node, Bun and Deno projects) on the oldest supported Bun and Deno and on the current releases.

## Pull requests

Pull requests are welcome on the GitHub repository. It is the published copy of the project's development repository, so a pull request is not merged there directly: the maintainers apply an accepted change upstream and credit the author, and it appears on GitHub with the next release. The pull request is then closed with a note pointing to that release.

## Licensing

Contributions are accepted under the MIT license of the project (see [LICENSE](LICENSE)). Test vectors from standards (NIST, RFCs) can be reused freely; vectors copied from the original's tests fall under the original's license, which the repository already carries.

## Publishing

Releases go to npm from GitHub Actions (`.github/workflows/publish.yml`) with npm trusted publishing, so no npm token exists. Set `version` in `packages/crypto-api/package.json`, add a `CHANGELOG.md` entry, merge, and push the matching tag (`1.2.3` -> `v1.2.3`; the tag must look like `v1.2.3` or `v1.2.3-rc.1`). The `build` job runs the shipped-mode checks, parity and package tests and packs the tarball with its SHA-256. The `publish` job, which alone holds the publish permission, verifies the tarball and publishes it, without checking out or building anything. A version with a pre-release part goes to the `next` dist-tag. A 1.0.x maintenance release, tagged on the `v1` branch, goes to `v1-latest`, so `latest` stays on the current line. Published versions cannot be changed, so a fix is always a new version.

Workflow actions are pinned to full commit hashes with the release in a trailing comment, and Dependabot proposes updates. The npm version in the `publish` job and the Playwright version in the `build` job are pinned by hand; keep them current.
