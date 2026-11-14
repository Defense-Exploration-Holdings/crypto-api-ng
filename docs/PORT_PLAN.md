# crypto-api → Zig/wasm port plan

Status: draft for review · Written 2026-11-14 · Source of truth for v1 work packages

This document inventories the original [`crypto-api`](https://github.com/nf404/crypto-api) (vendored as the `crypto-api/` submodule at `d39f6ce`, "Release 0.8.5", identical to the npm tarball of `crypto-api@0.8.5`), decides what is ported to Zig, what stays JavaScript and what is dropped, and breaks the v1 port into work packages that two sessions can run in parallel.

Release goals, as set by the maintainers:

- **v1 (1.0.0)**: a faithful port. Same public API, same import paths, same outputs, same `getState()` JSON, for every input the original accepts. Bugs are kept. Faster.
- **v2 (2.0.0)**: fix the known issues listed in section 7 and add modern crypto APIs (section 8).

Repo layout assumed here is the one from the scaffold PR (#1): Zig 0.17.1 (`.zig-version`), Node 22, `build.zig` at the root, Zig sources in `src/` (`src/root.zig` library root for native tests, `src/wasm.zig` is the only file with `export fn`), JS loader in `js/` (`load()` async, `loadSync(bytes)` sync, `zig build js` writes `js/generated/wasm-bytes.js`), ABI notes in `docs/abi.md`, `zig build check` runs everything.

---

## 1. Findings that shape the plan

1. **The published npm package has no working entry point.** `package.json` says `"main": "index"`, but `index.js` is not in the 0.8.5 (or 0.8.3, 0.8.2) tarball, so `require('crypto-api')` throws `MODULE_NOT_FOUND`. Users of 0.8.x can only use it through a bundler with deep imports such as `crypto-api/src/hasher/sha256` (extensionless `.mjs` imports, which Node's native ESM also rejects), or through the CDN global build `CryptoApi` from `nf404.github.io/crypto-api/crypto-api.min.js`. Users still on 0.7.x (`main: lib/crypto-api.js`, API `CryptoApi.hash(...).stringify('hex')`) have a different API, which 0.8.0 broke.
   - Consequence: v1 must keep the deep `src/...` paths working above all else. Making `main` work is a repair (nothing can depend on it being broken), so v1 does it.
2. **The data model is the "binary string"**: every input and output is a JS string whose code units are bytes. `update()` does not encode; only `CryptoApi.hash()`/`hmac()` call `fromUtf`. Calling `update()` with a string containing code units above 0xFF (for example Cyrillic text, which the README's ES5 example invites) yields deterministic but algorithm-specific garbage, neither UTF-8 nor Latin-1. Verified: `sha256.update('Привет')` matches neither. Users may have stored such hashes.
3. **Non-string input is silently coerced.** `update(new Uint8Array([1,2]))` hashes the string `"1,2"` while adding 2 to `state.length`.
4. **Options are open-ended.** `rounds` and `length` accept any value. Out-of-spec values produce garbage (SHA-256 `rounds: 80` runs with undefined constants, which become 0), throw (Snefru `rounds: 9` → `TypeError`), or hang (Snefru `length: 512` makes the block size 0 and `process()` loops forever). No test in the original suite passes any option.
5. **The message length field is 32-bit.** `addLengthBits()` uses `>>` on the byte count, so any message of 2^31 bytes (2 GiB) or more gets a wrong length field and a wrong hash. Reachable when streaming large files through `update()` in chunks.
6. **`getState()`/`setState()` are public and used for resumable hashing** (the `hasher-file` example calls `getState()`, `finalize()`, then `setState()` per 4 KiB slice). The state is a plain JSON object: `{message, length, hash[, checksum]}`. Number representation leaks: HAS-160 and RIPEMD keep their IV words unsigned (`4023233417`) until the first block, then signed int32; MD2 starts with arrays of `null`. Persisted state from 0.8.5 must load in v1, and v1 must emit the same JSON.
7. **HMAC is generic over any hasher object** (`update`/`finalize`/`reset`/`blockSizeInBytes`). It mutates the hasher it is given, and a second `finalize()` returns a wrong value because the inner pad is not re-applied. The base classes `Hasher`, `Hasher8`, `Hasher32be`, `Hasher32le` are importable, so users can write their own hashers and pass them to `Hmac`.
8. **SM3 is not reachable through `CryptoApi.getHasher('sm3')`** (it returns `undefined`), only via `import Sm3 from 'crypto-api/src/hasher/sm3'`. Unknown names return `undefined`, and `CryptoApi.hash()` then throws `TypeError`.
9. **Synchronous API.** Nothing is async (`new Sha256(); update(); finalize()`), so the wasm must be instantiated synchronously. Chrome allows sync `new WebAssembly.Module()` on the main thread up to 8 MB since 2023 (previously 4 KB), so embedded bytes plus `loadSync` work everywhere WebAssembly is allowed. It is not allowed under a CSP without `'wasm-unsafe-eval'`, in Cloudflare Workers (no runtime compile from bytes), in IE11, and in some embedded JS engines. v1 must keep working there.
10. **Baseline reproduced**: the original suite is 286 mocha tests, 99.8% line coverage, and passes on Node 22 after `npm install --legacy-peer-deps` with chai pinned to 4.2.0 (chai 4.5's exports map breaks `chai/register-assert`): `npx nyc mocha --recursive test/test.mjs` → 286 passing. This is the oracle for v1.
11. The project brief mentions public, private and original checkouts in one repo. Today this repo holds only the original as a submodule plus the scaffold; the public repo (`Defense-Exploration-Holdings/crypto-api-ng`) is not vendored here. Nothing in this plan depends on it.

---

## 2. Inventory of the original public surface

### 2.1 Hashers (12 classes, 23 named variants)

| Class (`src/hasher/…`) | Base | Block | Options (defaults) | `getHasher` names | Original tests | State fields |
|---|---|---|---|---|---|---|
| `Has160` (`has160.mjs`) | 32le | 64 | `rounds` (80) | `has160` | 7 vectors + state | message, length, hash[5] (IV unsigned) |
| `Md2` (`md2.mjs`) | 8 | 16 | `rounds` (18) | `md2` | 7 + state | message, length, hash[48], checksum[16] (start as `null`) |
| `Md4` (`md4.mjs`) | 32le | 64 | none | `md4` | 7 + state | message, length, hash[4] |
| `Md5` (`md5.mjs`) | 32le | 64 | none | `md5` | 7 + state | message, length, hash[4] |
| `Ripemd` (`ripemd.mjs`) | 32le | 64 | `length` (160: 128/160/256/320) | `ripemd`, `ripemd128`, `ripemd160`, `ripemd256`, `ripemd320` | 4×(8 + state) | hash[4/5/8/10] (IV unsigned); `processBlock` is reassigned per length in `reset()` |
| `Sha0` (`sha0.mjs`) | 32be | 64 | `rounds` (80) | `sha0` | 8 + state | hash[5] |
| `Sha1` (`sha1.mjs`) | 32be | 64 | `rounds` (80) | `sha1` | 9 + state | hash[5] |
| `Sha256` (`sha256.mjs`) | 32be | 64 | `length` (256: 224), `rounds` (64) | `sha224`, `sha256` | 2×(5 + state) | hash[8] |
| `Sha512` (`sha512.mjs`) | 32be | 128 | `length` (512: 384, any t), `rounds` (160, counted in 32-bit half-steps) | `sha384`, `sha512`, `sha512/224`, `sha512/256` | 4×(5 + state) | hash[16] (hi/lo int32 pairs) |
| `Sm3` (`sm3.mjs`) | 32be | 64 | `length` (256), `rounds` (64) | none (bug) | 6 + state | hash[8] |
| `Snefru` (`snefru.mjs`) | 32be | 48 / 32 | `length` (128: 256), `rounds` (8: 2, 4) | `snefru`, `snefru128`, `snefru128/8`, `snefru256`, `snefru256/8`, `snefru128/2`, `snefru256/4` | 4×(12 + state) | hash[4/8]; S-boxes generated at load from the RAND table |
| `Whirlpool` (`whirlpool.mjs`) | 32be | 64 | `type` ('': '0', 't'; numeric `0` is falsy and silently gives plain Whirlpool), `rounds` (10) | `whirlpool`, `whirlpool-0`, `whirlpool-t` | 12 + 2×(8 + state) | hash[16]; tables computed at load |

Every hasher exposes: `constructor(options)`, `reset()`, `update(binaryString)`, `finalize() → binaryString`, `getState()`, `setState(state)`, and the properties `options` (the caller's object, mutated with defaults), `state`, `unitSize`, `unitOrder`, `blockSize`, `blockSizeInBytes`. Protected methods `process()`, `processBlock()`, `getStateHash()`, `addPadding*()`, `addLengthBits()` are reachable by subclasses.

### 2.2 MAC

- `Hmac` (`src/mac/hmac.mjs`): `new Hmac(key, hasher)`, `update(binaryString)`, `finalize()`. Tested with HAS-160, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (7 vectors each, RFC 2202/4231 style, 49 total).

### 2.3 Encoders and tools

- `fromUtf(string)` (UTF-16 → UTF-8 binary string; lone surrogates produce invalid sequences), `fromArrayBuffer(buffer)` (also accepts plain arrays and typed arrays), `toHex(binary)`, `toBase64(binary)`. 24 tests.
- `src/tools/tools.mjs`: `rotateLeft`, `rotateRight`, `rotateRight64hi`, `rotateRight64lo`. Exported module, no tests of its own.

### 2.4 Facade (`src/crypto-api.mjs`, `src/index.mjs`, CDN global `CryptoApi`)

- Singleton object: `encoder.{fromUtf, fromArrayBuffer, toHex, toBase64}`, `getHasher(name, options)`, `hash(name, utfMessage, options) → hex`, `getHmac(binaryKey, hasher)`, `hmac(utfKey, utfMessage, hasher) → hex`. No tests in the original suite.

### 2.5 Build, docs, examples

- webpack 4 + babel 7 + uglify (ES5 global build), esdoc docs published to GitHub Pages, Travis CI with coveralls/codacy/codeclimate, examples (`hasher-basic`, `hasher-file`, `benchmark`, `benchmark-other`, `unit-tests`) that load mocha and comparison libraries from rawgit, which is shut down.

---

## 3. Decisions per item

The guiding rule for v1: **wasm runs the standard envelope, the original JS runs everything else.** Each hasher instance has an engine: the Zig/wasm engine for inputs and options inside the envelope below, and the original JS implementation (vendored unmodified) for anything outside it. Outputs are bit-identical by construction in both cases, because anything the wasm path does not cover is computed by the code that defined the behavior.

### 3.1 Port to Zig → wasm

| Item | Zig work | Envelope served by wasm |
|---|---|---|
| MD4, MD5 | compression, padding, 32-bit length field | always (no options) |
| HAS-160 | compression with `rounds` | rounds integer 1–80 |
| RIPEMD-128/160/256/320 | four compressions | length ∈ {128,160,256,320} |
| SHA-0, SHA-1 | compression with `rounds` | rounds 1–80 |
| SHA-224/256 | compression with `rounds`, output truncation | length ∈ {224,256}, rounds 1–64 |
| SHA-384/512, SHA-512/224, SHA-512/256 | native u64 compression; `rounds` mapped as ceil(rounds/2) steps; fixed IVs for /224 and /256 | length ∈ {224,256,384,512}, rounds 1–160 |
| SM3 | compression with `rounds` | length 256, rounds 1–64 |
| MD2 | byte-oriented compression, checksum, `rounds` | rounds 1–255 (no table overrun is possible) |
| Snefru 128/256 | S-boxes generated at **comptime** from the RAND table, exactly as `generateSbox()` does | length ∈ {128,256}, rounds 1–8 |
| Whirlpool, -0, -T | tables generated at comptime (keep only C[0] per variant and rotate, to stay small) | type ∈ {'', '0', 't'} (and `0`, which maps to plain Whirlpool exactly as the original does), rounds 1–10 |
| Length field | emulate the original exactly: `ToInt32(byteCount)` shifted as in `addLengthBits()` | always (bug kept in v1) |

Implementation notes for every port:

- State is a plain `extern struct` with a documented layout (`hash` words, buffered bytes, buffered length, total length as u64, params). JS owns a copy of it (see 3.3), so wasm is stateless between calls.
- Constants are written as literals and cross-checked in Zig tests against tables generated by running the original JS (MD5's `T` uses `Math.sin`, so no float math in Zig).
- Zig's `std.crypto` (MD5, SHA-1, SHA-2) is a second oracle in the Zig unit tests for default parameters. It is not used as the implementation, because it has no `rounds` parameter and does not keep the 32-bit length bug.

### 3.2 Stays JavaScript

| Item | Why |
|---|---|
| `Hasher`, `Hasher8`, `Hasher32be`, `Hasher32le` base classes (verbatim) | They are the extension API for user-defined hashers, and `instanceof` checks must keep working. |
| `Hmac` (verbatim) | It is generic over any hasher, including user-written ones. With a wasm-backed hasher the per-call cost is a few JS calls. A wasm HMAC fast path can come in v1.x after benchmarks. |
| Encoders `fromUtf`, `fromArrayBuffer`, `toHex`, `toBase64` (verbatim) | They work on JS strings. Crossing into wasm costs more than it saves for hash-sized data, and their quirks (for example `toHex('Ā') === '100'`) must stay. |
| `tools.mjs` rotate helpers (verbatim) | Public module, used by the legacy engine. |
| `CryptoApi` facade, `getHasher` table, `hash`, `getHmac`, `hmac` (verbatim, imports repointed) | Pure dispatch. |
| **Façade class per hasher** (new) | Same name, same constructor, same methods and properties, same option normalization (including mutating the caller's `options`). Chooses the engine, moves bytes, maps state. |
| **Legacy engines** (verbatim copies of the 12 hasher files, import specifiers given explicit `.mjs`) | Fallback where wasm is unavailable, and outside the envelope. Also the in-package oracle. |
| Loader (`js/`, from the scaffold) | `loadSync()` of embedded bytes, lazy at first construction rather than at import. |

### 3.3 How the façade works (the template WP-B establishes)

- **Engine choice at construction**: wasm if (a) WebAssembly compiled successfully (lazily, once; any failure, such as CSP or Workers, is cached and means legacy), (b) options are inside the envelope (3.1), (c) the instance's class does not override any of `process`, `processBlock`, `finalize`, `getStateHash`, `addLengthBits`, `addPadding*` relative to the façade prototype. Point (c) keeps user subclasses that customize internals exactly as before.
- **Demotion mid-stream**: an instance switches permanently to the legacy engine, carrying its state across through the shared `getState()` shape, when `update()` receives a non-string, or a string with any code unit above 0xFF (detected in the same loop that copies bytes into wasm memory), or when user code reads or writes `.state` (a getter/setter that hands over the live legacy object, so direct mutation keeps working).
- **State lives in JS**: each instance holds its state struct in a small `Uint8Array`. A call copies it into a fixed scratch region in wasm memory, streams input into a fixed scratch buffer in chunks (for example 64 KiB), and copies the state back. wasm memory never grows, nothing leaks when hashers are dropped (no `FinalizationRegistry` needed), and `getState()`/`setState()` are a struct ↔ JSON mapping. An optional optimization skips the copy-in when the same instance used the scratch last.
- **`getState()`** returns exactly the original JSON: `message` as a binary string of the buffered bytes, `length` as a Number, `hash` as int32 Numbers, except pristine IVs, which are emitted as the original literal arrays (unsigned for HAS-160/RIPEMD, `null`-filled for MD2). **`setState()`** accepts any object the original accepted. Objects the struct cannot represent (wide characters in `message`, non-number words) demote to legacy.
- **Output**: `finalize()` returns a binary string built with `String.fromCharCode` over the digest bytes.

### 3.4 Dropped or replaced

| Item | Replacement |
|---|---|
| webpack 4, babel 7, uglify | esbuild (or Zig + a small script) producing: `src/**/*.mjs` (old paths, now with explicit extensions so Node ESM works too), `index.js` CJS entry (repairs `main`), `crypto-api.min.js` global `CryptoApi` build at ES5 syntax level |
| esdoc and the GitHub Pages docs | README API section in v1; generated docs site in v2 |
| Travis, coveralls, codacy, codeclimate | GitHub Actions from the scaffold |
| rawgit-based examples | Examples rebuilt against local files; `benchmark*` replaced by `bench/` (section 6) |

### 3.5 Intentional v1 divergences (complete list)

1. Configurations where the original hangs forever (Snefru `length ≥ 512`, block size ≤ 0) throw `RangeError` instead.
2. `setState(obj)` no longer keeps a live reference to `obj` (the original mutated the caller's object as hashing continued). Reading `.state` afterwards still returns a live object (see demotion above).
3. `main`/`index.js` now exists.

Everything else, including the wide-character garbage, the 2 GiB length bug, HMAC reuse behavior and the `getHasher('sm3')` gap, is kept in v1 and fixed in v2.

---

## 4. Package layout for v1

```
packages/crypto-api/            published npm package (`crypto-api` if transferred, else `crypto-api-ng`; see section 9)
  package.json                  version 1.0.0, main: index.js, module: src/index.mjs, no "exports" map in v1
  index.js, index.min.js        CJS entry (repaired main)
  crypto-api.min.js             browser global build (CDN replacement)
  src/crypto-api.mjs, src/index.mjs
  src/hasher/<algo>.mjs         façade classes, same names and default exports as 0.8.5
  src/hasher/hasher*.mjs        base classes, verbatim
  src/mac/hmac.mjs              verbatim
  src/encoder/*.mjs             verbatim
  src/tools/tools.mjs           verbatim
  legacy/hasher/<algo>.mjs      verbatim engines (generated by scripts/vendor-legacy.mjs)
  wasm/<family>.js              embedded wasm bytes (generated)
src/hash/<algo>.zig             Zig cores (target-agnostic, with test blocks)
src/wasm/<family>.zig           per-family wasm roots (see below)
test/vectors/<algo>.json        vectors shared by Zig and JS
test/compat/                    differential tests against the crypto-api/ submodule
test/legacy-suite/              the original 286 tests, run against packages/crypto-api
bench/                          benchmarks (section 6)
```

No `"exports"` map in v1, because it would block deep paths that bundlers resolve today (extensionless `crypto-api/src/hasher/sha256`).

**One wasm module per family**: md (MD2/MD4/MD5), sha1 (SHA-0/1), sha256, sha512, sm3, ripemd, has160, snefru, whirlpool. A user who deep-imports only MD5 then pays only for the MD5 module plus legacy MD5 (a few KB), rather than the whole library. This deviates from the scaffold's single `crypto-api.wasm`; WP-B measures both and decides. Each family root is a few lines in `src/wasm/`, and `build.zig` iterates over a list, so adding a family is a one-line append.

---

## 5. v1 work packages

Each package is sized for one session, owns its own files, and lists the tests it must leave green. Shared files (`build.zig` family list, `src/root.zig` imports, the façade registry) take one-line appends only, so parallel PRs merge cleanly. Every PR runs `zig build check` plus the package's own commands.

### Schedule, two sessions at a time

| Round | Session A | Session B |
|---|---|---|
| 1 | **WP-A** compat harness and vectors | **WP-B** MD5 end to end (the template) |
| 2 | **WP-C** 32-bit little-endian family | **WP-D** SHA-1 family, SHA-256, SM3 |
| 3 | **WP-E** SHA-512 family | **WP-F** packaging, facade, builds |
| 4 | **WP-G** MD2 and Whirlpool | **WP-H** Snefru |
| 5 | **WP-I** release gates | **WP-J** benchmark harness |

WP-A and WP-B start together; WP-B can test against hand-written vectors until WP-A's harness lands. Rounds 2–4 depend only on WP-B's pattern. WP-F can start in round 2 if a slot frees up.

### WP-A: compat harness and vectors

- `scripts/vendor-legacy.mjs`: copy `crypto-api/src` into `packages/crypto-api/legacy/` and `src/` (verbatim files), rewriting only import specifiers to explicit `.mjs`. A test asserts the diff against the submodule contains nothing but specifier changes.
- Oracle loader: a zero-dependency Node module-resolution hook (`node:module` `register`) that resolves the submodule's extensionless imports, so tests can `import` the untouched original.
- `test/vectors/<algo>.json`: extracted from the original test files (all 262 hash/HMAC/encoder cases) plus official vectors (NIST CAVP SHA ShortMsg/LongMsg/Monte for SHA-1/2, RFC 1319/1320/1321, RFC 2202/4231 HMAC, ISO/IEC 10118-3 Whirlpool, RIPEMD and HAS-160 reference vectors, GB/T 32905 SM3).
- `test/compat/diff.test.js`: seeded differential fuzzer. For each algorithm and option grid (defaults, every listed length, rounds at 1, mid, max, and just outside the envelope), random messages at lengths 0–300 and at block boundaries (15/16/17, 55/56/57, 63/64/65, 111/112/113, 127/128/129), split across random `update()` calls. Compares `toHex(finalize())` and `JSON.stringify(getState())` after every call. Also wide-character strings, non-string inputs, `setState` of legacy-produced JSON, and HMAC with every hasher. `FUZZ_ITERS` env var (default 200 per cell in CI, 100k for release).
- `test/legacy-suite/`: run the original mocha files unchanged against `packages/crypto-api` (import paths remapped by the same hook). Target: 286 passing.
- Tests to run: `node --test test/compat/`, the legacy suite command, `zig build check`.

### WP-B: MD5 end to end (template for every later package)

- `src/hash/md5.zig`: state struct, init, update, final, 32-bit length emulation, `test` blocks against vectors and `std.crypto.hash.Md5`.
- `src/wasm/md.zig`: exports per the ABI shape (`md5_state_size`, `md5_init`, `md5_update`, `md5_final`, plus scratch region address and size). Amend `docs/abi.md` with the "state copied in and out, no allocation per hasher" convention.
- `packages/crypto-api/src/hasher/md5.mjs`: the façade with engine choice, demotion, state mapping, lazy `loadSync`.
- `docs/porting-guide.md`: the recipe for every later package, including the envelope table entry and how to map state JSON.
- Measure: one module vs per-family modules (bytes, compile time), `--release=fast` vs `small`, and the copy-in skip. Record the decision in `docs/abi.md`.
- Tests: MD5 vectors in Zig and JS, the MD5 and HMAC-MD5 parts of the legacy suite, the MD5 cells of the differential fuzzer.

### WP-C: 32-bit little-endian family (MD4, HAS-160, RIPEMD-128/160/256/320)

- HAS-160 `rounds`; RIPEMD's four block functions and its pristine-IV-unsigned JSON quirk.
- Tests: `has160Test`, `md4Test`, `ripemd{128,160,256,320}Test`, `hmac-has160Test`, fuzz cells.

### WP-D: SHA-0, SHA-1, SHA-224/256, SM3

- `rounds` for all four, `length` truncation for SHA-256, SM3's `length`.
- Tests: `sha0Test`, `sha1Test`, `sha224Test`, `sha256Test`, `sm3Test`, `hmac-sha{1,224,256}Test`, NIST CAVP SHA-1/SHA-256, fuzz cells.

### WP-E: SHA-384/512, SHA-512/224, SHA-512/256

- Native u64 arithmetic in Zig; state JSON emitted as hi/lo int32 pairs; `rounds` half-step mapping; fixed IVs for /224 and /256 (any other t goes to legacy, which derives its own IV).
- Tests: `sha384Test`, `sha512Test`, `sha512_224Test`, `sha512_256Test`, `hmac-sha{384,512}Test`, NIST CAVP SHA-512 family, fuzz cells.

### WP-F: packaging, facade, builds

- `packages/crypto-api/package.json` (1.0.0, `main` repaired, no `exports` map), `src/crypto-api.mjs`/`src/index.mjs` repointed, the CJS `index.js`, the global `crypto-api.min.js` (ES5 syntax, legacy engine automatically where WebAssembly is missing), README (v1 compatibility statement, the divergence list from 3.5, migration from 0.7.x and 0.8.x), CHANGELOG, LICENSE with the original MIT notice (Copyright (c) 2015 nf404) kept.
- Rebuild `example/hasher-basic`, `hasher-file`, `unit-tests` against local files.
- Tests: facade tests (new; the original has none) for every `getHasher` name and alias, `hash`, `hmac`, `getHmac`; `npm pack` content check; import smoke tests for `require('…')`, `import … from '…/src/hasher/sha256.mjs'`, a bundler resolving the extensionless path, and the global build in Playwright Chromium.

### WP-G: MD2 and Whirlpool

- MD2: byte-oriented, `null`-initialized state JSON, checksum block.
- Whirlpool: three variants from comptime tables, `rounds`, `type` normalization copied from the original (`'0'` selects Whirlpool-0, numeric `0` falls through to plain Whirlpool).
- Tests: `md2Test`, `whirlpoolTest`, `whirlpool-0Test`, `whirlpool-tTest`, ISO vectors, fuzz cells.

### WP-H: Snefru

- Comptime S-box generation mirroring `getRandomDigit`/`getRandomNumber`/`generateSbox` (check the 16 generated tables against a dump from the original). Variable block size (`16 - words`), zero padding, the `RangeError` for block size ≤ 0 (divergence 1).
- Tests: `snefru128_2Test`, `snefru128_8Test`, `snefru256_4Test`, `snefru256_8Test`, fuzz cells.

### WP-I: release gates

- All 286 original tests pass against the package; differential fuzz at 100k iterations per cell with zero mismatches; official vectors pass.
- Environments: Node 18/20/22/24, Bun, Deno, Chromium, Firefox, WebKit (Playwright), a page with a CSP that forbids wasm (legacy fallback), a Worker, a Cloudflare-Workers-like `WebAssembly.Module` refusal (legacy fallback).
- Bundle-size report per deep import and for the full facade, minified and gzipped, compared with 0.8.5.
- `npm publish --dry-run`, provenance settings, tag `v1.0.0` (publishing itself waits for the maintainers).

### WP-J: benchmark harness

Builds section 6. Can start as soon as WP-B lands and grows as algorithms arrive.

---

## 6. Benchmark and scoring plan (after v1)

**Correctness score**, reported with every benchmark run:
- Original suite: 286/286.
- Differential fuzz: cases run, mismatches (must be 0), per algorithm.
- Official vectors: pass/total per algorithm.
- `getState()` JSON round trips identical to 0.8.5.

**Speed**, per algorithm and named variant:
- Throughput in MB/s at 0 B, 16 B, 64 B, 1 KiB, 64 KiB, 1 MiB and 16 MiB, single `update()` and streamed in 4 KiB chunks (the `hasher-file` pattern).
- Small-message ops/s for `CryptoApi.hash('md5', 'xxx')` style calls, HMAC ops/s, `getState()`/`setState()` cost.
- Cold start: time from `import` to first digest (includes wasm compile).
- Contenders: `crypto-api@0.8.5` (baseline), v1 through the public string API, v1 wasm core called directly with `Uint8Array` (the v2 ceiling), and as references `node:crypto`, WebCrypto `subtle.digest` (SHA family), `hash-wasm`, `@noble/hashes`, `crypto-js`, `js-sha256`/`jsSHA`.
- Environments: Node 22 and 24, Bun, Deno, Chromium, Firefox, WebKit via Playwright.

**Size**: wasm bytes per family, `--release=fast` vs `small`, package and per-import bundle size vs 0.8.5.

**Method**: `mitata` or `tinybench` in Node, the same harness bundled for browsers; warm-up, at least 10 samples, report median and p95; 5 runs per environment on a quiet machine with the CPU model recorded. Results go to `bench/results/<date>-<env>.json`, plus a generated markdown table and chart for the README and the outreach material ("v1 is N× faster than 0.8.5 for X at Y size").

---

## 7. v2: known issues to fix (breaking where noted)

1. 64-bit message length field (wrong hashes at 2 GiB and above). Changes outputs for such inputs only.
2. Bytes in, bytes out: `update(Uint8Array | ArrayBuffer | DataView | string)`, with strings UTF-8 encoded by default (as 0.7.x did); `digest()` returns `Uint8Array`; binary-string I/O kept behind explicit helpers. Breaking.
3. Strings with code units above 0xFF in `update()`: encode as UTF-8 or throw, never garbage. Breaking.
4. Reject non-string, non-binary inputs instead of hashing `"1,2"`.
5. Validate `rounds` and `length`; throw `RangeError` outside the supported set. Do not mutate the caller's `options`.
6. HMAC: does not mutate the hasher passed in, `reset()`, correct repeated `finalize()`, accepts bytes; `getHmac`/`hmac` take keys the same way.
7. Whirlpool `type: 0` should select Whirlpool-0. `getHasher`: add `sm3`, case-insensitive names, throw on unknown names; `hash()` with an `encoding` option.
8. `fromUtf`: replace lone surrogates with U+FFFD (matches `TextEncoder`).
9. Encoders: add `fromHex`, `fromBase64`, base64url, base32; `toHex` defined for bytes only.
10. Modern packaging: `exports` map with ESM and CJS, TypeScript types, tree-shakable entry points, a separate `crypto-api/wasm` entry for environments that need precompiled modules (Cloudflare Workers), async `ready()` for very large modules.
11. Mark broken algorithms (MD2, MD4, MD5, SHA-0, SHA-1, HAS-160, Snefru) as legacy in docs and types; keep them available.
12. Constant-time `equal(a, b)` helper for MAC verification.
13. `getState()` returns a versioned, compact state; still reads 0.8.5/v1 JSON.

## 8. v2: modern API candidates

Zig's `std.crypto` already implements most of these, which makes them cheap to expose and well tested. Each still needs vectors and differential tests against a second implementation.

| Priority | Area | Candidates |
|---|---|---|
| P0 | Hashes | SHA-3 224/256/384/512, SHAKE128/256, Keccak-256 (Ethereum), BLAKE2b/BLAKE2s, BLAKE3 |
| P0 | MAC and KDF | HMAC (fixed), HKDF (RFC 5869), PBKDF2 |
| P0 | Password hashing | Argon2id (RFC 9106), scrypt, bcrypt |
| P1 | AEAD | AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV or AEGIS |
| P1 | Signatures and key exchange | Ed25519, X25519, ECDSA P-256, secp256k1 (ECDSA and BIP-340 Schnorr) |
| P1 | Post-quantum | ML-KEM (FIPS 203) from `std.crypto`; ML-DSA (FIPS 204) if available in Zig 0.17, otherwise a port; hybrid X25519+ML-KEM |
| P2 | SP 800-185 | cSHAKE, KMAC, TupleHash |
| P2 | Other MACs | Poly1305, CMAC, keyed BLAKE2/BLAKE3, SipHash |
| P2 | Protocols | HPKE (RFC 9180) |
| P2 | Non-cryptographic | CRC32, xxHash/XXH3 (clearly labelled) |
| Infra | Randomness | `randomBytes()` sourced from `crypto.getRandomValues` on the host (wasm has no entropy) |

---

## 9. Decisions needed from the maintainers

1. **npm name for v1.** *Decided 2026-11-14: ask the original author for the `crypto-api` name, and prepare `crypto-api-ng` in parallel as the fallback name so v1 is not blocked (`crypto-api-ng` was unclaimed on npm on 2026-11-14; claim it before announcing). With the fallback, existing users switch with `"crypto-api": "npm:crypto-api-ng@^1"`.* The `crypto-api` name belongs to the original author. Options: ask to be added as maintainer or have it transferred (then existing users get 1.0.0 by a normal major upgrade); or publish under a new name with the identical layout, so existing users switch with zero code changes via an alias, `"crypto-api": "npm:<new-name>@^1"`. Recommendation: ask for the transfer now, and prepare the new name in parallel so v1 is not blocked.
2. **Version number of the faithful release**: 1.0.0 (recommended; deliberate opt-in) versus 0.8.6 (would reach every `^0.8.5` user automatically and silently, which is risky for a rewrite).
3. **2 GiB length bug in v1**: keep it (recommended, per the "identical in v1" rule) or fix it in v1 as a documented exception.
4. **Browser global build**: keep ES5 syntax for the CDN file (recommended, it is what the README's "ES5" section promises) or move to ES2015.
5. **License** for the new code and the copyright line, keeping the original MIT notice.

---

## Appendix: behaviors verified against the original (Node 22, 0.8.5 source)

| Probe | Result |
|---|---|
| `require('crypto-api')` from the 0.8.5, 0.8.3 and 0.8.2 tarballs | `MODULE_NOT_FOUND` (no `index.js` shipped) |
| `sha256.update('Привет')` equals UTF-8 or Latin-1 SHA-256 | neither |
| `sha256.update(new Uint8Array([1,2]))` | hashes the string `"1,2"` |
| SHA-256 `{rounds: 80}` | runs, returns a digest (constants past 64 become 0) |
| Snefru `{rounds: 9}` | `TypeError: Cannot read properties of undefined` |
| Whirlpool `{type: 0}` vs `{}` | identical (plain Whirlpool) |
| SHA-512 `{rounds: 159}` vs default | identical (half-step loop) |
| SHA-256 `{length: 160}` | 5-word digest with the SHA-256 IV |
| `getHasher('sm3')`, `getHasher('SHA256')` | `undefined` |
| `CryptoApi.hash('nope', 'x')` | `TypeError` |
| HMAC-MD5 `finalize()` twice | second value differs from the first, and only the first matches `node:crypto` |
| `new Hmac('key', md5)` | leaves `md5.state.length === 64` |
| `new Md2().getState().hash` | 48 × `null` |
| `new Has160().getState().hash` | unsigned IV words; signed after the first block |
| `state.length = 2**29 + 2**32` vs `2**29` before `finalize()` | identical digests (high bits dropped) |
| `new Sha256(o)` with `o = {}` | `o` becomes `{length: 256, rounds: 64}` |
| `fromUtf('a\ud800')` | `61f0908080` (invalid UTF-8) |
| `toHex('Ā')` | `'100'` |
| `new Ripemd()` | has an own `processBlock` property |
