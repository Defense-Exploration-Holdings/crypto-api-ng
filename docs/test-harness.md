# v1 parity test harness

Goal: prove that the port is the same library as `crypto-api` 0.8.5 for every input
the original accepts: same digests, same thrown errors, same `getState()` JSON,
same object shape. The oracle is the **untouched original** (the `crypto-api/`
git submodule, `git submodule update --init crypto-api`). The implementation under
test (the **target**) is `packages/crypto-api`, or any other package root named by
`CRYPTO_API_TARGET`. Zero npm dependencies: only Node 22 (`node:test`, `node:crypto`).

```
zig build js                 # once: facades import the generated wasm modules (gitignored)
npm run test:parity          # everything below, ~20 s
npm run test:legacy-suite    # the original 286 mocha tests against the target
npm run test:compat          # differential fuzzing and the other compat tests
npm run vendor               # regenerate packages/crypto-api/{legacy,src} from the submodule
npm run vectors              # regenerate test/vectors from the original test files
```

## What runs

| Test | What it proves |
|---|---|
| `test/legacy-suite/run.mjs target` | The original `crypto-api/test/test.mjs`, unmodified, passes against the target: **286 tests**. Its `../src/...` imports are redirected to the target by a resolve hook, `node:test` stands in for mocha and `node:assert` for chai (the tests only use `assert.equal`). `run.mjs oracle` runs it against the original itself and must also give 286. |
| `compat/diff-hashers.test.js` | Seeded differential fuzzer, 12 hasher classes x 239 option cells (defaults, every documented `length`/`rounds`/`type`, values just outside the supported set, odd types such as `'7'`, `true`, `NaN`, `-1`, `1.5`). Each iteration runs one scenario on both implementations and compares every observable: return values, thrown error class and message, the caller's mutated `options` object, and `JSON.stringify(getState())` after every step. Scenarios: random bytes at block/padding boundaries and random lengths, split over 1-6 `update()` calls, `finalize()` (sometimes twice, or followed by more `update()`), `reset()` and a second message, plus 8% hostile inputs (strings with code units above 0xFF, `Uint8Array`, `ArrayBuffer`, numbers, `undefined`, `null`, plain arrays). Every scenario is then replayed with the state handed over mid-stream with `getState()` / `setState()` oracle -> target and target -> oracle. |
| `compat/harness-selftest.test.js` | Mutation test of the harness itself: 8 deliberately broken copies of the original (one constant, default, field or padding byte changed each) must all be rejected by the fuzzer, and one equivalent rewrite must be accepted. |
| `compat/vectors.test.js` | The 238 hash and HMAC vectors of the original suite (`test/vectors/*.json`) in one `update()`, byte by byte, and with a `getState()`/`setState()` round trip at every 7th offset. |
| `compat/openssl.test.js` | Independent oracle: `node:crypto` for MD5, SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256, RIPEMD-160 and SM3 (every block/padding boundary length plus random lengths, one million `a`), and `createHmac` for 8 of them with key lengths around the block size. |
| `compat/diff-mac-encoders-facade.test.js` | `Hmac` over every variant (including hostile keys and a user-written hasher), the four encoders with lone surrogates and code units above 0xFF, the rotate helpers, and the `CryptoApi` facade: every `getHasher` name with option variants, unknown names, `hash`, `hmac`, `getHmac`. |
| `compat/quirks.test.js` | The verified-behavior appendix of `PORT_PLAN.md` as 20 executable probes (pinned oracle answers, target must match), the 32-bit length field for all 24 variants at 17 lengths up to 2^53 (set through `state.length`, because 2 GiB inputs are impractical), and direct reads/writes of `.state`. |
| `compat/shape.test.js` | Class names, inheritance chains, prototype methods, instance properties, `instanceof` against the target's own base classes, and user subclasses overriding `processBlock`, `update`, `finalize`, `getStateHash`, `addLengthBits` behaving identically. |
| `compat/divergences.test.js` | The three intentional v1 divergences. The Snefru `length >= 512` hang is proved against the original in a child process with a timeout. The "target throws RangeError" half passes since the Snefru port (WP-H). |
| `compat/vendor.test.js` | Every file under `packages/crypto-api/{src,legacy}` equals the original with only relative import specifiers changed, and each import still resolves to the same module. `vendor-legacy.mjs --check` and `extract-vectors.mjs --check` show no drift. |

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `CRYPTO_API_TARGET` | `packages/crypto-api` | Package root under test (needs `src/` with the original layout). |
| `FUZZ_ITERS` | `200` | Iterations per option cell. Use `100000` for the release gate (WP-I). |
| `FUZZ_SEED` | `1` | Base seed. Every cell derives its own stream, so cells are independent and reproducible. |
| `FUZZ_ONLY` | none | Only run families whose id contains this text, e.g. `FUZZ_ONLY=md5`. |

A failing fuzz case prints the seed, the cell, the iteration, the options, the full
scenario as JSON and the first differing observation, for example
`step 4 (update) state: expected {...} actual {...}`. Replay it by re-running with the same
`FUZZ_SEED` and `FUZZ_ONLY`, or paste the scenario into `runScenario()` from
`test/harness/diff.mjs`.

## Conventions for porting threads

- **Facade marker.** A hand-written file under `packages/crypto-api/src/` must contain the line
  `// crypto-api-ng:facade`. `scripts/vendor-legacy.mjs` never overwrites such a file, and
  `vendor.test.js` skips it. Until a facade exists the file is a verbatim copy, so the target
  equals the oracle and every test passes trivially. That is intended: the harness is green on
  day one and each port has to keep it green.
- **Legacy engines** live in `packages/crypto-api/legacy/hasher/<algo>.mjs` and import the base
  classes and tools from the single copy in `src/`, so `instanceof Hasher32le` holds for facades
  that extend an engine.
- **Adding or changing an algorithm** means editing `test/harness/catalog.mjs` only: the family
  table (block size, length-field size), the option cells, the variants (and the `openssl` name if
  `node:crypto` implements it), the `getHasher` names. Every test iterates over the catalog.
  Keep new option values off the `HANGS` list, and probe them first with a timeout: some values
  make the original loop forever.
- **Vectors.** `test/vectors/<variant>.json` is `[{name, input, inputHex, hex, options?}]` and
  `hmac-<variant>.json` is `[{name, key, keyHex, input, inputHex, hex}]`. From Zig use the `*Hex`
  fields: a JSON parser decodes `input` as UTF-8, which differs from the intended bytes above 0x7F.
  These files are generated; edit the extractor, not the JSON. Hand-written vectors go in a
  different file name so the generator does not overwrite them.

## What it does not cover (yet)

- **NIST CAVP / official vector files** are not vendored (no network access when this was written).
  `node:crypto` plays that role for the algorithms OpenSSL implements. MD2, MD4, HAS-160,
  RIPEMD-128/256/320, SHA-0, Snefru, Whirlpool(-0/-T) have only the original suite's published
  vectors plus the differential fuzzer. Adding CAVP `.rsp` conversion would be a good follow-up.
- **Inputs of 2 GiB or more** are exercised through `state.length` only.
- **`src/index.mjs`** of the original assigns `module.exports` and cannot load as native ESM. In the package it is a
  facade file (default export), so the harness does not compare it with the original. `test/package/` (`npm run
  test:package`) covers the CJS entry, the global build, the tarball and the examples.
- **Environments** (browsers, Bun, Deno, CSP, Workers) belong to WP-I. The harness is plain ESM and
  has no Node-only dependency except `node:test` and `node:crypto` in the test files themselves.
- **Speed** is WP-J.
- **Hangs in the target.** A synchronous infinite loop cannot be interrupted by `node:test`. CI has a
  job timeout; locally interrupt with Ctrl-C. Only `divergences.test.js` deliberately triggers a hang,
  in a child process with a timeout.
