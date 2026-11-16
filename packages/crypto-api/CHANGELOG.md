# Changelog

## Unreleased

* Per-algorithm entry points. `package.json` now has an `exports` map with a short import path for every algorithm (`crypto-api-ng/sha256`, `crypto-api-ng/blake3`, `crypto-api-ng/hmac`, `crypto-api-ng/encoder/hex`, ...). Each is the same module as the matching `src/` path, and a bundle that imports only it contains only that algorithm and its own WebAssembly module (for example about 6 KB gzipped for SHA-256, against 110 KB for the whole package). The README lists every entry with its size. Nothing is removed: the main entry resolves as before (`require` and Node's `import` get `index.js`, bundlers get `src/index.mjs`), and every path of 0.8.5, with or without the `.mjs` extension, and every other file in the package still resolves. Tools that predate `exports` (webpack 4, TypeScript `node10` resolution without `typesVersions`) can keep using the `src/` paths.
* `fromUtf()`, and with it `CryptoApi.hash()` and `CryptoApi.hmac()` for string input, encodes an unpaired surrogate (a code unit in `U+D800` to `U+DFFF` that is not a high surrogate followed by a low one) as U+FFFD, as `TextEncoder` does. Previously it took the next code unit as the second half of a pair, so different strings such as `'\uDC00A'` and `'\u{10041}'` produced the same bytes and the same digest. Well-formed text is unchanged.
* Hashers only use `rounds`, `length` and `type` values that are own properties of the options object. A value inherited through the prototype chain, for example one added to `Object.prototype` by other code on the page, is ignored and the default is used. Previously such a value silently replaced the default (a one-round SHA-256, for instance). Own values are validated as before, and the options object you pass in still receives the defaults. The new hashers (`Sha3`, `Keccak`, `Shake`, `Blake2b`, `Blake2s`, `Blake3`) read their options (`length`, `strength`, `key`, `salt`, `personalization`, `context`) the same way, so an inherited `key`, `salt` or `context` can no longer turn a plain hash into a keyed one. `Sha3`, `Keccak` and `Shake` treat options that are not an object (`0`, `'abc'`, `true`) as no options.
* New hashers `Blake2b`, `Blake2s` and `Blake3` (`src/hasher/blake2b.mjs`, `blake2s.mjs`, `blake3.mjs`; `CryptoApi.getHasher()` names `blake2b`, `blake2s`, `blake3` and the sized variants `blake2b-256`, `blake2s-128`, ...). BLAKE2 supports digests of 8 to 512 (BLAKE2b) or 256 (BLAKE2s) bits, a key, a salt and a personalization string; BLAKE3 supports keyed hashing, key derivation and output of up to 1 MiB. Verified against the official BLAKE2 and BLAKE3 test vectors, RFC 7693, `node:crypto` and Python's `hashlib`. Compression runs in WebAssembly, with a plain JavaScript implementation where it is unavailable. `finalize()` of these hashers does not modify them. Keys, message bytes and digests are zeroed in the WebAssembly memory after every call. See the [API reference](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/blob/main/docs/api.md#blake2-and-blake3).
* New hashers, not in crypto-api 0.8.5: `Tiger` and `Tiger2` (192-bit digests, shorter ones with `length`), `Streebog` (GOST R 34.11-2012, 256 or 512 bits), and four non-cryptographic checksums `Crc32` (IEEE 802.3), `Crc32c` (Castagnoli), `XxHash32` and `XxHash64` (with a `seed` option). `getHasher()` and `hash()` know `tiger`, `tiger192`, `tiger160`, `tiger128`, `tiger2`, `streebog`, `streebog256`, `streebog512`, `crc32`, `crc32c`, `xxhash32` and `xxhash64`, and `Hmac` works with them. Verified against the published test vectors (the Tiger design vectors, RFC 6986, RFC 3720 for CRC-32C, the xxHash reference values), `zlib.crc32`, Zig's `std.hash` and independent Python implementations of Tiger and Streebog. Compression runs in WebAssembly with a plain JavaScript implementation where it is unavailable; `finalize()` does not modify the hasher; message bytes and digests are zeroed in the WebAssembly memory after every call. SHA-512/224 and SHA-512/256 were already available (`sha512/224`, `sha512/256`). See the [API reference](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/blob/main/docs/api.md#tiger-streebog-and-the-checksums).
* New key derivation functions, not in crypto-api 0.8.5: `Pbkdf2` (`src/kdf/pbkdf2.mjs`) and `Hkdf` (`src/kdf/hkdf.mjs`), both HMAC based and usable with any hasher, plus `CryptoApi.pbkdf2()` and `CryptoApi.hkdf()` that return hex. `iterations` of PBKDF2 is required and there is no default. Verified against RFC 6070, RFC 7914, RFC 5869 and `node:crypto`. See the [API reference](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/blob/main/docs/api.md#key-derivation).
* TypeScript declarations ship with the package (`index.d.ts`, `types.d.ts` and a `.d.mts` file for every module under `src/`). No runtime change.
* New hashers, not in crypto-api 0.8.5: `Sha3` (SHA3-224, SHA3-256, SHA3-384, SHA3-512), `Shake` (SHAKE128, SHAKE256 with any output length) and `Keccak` (Keccak-224/256/384/512 with the original padding, as used by Ethereum). `getHasher()` and `hash()` know `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `shake128`, `shake256`, `keccak224`, `keccak256`, `keccak384` and `keccak512`, and `Hmac` works with them. The permutation runs in WebAssembly with a JavaScript fallback; `finalize()` of these hashers does not change the state, so it can be repeated and `update()` continues the message. Message bytes and digests are zeroed in the WebAssembly memory after every call. `setState()` with a state these hashers cannot work on (a `hash` that is not 50 integers, a `message` that is not a string, a block size that is not a sponge rate, and for BLAKE2 and BLAKE3 a counter, stack or empty last block that does not match the rest of the state) makes `update()` or `finalize()` throw a `TypeError` or `RangeError`, the same with and without WebAssembly.
* New [API reference](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/blob/main/docs/api.md).

## 1.1.0 (2026-11-15)

Fixes the 0.8.5 bugs that 1.0 kept for compatibility.

**Behavior changes.** Every digest that 1.0 computed correctly is unchanged. Inputs and options that gave a wrong or meaningless result in 0.8.5 and 1.0 now throw or give the correct result, so code that depended on one of those results needs updating. The 1.0.x line stays available for code that needs the exact 0.8.5 behavior.

* `update()` accepts bytes: an `ArrayBuffer`, `SharedArrayBuffer` or any view of one (`Uint8Array`, `DataView`, other typed arrays) is hashed as its bytes. `Hmac` keys and messages, and the `CryptoApi.hash()`/`hmac()` messages and keys, accept bytes too (strings are still UTF-8 encoded there).
* `update()` throws `TypeError` for a string with a character above `\xFF` (previously an algorithm-specific value that was neither UTF-8 nor Latin-1). Convert text with `fromUtf()` first, or pass bytes.
* `update()` throws `TypeError` for any other value (previously coerced with `String()`, so `Uint8Array([1, 2])` was hashed as `"1,2"`).
* The message length field is the full 64-bit bit count. Messages of 2 GiB or more now get the correct digest; shorter messages are unaffected.
* `CryptoApi.getHasher('sm3')` returns an SM3 hasher, so `CryptoApi.hash('sm3', ...)` works.
* `Hmac` no longer modifies the hasher passed to it: it hashes with two fresh hashers of the same class and options, and ignores any data already in the one given. `finalize()` can be called repeatedly and returns the same value; `update()` after it continues the message. New `reset()` restarts with the same key.
* Out-of-range `rounds` and `length` options throw at construction: `RangeError` for a number outside the supported set, `TypeError` for a value that is not a number. `undefined` still selects the default. Supported values:

  | Class | `rounds` | `length` |
  |---|---|---|
  | `Has160` | 1 to 80 | |
  | `Md2` | 1 to 255 | |
  | `Ripemd` | | 128, 160, 256, 320 |
  | `Sha0`, `Sha1` | 1 to 80 | |
  | `Sha256` | 1 to 64 | 224, 256 |
  | `Sha512` | 1 to 160 | 32 to 512 in steps of 32 |
  | `Sm3` | 1 to 64 | 256 |
  | `Snefru` | 1 to 8 | 32 to 448 in steps of 32 |
  | `Whirlpool` | 1 to 10 | |

  `rounds` can reduce the standard round count but not extend it (MD2, whose rounds use no constants, allows up to 255). The rejected values previously ran on undefined round constants, threw from inside `update()`, or never returned.

## 1.0.1

* README: remove the outdated pre-release notice. No code changes.

## 1.0.0

Maintained Zig/WebAssembly port of `crypto-api` 0.8.5. Drop-in replacement: same API, same import paths, same results and `getState()` JSON. See "Differences from crypto-api 0.8.5" in the README for the complete list of deliberate differences.

* `main` works: `require()` returns the `CryptoApi` object (`index.js`)
* `src/index.mjs` default-exports the `CryptoApi` object
* Global build `crypto-api.min.js` (and `crypto-api.js`) in ES5 syntax with WebAssembly embedded and automatic fallback to the original JavaScript
* All `src/**/*.mjs` imports carry explicit `.mjs` extensions, so native Node ESM loads them
* Snefru throws `RangeError` instead of looping forever when `length` is 512 or more
* All hashers run their compression function in WebAssembly
* License: MIT for the whole package; `LICENSE` carries the original's notice (nf404, 2015) and one for the port (Defense Exploration Holdings LLC, 2026)

## History of crypto-api (nf404)

* 0.8.5
  - This version for deployment to npm
* 0.8.4
  - Add toBase64
  - Add fromArrayBuffer
  - Add support of SHA512/t hash
  - Optimize hash padding
  - Add SM3 hash
* 0.8.3
  - Fix Whirlpool bug
  - Add compiled es5 version for nodejs
* 0.8.2
  - technical version (fix npm key)
* 0.8.1
  - Add support for nodejs
  - Refactor reset function and fix bug with constructor calling in it
  - Fix es6 usage in documentation
* 0.8.0 **Breakable changes**
  - Rewrite to ES6
  - Refactor all code & invert dependencies
  - Add length option to Ripemd, Sha256, Sha512, Snefru
  - Add rounds option to Has160, Md2, Sha0, Sha1, Sha256, Sha512, Snefru, Whirlpool
  - WHIRLPOOL, WHIRLPOOL-0, WHIRLPOOL-T now selected by option type
  - Rewrite documentation to esdoc
* 0.7.5
  - Add Snefru v2.0, Snefru v2.5
* 0.7.4
  - Add HAS-160
  - Add WHIRLPOOL, WHIRLPOOL-0, WHIRLPOOL-T
* 0.7.3
  - Add RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320
* 0.7.2
  - Fix documentation
* 0.7.1
  - Add SHA512/224, SHA512/256
* 0.7.0
  - Add SHA384, SHA512
* 0.6.2
  - Perfomance optimization
  - Add benchmark
