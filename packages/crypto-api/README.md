# crypto-api-ng

Hashing library for JavaScript with no dependencies: a maintained port of [`crypto-api`](https://github.com/nf404/crypto-api) 0.8.5 (Aleksandr Mogilnikov, "nf404") whose compression functions run as Zig-compiled WebAssembly.

**Version 1 is a drop-in replacement for `crypto-api@0.8.5`**: same classes, same import paths, same options, same digests and the same `getState()` JSON for every input the original accepts, bugs included. **Version 1.1** keeps that API and fixes those bugs (see "Changes in 1.1"); the 1.0.x line keeps them for code that depends on the exact 0.8.5 behavior. Where a hasher is used outside what the WebAssembly code models exactly (subclasses overriding internals, unusual states set with `setState()`, no WebAssembly in the environment), the original JavaScript code runs instead, so the result is the same either way.

## Install

```sh
npm install crypto-api-ng
```

## Use

### Node.js (CommonJS)

`require('crypto-api-ng')` returns the `CryptoApi` object, the same one as the browser global. (In the original 0.8.x tarballs `main` pointed at a file that was never published, so this always failed.)

```javascript
const CryptoApi = require('crypto-api-ng');

console.log(CryptoApi.hash('sha256', 'message'));                        // hex digest of a UTF string
console.log(CryptoApi.hmac('key', 'message', CryptoApi.getHasher('md5')));
```

### ES modules (Node.js, bundlers)

The classes are importable one by one, with a short path for each algorithm (see [Per-algorithm entry points](#per-algorithm-entry-points)) or with the paths of 0.8.5. Importing only the hashers you use keeps a bundle small: each algorithm family has its own WebAssembly module.

```javascript
import Sha256 from "crypto-api-ng/sha256";
import {toHex} from "crypto-api-ng/encoder/hex";
import {fromUtf} from "crypto-api-ng/encoder/utf";

let hasher = new Sha256();
hasher.update(fromUtf('message'));
console.log(toHex(hasher.finalize()));
```

```javascript
import Md5 from "crypto-api-ng/md5";
import Hmac from "crypto-api-ng/hmac";
import {toHex} from "crypto-api-ng/encoder/hex";
import {fromUtf} from "crypto-api-ng/encoder/utf";

let hasher = new Md5();
let hmac = new Hmac(fromUtf('key'), hasher);
hmac.update(fromUtf('message'));
console.log(toHex(hmac.finalize()));
```

The paths of 0.8.5 keep working: `crypto-api-ng/src/hasher/sha256.mjs`, and also without the extension (`crypto-api-ng/src/hasher/sha256`), in Node and in every bundler that reads `exports`. `crypto-api-ng/src/index.mjs` default-exports the `CryptoApi` object. `require('crypto-api-ng')` and the global build are a separate bundle with its own copy of the classes, so a hasher created by one is not `instanceof` the classes of the other: pick one style per program.

### Per-algorithm entry points

Each algorithm has a short import path that loads that algorithm and its WebAssembly module and nothing else. `import Sha256 from "crypto-api-ng/sha256"` in a browser app adds about 6 KB (gzipped) to the bundle, against 110 KB for the whole package, and none of the other WebAssembly modules. The default export is the same class as the one at `crypto-api-ng/src/hasher/sha256.mjs` (the same module, so `instanceof` agrees between the two paths). A family covers its variants through options, for example `new Sha256({length: 224})` is SHA-224.

Sizes are one bundle of that import alone (esbuild, minified, ES module, the WebAssembly embedded as base64). The first row is the `CryptoApi` object with all hashers.

<!-- entry-sizes:start -->
| Import | Provides | Minified | Min + gzip |
|---|---|---:|---:|
| `crypto-api-ng` | Everything: the `CryptoApi` object with every hasher, HMAC and the encoders | 244.3 KB | 110.1 KB |
| `crypto-api-ng/md2` | MD2 | 8.6 KB | 4.1 KB |
| `crypto-api-ng/md4` | MD4 | 15.3 KB | 6.2 KB |
| `crypto-api-ng/md5` | MD5 | 15.2 KB | 6.0 KB |
| `crypto-api-ng/has160` | HAS-160 | 11.9 KB | 5.2 KB |
| `crypto-api-ng/ripemd` | RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320 | 23.7 KB | 9.2 KB |
| `crypto-api-ng/sha0` | SHA-0 | 14.2 KB | 5.8 KB |
| `crypto-api-ng/sha1` | SHA-1 | 14.2 KB | 5.8 KB |
| `crypto-api-ng/sha256` | SHA-224, SHA-256 | 12.9 KB | 5.9 KB |
| `crypto-api-ng/sha512` | SHA-384, SHA-512, SHA-512/224, SHA-512/256 | 17.1 KB | 8.2 KB |
| `crypto-api-ng/sha3` | SHA3-224, SHA3-256, SHA3-384, SHA3-512 | 9.1 KB | 4.6 KB |
| `crypto-api-ng/shake` | SHAKE128, SHAKE256 | 9.1 KB | 4.7 KB |
| `crypto-api-ng/keccak` | Keccak-224, Keccak-256, Keccak-384, Keccak-512 | 9.1 KB | 4.6 KB |
| `crypto-api-ng/blake2b` | BLAKE2b | 17.7 KB | 8.0 KB |
| `crypto-api-ng/blake2s` | BLAKE2s | 15.3 KB | 7.2 KB |
| `crypto-api-ng/blake3` | BLAKE3 | 14.9 KB | 7.0 KB |
| `crypto-api-ng/sm3` | SM3 | 12.0 KB | 5.2 KB |
| `crypto-api-ng/snefru` | Snefru 128/256 | 89.6 KB | 50.0 KB |
| `crypto-api-ng/whirlpool` | Whirlpool, Whirlpool-0, Whirlpool-T | 23.4 KB | 12.6 KB |
| `crypto-api-ng/hmac` | HMAC (takes any hasher object) | 2.0 KB | 0.9 KB |
| `crypto-api-ng/encoder/hex` | toHex | 0.1 KB | 0.1 KB |
| `crypto-api-ng/encoder/base64` | toBase64 | 0.5 KB | 0.3 KB |
| `crypto-api-ng/encoder/utf` | fromUtf | 0.5 KB | 0.2 KB |
| `crypto-api-ng/encoder/array-buffer` | fromArrayBuffer | 0.1 KB | 0.1 KB |
<!-- entry-sizes:end -->

Notes:

* The entries are ES modules. `require("crypto-api-ng/sha256")` works where Node can `require()` ES modules (22.12 and later); for older CommonJS environments use `require("crypto-api-ng")` or the global build.
* The main entry (`crypto-api-ng`) is unchanged: `CryptoApi.getHasher()` selects an algorithm by name at run time, so importing it always includes every hasher. Use the entries above to ship only what you use.
* The entries need a bundler or runtime that reads the `exports` field of `package.json` (Node 12.7 or later, webpack 5, esbuild, Rollup with `@rollup/plugin-node-resolve`, Vite, TypeScript with `moduleResolution` `node16`, `nodenext` or `bundler`; `node10` resolution also works through `typesVersions`). Older tools can use the 0.8.5 paths under `src/`.
* The package sets `"sideEffects": false`, and a hasher starts its WebAssembly module only on first use, so an unused import costs nothing at run time.

### TypeScript

The package ships its own declarations; nothing extra to install. They cover the `CryptoApi` object (`import CryptoApi = require("crypto-api-ng")` or `import CryptoApi from "crypto-api-ng/src/index.mjs"`), every hasher class, `Hmac` and the encoders, with the option ranges of each algorithm typed.

```typescript
import Sha256 from "crypto-api-ng/sha256";
import { toHex } from "crypto-api-ng/encoder/hex";

const hasher = new Sha256({ length: 224 });
hasher.update(new Uint8Array([1, 2, 3]));
console.log(toHex(hasher.finalize()));
```

### Browser (ES5 global build)

`crypto-api.min.js` (and the unminified `crypto-api.js`) is a UMD build in ES5 syntax that defines the global `CryptoApi`. The WebAssembly modules are embedded, so it is a single file. Load it from your own server or a CDN that mirrors npm:

```html
<script src="https://cdn.jsdelivr.net/npm/crypto-api-ng/crypto-api.min.js"></script>
<script>
  var hasher = CryptoApi.getHasher('sha256');
  hasher.update('message');                       // update() takes a binary string
  console.log(CryptoApi.encoder.toHex(hasher.finalize()));

  console.log(CryptoApi.hash('sha256', 'message')); // UTF string in, hex out

  var hmac = CryptoApi.getHmac('key', CryptoApi.getHasher('md5'));
  hmac.update('message');
  console.log(CryptoApi.encoder.toHex(hmac.finalize()));

  console.log(CryptoApi.hmac('key', 'message', CryptoApi.getHasher('md5'))); // UTF key and message
</script>
```

Where WebAssembly is missing or blocked (a page whose Content-Security-Policy lacks `'wasm-unsafe-eval'`, Cloudflare Workers, old browsers), the same file keeps working with the original JavaScript code.

`example/` has runnable pages (`hasher-basic.html`, `hasher-file.html`, `unit-tests.html`) that load the global build from `..`, and `node.mjs` / `node.cjs`.

## What is included

* Hashing: HAS-160, MD2, MD4, MD5, RIPEMD-128/160/256/320, SHA-0, SHA-1, SHA-224/256, SHA-384/512, SHA-512/224, SHA-512/256, SM3, Snefru v2.0 and v2.5, WHIRLPOOL, WHIRLPOOL-0, WHIRLPOOL-T
* Added in this package: SHA3-224/256/384/512, SHAKE128/256, Keccak-224/256/384/512, BLAKE2b, BLAKE2s, BLAKE3
* MAC: HMAC (`src/mac/hmac.mjs`, works with any hasher object, including your own)
* Encodings: `fromUtf`, `fromArrayBuffer`, `toHex`, `toBase64`
* The `CryptoApi` object: `getHasher`, `hash`, `getHmac`, `hmac`, `encoder`

The full API, with options, errors and examples, is in the [API reference](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/blob/main/docs/api.md). All of the algorithms run their compression function in WebAssembly, with the original JavaScript as the fallback.

## Package layout

```
index.js                  CommonJS main (requires crypto-api.js)
index.d.ts, types.d.ts    TypeScript declarations (each module under src/ has a .d.mts next to it)
crypto-api.js, .min.js    UMD / global `CryptoApi` build, ES5 syntax, WebAssembly embedded
src/                      the public modules of 0.8.5, same paths (hasher classes, hmac, encoders, tools), and the new hashers
legacy/hasher/            the original 0.8.5 hasher code, used as fallback and as the base of the wasm facades
wasm/                     embedded WebAssembly, one module per algorithm family
example/                  runnable examples
```

## Differences from crypto-api 0.8.5

Everything observable is kept, with these deliberate exceptions (and, from 1.1, the fixes listed in the next section):

1. **No endless loop in Snefru.** `length` of 512 or more gives a block size of 0 or less, and the original `process()` never returns. 1.0 throws `RangeError` from `update()`; 1.1 rejects such a `length` at construction.
2. **`main` works.** `require('crypto-api-ng')` loads `index.js` (the original's `main` pointed at a file that was never published).
3. **`src/index.mjs` is loadable.** The original assigned `module.exports` inside an ES module, which only the original's own babel setup accepted. v1 default-exports the same object.
4. **Private scratch arrays.** The `@private` working arrays of some hashers (`W`, `blockUnits`) are not filled when WebAssembly did the work, so `JSON.stringify(hasher)` can differ from the original in those fields. `getState()`, `setState()` and `state` are unaffected.

## Changes in 1.1

1.1 fixes the 0.8.5 bugs that 1.0 kept for compatibility. Every digest 1.0 computed correctly is unchanged; what changes is what happens with inputs and options that gave wrong or meaningless results:

* **Bytes in.** `update()` takes a binary string (characters `\x00` to `\xFF`) or bytes: an `ArrayBuffer`, `SharedArrayBuffer` or any view of one (`Uint8Array`, `DataView`, ...). So do `Hmac` and the keys and messages of `CryptoApi.hash()` and `CryptoApi.hmac()`, which still UTF-8 encode strings.
* **No silent garbage.** `update()` throws `TypeError` for a string with a character above `\xFF` (encode text with `fromUtf()` first) and for any value that is neither a string nor bytes.
* **Messages of 2 GiB and more.** The length field is the full 64-bit bit count, so these get the correct digest.
* **`CryptoApi.getHasher('sm3')`** returns an SM3 hasher.
* **`Hmac`** leaves the hasher it is given untouched, `finalize()` can be called more than once, and `reset()` restarts with the same key.
* **Options are checked.** A `rounds` or `length` outside the supported set throws `RangeError` (or `TypeError` for a non-number) when the hasher is created. The supported values are listed in `CHANGELOG.md`.

## Migrating

* **From 0.8.x**: change the package name in `package.json`, imports and CDN URLs. Paths under `src/` and the `CryptoApi` global are unchanged. Persisted `getState()` objects load as before.
* **From 1.0**: code that hashes text with `fromUtf()` (or `CryptoApi.hash()`), uses documented options and creates a new `Hmac` per message works unchanged. Replace `update(fromArrayBuffer(buffer))` with `update(buffer)` if you like; both work. Code that relied on one of the behaviors listed under "Changes in 1.1" needs updating, or can pin `~1.0.0`.
* **From 0.7.x**: 0.8.0 changed the API (`CryptoApi.hash(...).stringify('hex')` became `CryptoApi.hash(name, message)` returning hex, hashers are classes). Nothing in this package restores the 0.7 API.

## License

MIT. The original `crypto-api` is Copyright (c) 2015 nf404, and the Zig/WebAssembly port is Copyright (c) 2026 Defense Exploration Holdings LLC; both notices are in `LICENSE`.
