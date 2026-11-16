# crypto-api-ng

Hashing library for JavaScript with no dependencies: a maintained port of [`crypto-api`](https://github.com/nf404/crypto-api) 0.8.5 (Aleksandr Mogilnikov, "nf404") whose compression functions run as Zig-compiled WebAssembly.

**Version 1 is a drop-in replacement for `crypto-api@0.8.5`**: same classes, same import paths, same options, same digests and the same `getState()` JSON for every input the original accepts, bugs included. **Version 1.1** keeps that API and fixes those bugs (see "Changes in 1.1"); the 1.0.x line keeps them for code that depends on the exact 0.8.5 behavior. Where a hasher is used outside what the WebAssembly code models exactly (subclasses overriding internals, unusual states set with `setState()`, no WebAssembly in the environment), the original JavaScript code runs instead, so the result is the same either way.

## Install

```sh
npm install crypto-api-ng
```

On Deno, from [JSR](https://jsr.io/@defense-exploration/crypto-api-ng):

```sh
deno add jsr:@defense-exploration/crypto-api-ng
```

```javascript
import Sha256 from "@defense-exploration/crypto-api-ng/sha256";
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

### Bun and Deno

Bun installs the package from npm like Node does (`bun add crypto-api-ng`) and reads the same `exports` map; `require()` and `import` both work. Deno 2 loads it with an `npm:` specifier or from a `package.json` dependency; the main entry is an ES module with a default export, and the per-algorithm entries work the same way:

```javascript
import CryptoApi from "npm:crypto-api-ng";
import Sha256 from "npm:crypto-api-ng/sha256";

console.log(CryptoApi.hash('sha256', 'message'));
```

Both runtimes run the WebAssembly code. Continuous integration installs the packed tarball into a Bun project (1.1 and the current release) and a Deno project (2.0 and the current release), and checks every entry point and the original test vectors there, with and without WebAssembly.

### Per-algorithm entry points

Each algorithm has a short import path that loads that algorithm and its WebAssembly module and nothing else. `import Sha256 from "crypto-api-ng/sha256"` in a browser app adds about 6 KB (gzipped) to the bundle, against 110 KB for the whole package, and none of the other WebAssembly modules. The default export is the same class as the one at `crypto-api-ng/src/hasher/sha256.mjs` (the same module, so `instanceof` agrees between the two paths). A family covers its variants through options, for example `new Sha256({length: 224})` is SHA-224.

Sizes are one bundle of that import alone (esbuild, minified, ES module, the WebAssembly embedded as base64). The first row is the `CryptoApi` object with all hashers.

<!-- entry-sizes:start -->
| Import | Provides | Minified | Min + gzip |
|---|---|---:|---:|
| `crypto-api-ng` | Everything: the `CryptoApi` object with every hasher, HMAC and the encoders | 338.8 KB | 159.4 KB |
| `crypto-api-ng/md2` | MD2 | 11.5 KB | 5.2 KB |
| `crypto-api-ng/md4` | MD4 | 18.1 KB | 7.4 KB |
| `crypto-api-ng/md5` | MD5 | 18.1 KB | 7.3 KB |
| `crypto-api-ng/has160` | HAS-160 | 14.9 KB | 6.3 KB |
| `crypto-api-ng/ripemd` | RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320 | 27.2 KB | 10.6 KB |
| `crypto-api-ng/sha0` | SHA-0 | 17.3 KB | 6.9 KB |
| `crypto-api-ng/sha1` | SHA-1 | 17.3 KB | 6.9 KB |
| `crypto-api-ng/sha256` | SHA-224, SHA-256 | 15.9 KB | 7.0 KB |
| `crypto-api-ng/sha512` | SHA-384, SHA-512, SHA-512/224, SHA-512/256 | 20.5 KB | 9.4 KB |
| `crypto-api-ng/sha3` | SHA3-224, SHA3-256, SHA3-384, SHA3-512 | 13.0 KB | 5.9 KB |
| `crypto-api-ng/shake` | SHAKE128, SHAKE256 | 13.1 KB | 5.9 KB |
| `crypto-api-ng/keccak` | Keccak-224, Keccak-256, Keccak-384, Keccak-512 | 13.0 KB | 5.9 KB |
| `crypto-api-ng/blake2b` | BLAKE2b | 22.0 KB | 9.3 KB |
| `crypto-api-ng/blake2s` | BLAKE2s | 19.6 KB | 8.6 KB |
| `crypto-api-ng/blake3` | BLAKE3 | 19.8 KB | 8.5 KB |
| `crypto-api-ng/sm3` | SM3 | 15.0 KB | 6.3 KB |
| `crypto-api-ng/snefru` | Snefru 128/256 | 92.5 KB | 51.4 KB |
| `crypto-api-ng/whirlpool` | Whirlpool, Whirlpool-0, Whirlpool-T | 26.7 KB | 13.7 KB |
| `crypto-api-ng/tiger` | Tiger (192-bit, shorter with `length`) | 30.4 KB | 15.6 KB |
| `crypto-api-ng/tiger2` | Tiger2 | 30.4 KB | 15.6 KB |
| `crypto-api-ng/streebog` | Streebog (GOST R 34.11-2012, 256 and 512 bits) | 44.2 KB | 27.5 KB |
| `crypto-api-ng/crc32` | CRC-32 checksum | 12.8 KB | 6.4 KB |
| `crypto-api-ng/crc32c` | CRC-32C (Castagnoli) checksum | 12.8 KB | 6.4 KB |
| `crypto-api-ng/xxhash32` | xxHash32 checksum | 13.6 KB | 6.0 KB |
| `crypto-api-ng/xxhash64` | xxHash64 checksum | 14.7 KB | 6.4 KB |
| `crypto-api-ng/hmac` | HMAC (takes any hasher object) | 4.2 KB | 1.6 KB |
| `crypto-api-ng/pbkdf2` | PBKDF2 (RFC 8018) over HMAC with any hasher | 6.0 KB | 2.2 KB |
| `crypto-api-ng/hkdf` | HKDF (RFC 5869) over HMAC with any hasher | 5.9 KB | 2.2 KB |
| `crypto-api-ng/encoder/hex` | toHex | 0.1 KB | 0.1 KB |
| `crypto-api-ng/encoder/base64` | toBase64 | 0.5 KB | 0.3 KB |
| `crypto-api-ng/encoder/utf` | fromUtf | 0.6 KB | 0.3 KB |
| `crypto-api-ng/encoder/bytes` | utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes | 4.6 KB | 1.9 KB |
| `crypto-api-ng/encoder/array-buffer` | fromArrayBuffer | 0.1 KB | 0.1 KB |
<!-- entry-sizes:end -->

Notes:

* The entries are ES modules. `require("crypto-api-ng/sha256")` works where Node can `require()` ES modules (22.12 and later); for older CommonJS environments use `require("crypto-api-ng")` or the global build.
* The main entry (`crypto-api-ng`) is unchanged: `CryptoApi.getHasher()` selects an algorithm by name at run time, so importing it always includes every hasher. Use the entries above to ship only what you use.
* The entries need a bundler or runtime that reads the `exports` field of `package.json` (Node 12.7 or later, webpack 5, esbuild, Rollup with `@rollup/plugin-node-resolve`, Vite, TypeScript with `moduleResolution` `node16`, `nodenext` or `bundler`; `node10` resolution also works through `typesVersions`). Older tools can use the 0.8.5 paths under `src/`.
* The package sets `"sideEffects": false`, and a hasher starts its WebAssembly module only on first use, so an unused import costs nothing at run time.

### Bytes in, bytes out

Hashers and HMAC take `Uint8Array` and give `Uint8Array` back through `digest()`, and `src/encoder/bytes.mjs` converts between bytes, UTF-8 text, hex and base64, so no binary strings are involved. The binary-string interface above stays as it is.

```javascript
import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
import {utf8ToBytes, bytesToHex} from "crypto-api-ng/src/encoder/bytes.mjs";

const hasher = new Sha256();
hasher.update(utf8ToBytes('message'));
console.log(bytesToHex(hasher.digest()));    // or hasher.digest('hex'), 'base64', 'base64url'
```

### TypeScript

The package ships its own declarations; nothing extra to install. They cover the `CryptoApi` object (`import CryptoApi = require("crypto-api-ng")` or `import CryptoApi from "crypto-api-ng/src/index.mjs"`), every hasher class, `Hmac`, `Pbkdf2`, `Hkdf` and the encoders, with the option ranges of each algorithm typed.

```typescript
import Sha256 from "crypto-api-ng/sha256";
import { toHex } from "crypto-api-ng/encoder/hex";

const hasher = new Sha256({ length: 224 });
hasher.update(new Uint8Array([1, 2, 3]));
console.log(toHex(hasher.finalize()));
```

### Browser (ES5 global build)

`crypto-api.min.js` (and the unminified `crypto-api.js`) is a UMD build in ES5 syntax that defines the global `CryptoApi`. The WebAssembly modules are embedded, so it is a single file. Load it from your own server or a CDN that mirrors npm. Pin the version in the URL and add an `integrity` attribute, so that the browser rejects a file that differs from the one you checked:

```html
<script src="https://cdn.jsdelivr.net/npm/crypto-api-ng@1.2.2/crypto-api.min.js"
        integrity="sha384-HASH_OF_THE_FILE"
        crossorigin="anonymous"></script>
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

Compute the value for `integrity` from the file of that version, once, and replace `HASH_OF_THE_FILE` with it (update both the version and the hash when you upgrade):

```sh
openssl dgst -sha384 -binary crypto-api.min.js | openssl base64 -A
```

Where WebAssembly is missing or blocked (a page whose Content-Security-Policy lacks `'wasm-unsafe-eval'`, Cloudflare Workers, old browsers), the same file keeps working with the original JavaScript code.

`example/` has runnable pages (`hasher-basic.html`, `hasher-file.html`, `unit-tests.html`) that load the global build from `..`, and `node.mjs` / `node.cjs`.

## What is included

* Hashing: HAS-160, MD2, MD4, MD5, RIPEMD-128/160/256/320, SHA-0, SHA-1, SHA-224/256, SHA-384/512, SHA-512/224, SHA-512/256, SM3, Snefru v2.0 and v2.5, WHIRLPOOL, WHIRLPOOL-0, WHIRLPOOL-T
* Added in this package: SHA3-224/256/384/512, SHAKE128/256, Keccak-224/256/384/512, BLAKE2b, BLAKE2s, BLAKE3, Tiger, Tiger2, Streebog-256/512, and the checksums CRC-32, CRC-32C, XXH32, XXH64
* MAC: HMAC (`src/mac/hmac.mjs`, works with any hasher object, including your own)
* Key derivation: PBKDF2 (`src/kdf/pbkdf2.mjs`) and HKDF (`src/kdf/hkdf.mjs`), over HMAC with any hasher
* Encodings: `fromUtf`, `fromArrayBuffer`, `toHex`, `toBase64` (binary strings) and, added in this package, `utf8ToBytes`, `bytesToUtf8`, `bytesToHex`, `hexToBytes`, `bytesToBase64`, `base64ToBytes` (bytes)
* The `CryptoApi` object: `getHasher`, `hash`, `hashBytes`, `getHmac`, `hmac`, `hmacBytes`, `pbkdf2`, `hkdf`, `encoder`

The full API, with options, errors and examples, is in the [API reference](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/blob/main/docs/api.md). All of the algorithms run their compression function in WebAssembly, with the original JavaScript as the fallback.

## Security notes

* **Compatibility algorithms.** MD2, MD4, MD5, SHA-0, SHA-1, HAS-160, RIPEMD-128 and Snefru are provided for compatibility with existing data and protocols. They are not collision resistant. Do not use them for signatures, certificates or to check data from an untrusted source. Use SHA-256 or stronger for new designs.
* **Reduced rounds.** The `rounds` option of a hasher can be lowered below the standard value. This weakens any algorithm. It exists for research and interoperability only.
* **No constant-time claim.** The implementation does not claim constant-time execution. Do not use it to process secrets where timing is observable by an attacker.
* **Compare MACs in constant time.** Do not compare MAC values with `===`. In Node.js, use `crypto.timingSafeEqual` on buffers of equal length:

  ```javascript
  const { timingSafeEqual } = require('node:crypto');
  // expected: a Buffer with the MAC you were sent or stored
  const actual = Buffer.from(CryptoApi.hmac(key, message, CryptoApi.getHasher('sha256')), 'hex');
  const ok = actual.length === expected.length && timingSafeEqual(actual, expected);
  ```
* **Key material in memory.** An `Hmac` object keeps key-derived state in memory for as long as it exists. Drop the reference when you are done with it.

To report a vulnerability, follow [SECURITY.md](https://github.com/Defense-Exploration-Holdings/crypto-api-ng/blob/main/SECURITY.md).

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
