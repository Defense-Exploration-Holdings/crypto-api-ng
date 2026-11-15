# crypto-api-ng

Hashing library for JavaScript with no dependencies: a maintained port of [`crypto-api`](https://github.com/nf404/crypto-api) 0.8.5 (Aleksandr Mogilnikov, "nf404") whose compression functions run as Zig-compiled WebAssembly.

**Version 1 is a drop-in replacement for `crypto-api@0.8.5`**: same classes, same import paths, same options, same digests and the same `getState()` JSON for every input the original accepts, bugs included. **Version 2**, in development on this branch, keeps that API and fixes those bugs (see "Changes in version 2"). Where a hasher is used outside what the WebAssembly code models exactly (subclasses overriding internals, unusual states set with `setState()`, no WebAssembly in the environment), the original JavaScript code runs instead, so the result is the same either way.

> Status: pre-release. Not yet published to npm; the package name is not final.

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

The classes are importable one by one, exactly as with 0.8.5. Importing only the hashers you use keeps a bundle small: each algorithm family has its own WebAssembly module.

```javascript
import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
import {fromUtf} from "crypto-api-ng/src/encoder/utf.mjs";

let hasher = new Sha256();
hasher.update(fromUtf('message'));
console.log(toHex(hasher.finalize()));
```

```javascript
import Md5 from "crypto-api-ng/src/hasher/md5.mjs";
import Hmac from "crypto-api-ng/src/mac/hmac.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
import {fromUtf} from "crypto-api-ng/src/encoder/utf.mjs";

let hasher = new Md5();
let hmac = new Hmac(fromUtf('key'), hasher);
hmac.update(fromUtf('message'));
console.log(toHex(hmac.finalize()));
```

The extensionless paths of 0.8.5 (`crypto-api-ng/src/hasher/sha256`) still resolve in bundlers that try `.mjs` (webpack's default), because the files keep their names and locations. Native Node ESM and bundlers configured without `.mjs` need the explicit `.mjs`, as in the examples above. There is no `exports` map in v1, so every deep path stays reachable. `crypto-api-ng/src/index.mjs` default-exports the `CryptoApi` object. `require('crypto-api-ng')` and the global build are a separate bundle with its own copy of the classes, so a hasher created by one is not `instanceof` the classes of the other: pick one style per program.

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
* MAC: HMAC (`src/mac/hmac.mjs`, works with any hasher object, including your own)
* Encodings: `fromUtf`, `fromArrayBuffer`, `toHex`, `toBase64`
* The `CryptoApi` object: `getHasher`, `hash`, `getHmac`, `hmac`, `encoder`

The API documentation of 0.8.5 applies unchanged. All of them run their compression function in WebAssembly, with the original JavaScript as the fallback.

## Package layout

```
index.js                  CommonJS main (requires crypto-api.js)
crypto-api.js, .min.js    UMD / global `CryptoApi` build, ES5 syntax, WebAssembly embedded
src/                      the public modules of 0.8.5, same paths (hasher classes, hmac, encoders, tools)
legacy/hasher/            the original 0.8.5 hasher code, used as fallback and as the base of the wasm facades
wasm/                     embedded WebAssembly, one module per algorithm family
example/                  runnable examples
```

## Differences from crypto-api 0.8.5

Everything observable is kept, with these deliberate exceptions (and, in version 2, the fixes listed in the next section):

1. **No endless loop in Snefru.** `length` of 512 or more gives a block size of 0 or less, and the original `process()` never returns. Version 1 throws `RangeError` from `update()`; version 2 rejects such a `length` at construction.
2. **`main` works.** `require('crypto-api-ng')` loads `index.js` (the original's `main` pointed at a file that was never published).
3. **`src/index.mjs` is loadable.** The original assigned `module.exports` inside an ES module, which only the original's own babel setup accepted. v1 default-exports the same object.
4. **Private scratch arrays.** The `@private` working arrays of some hashers (`W`, `blockUnits`) are not filled when WebAssembly did the work, so `JSON.stringify(hasher)` can differ from the original in those fields. `getState()`, `setState()` and `state` are unaffected.

## Changes in version 2

Version 2 fixes the 0.8.5 behaviors that version 1 kept for compatibility. Every digest version 1 computed correctly is unchanged; what changes is what happens with inputs and options that gave wrong or meaningless results:

* **Bytes in.** `update()` takes a binary string (characters `\x00` to `\xFF`) or bytes: an `ArrayBuffer`, `SharedArrayBuffer` or any view of one (`Uint8Array`, `DataView`, ...). So do `Hmac` and the keys and messages of `CryptoApi.hash()` and `CryptoApi.hmac()`, which still UTF-8 encode strings.
* **No silent garbage.** `update()` throws `TypeError` for a string with a character above `\xFF` (encode text with `fromUtf()` first) and for any value that is neither a string nor bytes.
* **Messages of 2 GiB and more.** The length field is the full 64-bit bit count, so these get the correct digest.
* **`CryptoApi.getHasher('sm3')`** returns an SM3 hasher.
* **`Hmac`** leaves the hasher it is given untouched, `finalize()` can be called more than once, and `reset()` restarts with the same key.
* **Options are checked.** A `rounds` or `length` outside the supported set throws `RangeError` (or `TypeError` for a non-number) when the hasher is created. The supported values are listed in `CHANGELOG.md`.

## Migrating

* **From 0.8.x**: change the package name in `package.json`, imports and CDN URLs. Paths under `src/` and the `CryptoApi` global are unchanged. Persisted `getState()` objects load as before.
* **From 1.x**: code that hashes text with `fromUtf()` (or `CryptoApi.hash()`), uses documented options and creates a new `Hmac` per message works unchanged. Replace `update(fromArrayBuffer(buffer))` with `update(buffer)` if you like; both work. Code that relied on one of the behaviors listed under "Changes in version 2" needs updating.
* **From 0.7.x**: 0.8.0 changed the API (`CryptoApi.hash(...).stringify('hex')` became `CryptoApi.hash(name, message)` returning hex, hashers are classes). Nothing in this package restores the 0.7 API.

## License

MIT. The original `crypto-api` is Copyright (c) 2015 nf404, and the Zig/WebAssembly port is Copyright (c) 2026 Defense Exploration Holdings LLC; both notices are in `LICENSE`.
