# API reference

This page covers the public API of `crypto-api-ng` 1.1. It is the API of [crypto-api](https://github.com/nf404/crypto-api) 0.8.5 plus the changes listed in the [CHANGELOG](../packages/crypto-api/CHANGELOG.md).

Hashers work on **binary strings**: strings whose characters are all in `\x00`-`\xFF`, one character per byte. Digests are returned the same way. Use the encoders below to turn text into bytes and digests into hex or base64. Since 1.1 every input argument also accepts bytes (`ArrayBuffer`, `SharedArrayBuffer` or any view such as `Uint8Array`).

## The `CryptoApi` object

`require('crypto-api-ng')`, `import CryptoApi from 'crypto-api-ng/src/index.mjs'` and the browser global `CryptoApi` are the same object.

```javascript
CryptoApi.hash('sha256', 'abc');
// 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
```

| Method | Returns | Notes |
|---|---|---|
| `hash(name, message, options?)` | hex string | A string `message` is UTF-8 encoded; bytes are hashed as they are. |
| `getHasher(name, options?)` | a hasher | `undefined` for an unknown `name`. Names are in the table below. |
| `hmac(key, message, hasher)` | hex string | `key` and `message` are UTF-8 encoded if they are strings, bytes otherwise. |
| `getHmac(key, hasher)` | an `Hmac` | `key` is a binary string or bytes (not UTF-8 encoded). |
| `encoder` | object | `fromUtf`, `fromArrayBuffer`, `toHex`, `toBase64`. |

### Algorithm names

| Names for `getHasher` and `hash` | Class (path under `src/hasher/`) | Digest |
|---|---|---|
| `has160` | `Has160` (`has160.mjs`) | 160 bits |
| `md2`, `md4`, `md5` | `Md2`, `Md4`, `Md5` | 128 bits |
| `ripemd128`, `ripemd160` (also `ripemd`), `ripemd256`, `ripemd320` | `Ripemd` (`ripemd.mjs`) | 128, 160, 256, 320 bits |
| `sha0`, `sha1` | `Sha0`, `Sha1` | 160 bits |
| `sha224`, `sha256` | `Sha256` (`sha256.mjs`) | 224, 256 bits |
| `sha384`, `sha512`, `sha512/224`, `sha512/256` | `Sha512` (`sha512.mjs`) | 384, 512, 224, 256 bits |
| `sm3` | `Sm3` (`sm3.mjs`) | 256 bits |
| `snefru` (also `snefru128`, `snefru128/8`), `snefru128/2`, `snefru256` (also `snefru256/8`), `snefru256/4` | `Snefru` (`snefru.mjs`) | 128 or 256 bits |
| `whirlpool`, `whirlpool-0`, `whirlpool-t` | `Whirlpool` (`whirlpool.mjs`) | 512 bits |

Options passed to `getHasher` or `hash` override the defaults a name implies. Names that are not listed, including different capitalization, give `undefined` from `getHasher`.

## Hashers

Every hasher is a class with a default export, for example `import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs"`, and takes an optional options object.

```javascript
import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";

const hasher = new Sha256();
hasher.update('a');
hasher.update(new Uint8Array([0x62, 0x63]));
console.log(toHex(hasher.finalize()));   // sha256 of "abc"
```

| Method | Description |
|---|---|
| `update(message)` | Adds a binary string or bytes to the message. Can be called any number of times. Throws `TypeError` for anything else, and for a string with a character above `\xFF`. |
| `finalize()` | Pads, finishes and returns the digest as a binary string. Pass it to `toHex` or `toBase64`. |
| `reset()` | Back to the initial state, keeping the options. |
| `getState()` / `setState(state)` | A plain JSON-serializable snapshot of the hasher, and restoring it into a hasher of the same class and options. Use it to pause and resume a hash. |

A hasher is single use: after `finalize()` call `reset()` before hashing another message.

### Options

An option that is left out (or `undefined`) takes its default. Since 1.1 a value that is not supported throws `RangeError` (a number outside the set) or `TypeError` (not a number) when the hasher is created.

| Class | `rounds` (default) | `length` (default) | Other |
|---|---|---|---|
| `Has160` | 1 to 80 (80) | | |
| `Md2` | 1 to 255 (18) | | |
| `Md4`, `Md5` | | | |
| `Ripemd` | | 128, 160, 256 or 320 (160) | |
| `Sha0`, `Sha1` | 1 to 80 (80) | | |
| `Sha256` | 1 to 64 (64) | 224 or 256 (256) | |
| `Sha512` | 1 to 160 (160) | 32 to 512 in steps of 32 (512) | 384 is SHA-384, 512 is SHA-512, any other value is SHA-512/t (224 and 256 are the standard SHA-512/224 and SHA-512/256). |
| `Sm3` | 1 to 64 (64) | 256 | |
| `Snefru` | 1 to 8 (8) | 32 to 448 in steps of 32 (128) | |
| `Whirlpool` | 1 to 10 (10) | | `type`: `'0'` (Whirlpool-0), `'t'` (Whirlpool-T), anything else is Whirlpool |

`rounds` can lower the standard number of rounds, never raise it (MD2 allows up to 255). It exists for compatibility with the original and for research on reduced-round variants; leave it alone for normal hashing.

## HMAC

```javascript
import Md5 from "crypto-api-ng/src/hasher/md5.mjs";
import Hmac from "crypto-api-ng/src/mac/hmac.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";

const mac = new Hmac('key', new Md5());   // the Md5 object is not modified
mac.update('message');
console.log(toHex(mac.finalize()));
```

`new Hmac(key, hasher)` takes a binary string or bytes as the key and any hasher object, including your own subclass. It uses two fresh hashers of the same class and options, so the one you pass in stays untouched. `update(message)` adds data, `finalize()` returns the MAC as a binary string and can be called again (and `update()` continues the message), and `reset()` restarts with the same key. Whether the key is a UTF-8 string is up to you: use `CryptoApi.hmac()` or `fromUtf()` for text keys.

Compare MAC values in constant time (`crypto.timingSafeEqual` in Node.js), not with `===`. An `Hmac` object keeps key-derived state in memory for as long as it exists. See "Security notes" in the [package README](../packages/crypto-api/README.md) and [SECURITY.md](../SECURITY.md).

## Encoders

Each is its own module under `src/encoder/` with a named export, and also available as `CryptoApi.encoder.<name>`.

| Function | Module | Description |
|---|---|---|
| `fromUtf(text)` | `utf.mjs` | JavaScript string to a binary string of its UTF-8 bytes. |
| `fromArrayBuffer(buffer)` | `array-buffer.mjs` | `ArrayBuffer` to a binary string. Since 1.1 `update()` takes the buffer directly. |
| `toHex(binary)` | `hex.mjs` | Binary string (a digest) to lowercase hex. |
| `toBase64(binary)` | `base64.mjs` | Binary string to base64. |

## Errors

| Thrown | When |
|---|---|
| `TypeError` | `update()` (or an `Hmac` key or message) is not a string or bytes, or is a string with a character above `\xFF`; an option that is not a number. |
| `RangeError` | An option value outside the supported set (table above). |

## Compatibility notes

- `getState()` objects from 0.8.x and 1.0 load into 1.1 hashers.
- 1.0 and 0.8.5 hashed a string with characters above `\xFF` without complaint and gave a meaningless result; convert text with `fromUtf()` first.
- Messages of 2 GiB and more are hashed correctly from 1.1 on.
- Environments without WebAssembly, or a page whose Content-Security-Policy blocks it, run the original JavaScript implementation and give identical results.
