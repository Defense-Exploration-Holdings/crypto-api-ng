# API reference

This page covers the public API of `crypto-api-ng` 1.1. It is the API of [crypto-api](https://github.com/nf404/crypto-api) 0.8.5 plus the changes listed in the [CHANGELOG](../packages/crypto-api/CHANGELOG.md).

Hashers work on **binary strings**: strings whose characters are all in `\x00`-`\xFF`, one character per byte. `finalize()` returns the digest the same way. Since 1.1 every input argument also accepts bytes (`ArrayBuffer`, `SharedArrayBuffer` or any view such as `Uint8Array`), and `digest()` returns bytes, so a program that works on bytes never has to touch a binary string: see [Working with bytes](#working-with-bytes).

## The `CryptoApi` object

`require('crypto-api-ng')`, `import CryptoApi from 'crypto-api-ng/src/index.mjs'` and the browser global `CryptoApi` are the same object.

```javascript
CryptoApi.hash('sha256', 'abc');
// 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
```

| Method | Returns | Notes |
|---|---|---|
| `hash(name, message, options?)` | hex string | A string `message` is UTF-8 encoded; bytes are hashed as they are. |
| `hashBytes(name, message, options?)` | `Uint8Array` | Same as `hash`, digest as bytes. |
| `getHasher(name, options?)` | a hasher | `undefined` for an unknown `name`. Names are in the table below. |
| `hmac(key, message, hasher)` | hex string | `key` and `message` are UTF-8 encoded if they are strings, bytes otherwise. |
| `hmacBytes(key, message, hasher)` | `Uint8Array` | Same as `hmac`, MAC as bytes. |
| `getHmac(key, hasher)` | an `Hmac` | `key` is a binary string or bytes (not UTF-8 encoded). |
| `pbkdf2(password, hasher, options)` | hex string | PBKDF2 key derivation, see [Key derivation](#key-derivation). Strings are UTF-8 encoded. |
| `hkdf(ikm, hasher, options?)` | hex string | HKDF key derivation. Strings are UTF-8 encoded. |
| `pbkdf2Bytes(password, hasher, options)`, `hkdfBytes(ikm, hasher, options?)` | `Uint8Array` | Same as `pbkdf2` and `hkdf`, key as bytes. |
| `encoder` | object | `fromUtf`, `fromArrayBuffer`, `toHex`, `toBase64` (binary strings), and `utf8ToBytes`, `bytesToUtf8`, `bytesToHex`, `hexToBytes`, `bytesToBase64`, `base64ToBytes` (bytes). |

### Algorithm names

| Names for `getHasher` and `hash` | Class (path under `src/hasher/`) | Digest |
|---|---|---|
| `blake2b` (also `blake2b-512`), `blake2b-384`, `blake2b-256`, `blake2b-160`, `blake2b-128` | `Blake2b` (`blake2b.mjs`) | 512, 384, 256, 160, 128 bits |
| `blake2s` (also `blake2s-256`), `blake2s-224`, `blake2s-160`, `blake2s-128` | `Blake2s` (`blake2s.mjs`) | 256, 224, 160, 128 bits |
| `blake3` | `Blake3` (`blake3.mjs`) | 256 bits (any length with the `length` option) |
| `has160` | `Has160` (`has160.mjs`) | 160 bits |
| `md2`, `md4`, `md5` | `Md2`, `Md4`, `Md5` | 128 bits |
| `ripemd128`, `ripemd160` (also `ripemd`), `ripemd256`, `ripemd320` | `Ripemd` (`ripemd.mjs`) | 128, 160, 256, 320 bits |
| `sha0`, `sha1` | `Sha0`, `Sha1` | 160 bits |
| `sha224`, `sha256` | `Sha256` (`sha256.mjs`) | 224, 256 bits |
| `sha384`, `sha512`, `sha512/224`, `sha512/256` | `Sha512` (`sha512.mjs`) | 384, 512, 224, 256 bits |
| `sm3` | `Sm3` (`sm3.mjs`) | 256 bits |
| `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512` | `Sha3` (`sha3.mjs`) | 224, 256, 384, 512 bits |
| `shake128`, `shake256` | `Shake` (`shake.mjs`) | any length, 256 and 512 bits by default |
| `keccak224`, `keccak256`, `keccak384`, `keccak512` | `Keccak` (`keccak.mjs`) | 224, 256, 384, 512 bits |
| `snefru` (also `snefru128`, `snefru128/8`), `snefru128/2`, `snefru256` (also `snefru256/8`), `snefru256/4` | `Snefru` (`snefru.mjs`) | 128 or 256 bits |
| `whirlpool`, `whirlpool-0`, `whirlpool-t` | `Whirlpool` (`whirlpool.mjs`) | 512 bits |
| `tiger` (also `tiger192`), `tiger160`, `tiger128` | `Tiger` (`tiger.mjs`) | 192, 160, 128 bits |
| `tiger2` | `Tiger2` (`tiger2.mjs`) | 192 bits (any length with the `length` option) |
| `streebog` (also `streebog512`), `streebog256` | `Streebog` (`streebog.mjs`) | 512, 256 bits |
| `crc32`, `crc32c` | `Crc32`, `Crc32c` (`crc32.mjs`, `crc32c.mjs`) | 32 bits (checksums) |
| `xxhash32`, `xxhash64` | `XxHash32`, `XxHash64` (`xxhash32.mjs`, `xxhash64.mjs`) | 32, 64 bits (checksums) |
| `xxhash3`, `xxhash128` | `XxHash3`, `XxHash128` (`xxhash3.mjs`, `xxhash128.mjs`) | 64, 128 bits (checksums) |
| `siphash`, `siphash-2-4`, `siphash-1-3` | `SipHash`, `SipHash13` (`siphash.mjs`, `siphash13.mjs`) | 64 bits (keyed; `key` is required) |
| `murmur3`, `murmur3-x86-32`, `murmur3-x64-128` | `Murmur3`, `Murmur3x64` (`murmur3.mjs`, `murmur3x64.mjs`) | 32, 128 bits (checksums) |

Options passed to `getHasher` or `hash` override the defaults a name implies. Names that are not listed, including different capitalization, give `undefined` from `getHasher`.

## Hashers

Every hasher is a class with a default export, for example `import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs"`, and takes an optional options object. Each also has a short per-algorithm entry point that loads only that algorithm, for example `import Sha256 from "crypto-api-ng/sha256"` (the same class); the [package README](../packages/crypto-api/README.md#per-algorithm-entry-points) lists them all with their sizes.

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
| `digest(encoding?)` | `finalize()`, then the digest as a `Uint8Array`, or as text for `encoding` `'hex'`, `'base64'`, `'base64url'` or `'binary'`. See [Working with bytes](#working-with-bytes). |
| `reset()` | Back to the initial state, keeping the options. |
| `getState()` / `setState(state)` | A plain JSON-serializable snapshot of the hasher, and restoring it into a hasher of the same class and options. Use it to pause and resume a hash. |

A hasher is single use: after `finalize()` call `reset()` before hashing another message (the BLAKE hashers are the exception, see below).

### Options

An option that is left out (or `undefined`) takes its default. Since 1.1 a value that is not supported throws `RangeError` (a number outside the set) or `TypeError` (not a number) when the hasher is created.

| Class | `rounds` (default) | `length` (default) | Other |
|---|---|---|---|
| `Blake2b` | | 8 to 512 in steps of 8 (512) | `key` (up to 64 bytes), `salt` and `personalization` (up to 16 bytes each) |
| `Blake2s` | | 8 to 256 in steps of 8 (256) | `key` (up to 32 bytes), `salt` and `personalization` (up to 8 bytes each) |
| `Blake3` | | 8 to 8388608 in steps of 8 (256) | `key` (exactly 32 bytes) or `context`, not both |
| `Has160` | 1 to 80 (80) | | |
| `Md2` | 1 to 255 (18) | | |
| `Md4`, `Md5` | | | |
| `Ripemd` | | 128, 160, 256 or 320 (160) | |
| `Sha0`, `Sha1` | 1 to 80 (80) | | |
| `Sha256` | 1 to 64 (64) | 224 or 256 (256) | |
| `Sha512` | 1 to 160 (160) | 32 to 512 in steps of 32 (512) | 384 is SHA-384, 512 is SHA-512, any other value is SHA-512/t (224 and 256 are the standard SHA-512/224 and SHA-512/256). |
| `Sm3` | 1 to 64 (64) | 256 | |
| `Sha3`, `Keccak` | | 224, 256, 384 or 512 (512) | |
| `Shake` | | 8 to 2^30 in steps of 8 (256 for strength 128, 512 for strength 256) | `strength`: 128 (SHAKE128, the default) or 256 (SHAKE256) |
| `Snefru` | 1 to 8 (8) | 32 to 448 in steps of 32 (128) | |
| `Tiger`, `Tiger2` | | 8 to 192 in steps of 8 (192) | |
| `Streebog` | | 256 or 512 (512) | |
| `Crc32`, `Crc32c` | | | |
| `XxHash32` | | | `seed`: an integer from 0 to 2^32 - 1 (0) |
| `XxHash64` | | | `seed`: an integer from 0 to 2^53 - 1 (0) |
| `XxHash3`, `XxHash128` | | | `seed`: an integer from 0 to 2^53 - 1 (0) |
| `SipHash`, `SipHash13` | | | `key`: exactly 16 bytes, required |
| `Murmur3`, `Murmur3x64` | | | `seed`: an integer from 0 to 2^32 - 1 (0) |
| `Whirlpool` | 1 to 10 (10) | | `type`: `'0'` (Whirlpool-0), `'t'` (Whirlpool-T), anything else is Whirlpool |

The SHA-3 hashers `Sha3`, `Shake` and `Keccak` are additions of this package (the original has no SHA-3). They use the same interface with these differences:

- `length` is the digest size in bits. For `Shake` it is the output length, a multiple of 8, and `strength` selects SHAKE128 or SHAKE256; the digest can be up to 128 MiB, returned as a string of `length / 8` characters. `Shake` has no `rounds` option.
- `Keccak` is the hash with the padding of the original Keccak submission, which differs from SHA-3 in one byte of domain separation. Keccak-256 is the hash Ethereum calls "keccak256". Use `Sha3` for the standard.
- `finalize()` does not end the message: it can be called again with the same result, and `update()` continues the message. `reset()` still starts over.
- `blockSizeInBytes` is the sponge rate (144, 136, 104 and 72 for the four SHA-3 sizes, 168 and 136 for SHAKE128 and SHAKE256), which is the block size HMAC uses. HMAC-SHA3-256 and the like match the usual definition. NIST does not define HMAC over SHAKE (use KMAC for that); the combination works but has no standard to compare with.

`rounds` can lower the standard number of rounds, never raise it (MD2 allows up to 255). It exists for compatibility with the original and for research on reduced-round variants; leave it alone for normal hashing.

### BLAKE2 and BLAKE3

[BLAKE2b and BLAKE2s](https://www.rfc-editor.org/rfc/rfc7693) and [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) are not in `crypto-api` 0.8.5, so they follow the conventions of this package instead. Their `length` is in bits, like the other hashers', and a value that is not supported throws.

```javascript
import Blake2b from "crypto-api-ng/src/hasher/blake2b.mjs";
import Blake3 from "crypto-api-ng/src/hasher/blake3.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";

const mac = new Blake2b({length: 256, key: 'secret key'});   // a keyed hash is a MAC, no HMAC needed
mac.update('message');
console.log(toHex(mac.finalize()));

const kdf = new Blake3({context: 'my-app 2026-11-15 session keys', length: 512});
kdf.update(inputKeyMaterial);                                // bytes or a binary string
const keys = kdf.finalize();                                 // 64 bytes of derived key
```

- `key`, `salt`, `personalization` and `context` are binary strings or bytes, not UTF-8 encoded: use `fromUtf()` for text that is not ASCII. A BLAKE2 `salt` or `personalization` shorter than its size is padded with zero bytes.
- BLAKE2 `key` makes the digest a MAC. An empty key is no key.
- BLAKE3 has three modes. Without options it is a plain hash. With `key` (32 bytes) it is a keyed hash. With `context` it derives a key: the context string should be hard-coded and globally unique for the use, and the data you `update()` with is the key material. `key` and `context` cannot be combined.
- BLAKE3 can produce output of any length: the first 256 bits are the usual digest, and a longer `length` extends it (up to 1 MiB). A shorter output is a prefix of a longer one.
- Unlike the older hashers, `finalize()` leaves the hasher as it was: calling it again returns the same digest, and `update()` continues the message. Messages are limited to 2^53 - 1 bytes.
- `getState()` returns a JSON-serializable object like the other hashers'. A keyed BLAKE2 state holds the key (zero padded) until the first block is compressed, so treat it as secret material.
- The tree modes of BLAKE2 (`blake2bp`, `blake2sp`, `blake2xb`) are not implemented.

### Tiger, Streebog and the checksums

`Tiger`, `Tiger2`, `Streebog`, `Crc32`, `Crc32c`, `XxHash32`, `XxHash64`, `XxHash3`, `XxHash128`, `SipHash`, `SipHash13`, `Murmur3` and `Murmur3x64` are not in `crypto-api` 0.8.5. They follow the conventions of the BLAKE hashers: `length` is in bits, `finalize()` leaves the hasher as it was (call it again for the same digest, `update()` continues the message), options that are not supported throw, and `getState()` is a JSON-serializable object. Messages are limited to 2^53 - 1 bytes.

```javascript
import Streebog from "crypto-api-ng/src/hasher/streebog.mjs";
import XxHash64 from "crypto-api-ng/src/hasher/xxhash64.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";

const gost = new Streebog({length: 256});
gost.update('message');
console.log(toHex(gost.finalize()));

const sum = new XxHash64({seed: 42});
sum.update(bytes);                       // bytes or a binary string
console.log(toHex(sum.finalize()));      // 16 hex digits
```

- **Tiger** is the 1995 design of Anderson and Biham (192-bit digest, 64-byte blocks, three passes). The digest is the three 64-bit words in little-endian byte order, which is what the reference code prints (`3293ac63...` for the empty message). `length` takes the first bytes of that digest, which gives Tiger/160 and Tiger/128. **Tiger2** is Tiger with the padding byte 0x80 instead of 0x01 (`4441be75...` for the empty message).
- **Streebog** is the Russian standard GOST R 34.11-2012 ([RFC 6986](https://www.rfc-editor.org/rfc/rfc6986)). `length` 256 and 512 are the two variants (HMAC over either has the block size 64 bytes). The digest is the final value in memory order, the byte order that OpenSSL's gost engine, rhash and the Linux kernel print (`3f539a21...` and `8e945da2...` for the empty message). RFC 6986 prints its test vectors as big-endian integers, which is the same digest with the bytes reversed.
- **CRC-32** (IEEE 802.3, the one in zlib, gzip and PNG) and **CRC-32C** (Castagnoli, iSCSI and ext4) are checksums. The digest is the 4 bytes of the checksum, most significant first, so `toHex()` gives the number everyone prints (`cbf43926` for `123456789`).
- **XXH32** and **XXH64** are the xxHash functions of Yann Collet. The digest is the canonical representation of the specification, the hash as a big-endian number (`02cc5d05` and `ef46db3751d8e999` for the empty message with seed 0).
- **XXH3** (`XxHash3`, 64 bits) and **XXH128** (`XxHash128`, 128 bits) are the newer xxHash functions (xxHash 0.8, `XXH3_64bits_withSeed` and `XXH3_128bits_withSeed`). The digest is the canonical representation, the hash as a big-endian number, high 64 bits first for XXH128 (`2d06800538d394c2` and `99aa06d3014798d86001c324468d497f` for the empty message with seed 0). The custom secret of the reference API is not supported. A seed is limited to 2^53 - 1 here; the hasher state holds it as two 32-bit words, so `setState()` can restore any 64-bit seed.
- **SipHash-2-4** (`SipHash`) and **SipHash-1-3** (`SipHash13`) of Aumasson and Bernstein are keyed 64-bit hashes for hash tables that face untrusted input: without the key an attacker cannot predict which inputs collide. The 16-byte `key` is required, and should be random and secret. The digest is the output of the reference implementation, the 64-bit result least significant byte first (`310e0edd47db6f72` for the empty message and the key `00 01 .. 0f`). 64 bits is too short for a message authentication code; use HMAC or a keyed BLAKE2 for that. SipHash-1-3 is the faster variant used by Rust and Python. `getState()` holds values derived from the key, so treat a saved state like the key.
- **MurmurHash3** x86_32 (`Murmur3`) and x64_128 (`Murmur3x64`) are Austin Appleby's hashes from SMHasher, with a 32-bit seed. `Murmur3` writes the 32-bit result most significant byte first, so its hex form is the number other libraries print (`b3dd93fa` for `abc`). `Murmur3x64` writes the 16 bytes of the reference implementation, h1 then h2 each least significant byte first, which is what `mmh3.hash_bytes` (Python) and `Hashing.murmur3_128` (Guava) return. The x86_128 variant gives different values and is not provided.
- CRC-32, xxHash and MurmurHash3 are **not cryptographic**: they detect accidental changes and are fast, and anyone can produce input with a chosen checksum. Do not use them to authenticate or to compare secrets. Tiger is old and weakened in its reduced-round form; Streebog is the standard hash of Russian signatures; neither is a better choice than SHA-2, SHA-3 or BLAKE for new designs except where a protocol asks for it.

## HMAC

```javascript
import Md5 from "crypto-api-ng/src/hasher/md5.mjs";
import Hmac from "crypto-api-ng/src/mac/hmac.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";

const mac = new Hmac('key', new Md5());   // the Md5 object is not modified
mac.update('message');
console.log(toHex(mac.finalize()));
```

`new Hmac(key, hasher)` takes a binary string or bytes as the key and any hasher object, including your own subclass. It uses two fresh hashers of the same class and options, so the one you pass in stays untouched. `update(message)` adds data, `finalize()` returns the MAC as a binary string and can be called again (and `update()` continues the message), and `reset()` restarts with the same key. `digest(encoding?)` is `finalize()` returning bytes or text, like the hashers' `digest()`. Whether the key is a UTF-8 string is up to you: use `CryptoApi.hmac()` or `utf8ToBytes()` for text keys.

## Working with bytes

The classic interface speaks binary strings. Everything below speaks bytes instead, so you can hash and encode without a binary string anywhere.

```javascript
import CryptoApi from "crypto-api-ng/src/index.mjs";
import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
import Hmac from "crypto-api-ng/src/mac/hmac.mjs";
import {utf8ToBytes, bytesToHex, hexToBytes} from "crypto-api-ng/src/encoder/bytes.mjs";

const hasher = new Sha256();
hasher.update(utf8ToBytes('message'));     // bytes in
const digest = hasher.digest();            // Uint8Array(32) out
console.log(bytesToHex(digest));

const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
const mac = new Hmac(key, new Sha256());
mac.update(new Uint8Array([1, 2, 3]));
console.log(mac.digest('base64url'));      // or ask for text directly

CryptoApi.hashBytes('sha3-256', 'a string is UTF-8 encoded');   // Uint8Array(32)
CryptoApi.hmacBytes(key, new Uint8Array([1, 2, 3]), CryptoApi.getHasher('sha256'));
```

### `digest(encoding?)`

`digest()` is on every hasher, on `Hmac` and on the key derivation classes `Pbkdf2` and `Hkdf`. It calls `finalize()` and converts the result, so everything said about `finalize()` applies: a 0.8.5 hasher is used up by it, the SHA-3 and BLAKE hashers and `Hmac` can be asked again. A subclass that overrides `finalize()` is respected.

| `encoding` | Returns |
|---|---|
| left out | a new `Uint8Array` that owns its buffer |
| `'hex'` | lowercase hex |
| `'base64'` | base64 with padding |
| `'base64url'` | URL-safe base64 without padding, as Node.js writes it |
| `'binary'` | the binary string `finalize()` returns |

Any other value throws `TypeError` before the hasher is touched.

### Byte encoders

Importable from `src/encoder/bytes.mjs` and available as `CryptoApi.encoder.<name>`. They take bytes (`ArrayBuffer`, `SharedArrayBuffer` or any view of one) and return `Uint8Array` or text. Options are read as own properties of the object you pass, never from the prototype chain.

| Function | Description |
|---|---|
| `utf8ToBytes(text)` | UTF-8 bytes of a string. An unpaired surrogate becomes U+FFFD, as `TextEncoder` does. |
| `bytesToUtf8(bytes, options?)` | Text from UTF-8 bytes. Invalid bytes become U+FFFD; with `{fatal: true}` they throw `TypeError`. A leading byte order mark is kept. |
| `bytesToHex(bytes)` | Lowercase hex. |
| `hexToBytes(hex)` | Bytes from hex of either case, no separators or `0x`. Throws `SyntaxError` for an odd length or a character that is not a hex digit. |
| `bytesToBase64(bytes, options?)` | Base64 ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)). Options: `alphabet` (`'base64'`, the default, or `'base64url'`) and `omitPadding` (default `false`). |
| `base64ToBytes(text, options?)` | Bytes from base64. Option: `alphabet`. Padding may be left out, ASCII whitespace is ignored, and the unused bits of the last character must be zero. Throws `SyntaxError` for a character outside the alphabet, wrong padding, a length no byte string encodes to, or non-zero unused bits. |

`TextEncoder` and `TextDecoder` do the UTF-8 work where they exist, and a built-in implementation with the same results takes over where they do not. The encoders throw `TypeError` for an argument of the wrong type (for example text where bytes are expected).

Compare MAC values in constant time (`crypto.timingSafeEqual` in Node.js), not with `===`. An `Hmac` object keeps key-derived state in memory for as long as it exists. See "Security notes" in the [package README](../packages/crypto-api/README.md) and [SECURITY.md](../SECURITY.md).

## Key derivation

PBKDF2 ([RFC 8018](https://www.rfc-editor.org/rfc/rfc8018#section-5.2)) and HKDF ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)) are not in `crypto-api` 0.8.5. Both run HMAC over any hasher of the library, built on `Hmac`, and follow the same conventions as the rest of the package: a `new` class per use, binary strings or bytes in and a binary string out, and `length` in bits.

```javascript
import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
import Pbkdf2 from "crypto-api-ng/src/kdf/pbkdf2.mjs";
import Hkdf from "crypto-api-ng/src/kdf/hkdf.mjs";
import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
import {fromUtf} from "crypto-api-ng/src/encoder/utf.mjs";

// A key from a password: 32 bytes, 600000 iterations
const key = new Pbkdf2(fromUtf('correct horse'), new Sha256(), {salt: salt, iterations: 600000, length: 256}).finalize();

// Several keys from one secret
const kdf = new Hkdf(sharedSecret, new Sha256(), {salt: salt});
const encryptionKey = kdf.expand('my-app encryption', 256);
const macKey = kdf.expand('my-app mac', 256);

// Or in one call, with hex output and UTF-8 encoding of strings
CryptoApi.pbkdf2('correct horse', CryptoApi.getHasher('sha256'), {salt: 'salt', iterations: 600000});
CryptoApi.hkdf('secret', CryptoApi.getHasher('sha256'), {salt: 'salt', info: 'my-app', length: 512});
```

`new Pbkdf2(password, hasher, options)`

| Option | Meaning |
|---|---|
| `iterations` | Required: an integer from 1 to 4294967295. There is no default, because no count is safe for every machine; OWASP advised 600000 for HMAC-SHA-256 and 210000 for HMAC-SHA-512 in 2023. |
| `salt` | Binary string or bytes. Default empty; use a random salt of at least 16 bytes per password. |
| `length` | Size of the key in bits, a multiple of 8 up to 4294967295 digests. Default: the digest size of the hasher. |

`finalize()` returns the key as a binary string and can be called again. `digest(encoding?)` does the same and returns a `Uint8Array`, or text for `encoding` as for [hashers](#digestencoding). The work happens in `finalize()` and `digest()`, not in the constructor.

`new Hkdf(ikm, hasher, options?)` runs the extract step right away.

| Option or method | Meaning |
|---|---|
| `salt` | Binary string or bytes. Default empty, which is what RFC 5869 defines as a salt of zero bytes the size of the digest. |
| `info` | Context for `finalize()`, binary string or bytes. Default empty. |
| `length` | Size of the output of `finalize()` in bits, a multiple of 8 up to 255 digests. Default: the digest size of the hasher. |
| `extract()` | The pseudorandom key (PRK) of the extract step, as a binary string. |
| `expand(info?, length?)` | HKDF-Expand with another `info` and `length`: keys for different purposes from one extract step. |
| `finalize()` | HKDF-Expand with the `info` and `length` options. Can be called again. |
| `expandBytes(info?, length?)` | `expand()` returning a `Uint8Array`. |
| `digest(encoding?)` | `finalize()` returning a `Uint8Array`, or text for `encoding` as for [hashers](#digestencoding). |

Notes:

- The password, key material, salt and `info` are binary strings or bytes like the key of `Hmac`: a string with a character above `\xFF` throws, so encode text with `fromUtf()`. `CryptoApi.pbkdf2()` and `CryptoApi.hkdf()` do that for strings, like `CryptoApi.hmac()`.
- The hasher passed in is not modified, and data already in it is ignored (`Hmac` uses fresh copies). The digest size comes from the hasher, so `new Sha512({length: 256})` gives 32-byte blocks. Any hasher works, including keyed BLAKE2 and SHAKE, but the standards only define the construction over the usual hash functions.
- Options are read as own properties only, as for the hashers, and the object you pass is not modified. A name that is not an option of the class (for example a misspelled `salt`) throws `TypeError` instead of deriving an unsalted key.
- Speed: every iteration is one HMAC in JavaScript around the WebAssembly compression function, about 6 microseconds for SHA-256 on a current machine (600000 iterations take a few seconds). Use [`crypto.subtle.deriveBits`](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/deriveBits) or `node:crypto` where you only need SHA-1/2 and want the platform's speed; use these classes for the algorithms the platform does not have (SM3, BLAKE2, RIPEMD, Whirlpool) or when one code path must work everywhere.
- Verified against RFC 6070, RFC 7914 and RFC 5869 and, for the digests it has, `node:crypto`.

## Encoders

Each is its own module under `src/encoder/` with a named export, and also available as `CryptoApi.encoder.<name>`.

| Function | Module | Description |
|---|---|---|
| `fromUtf(text)` | `utf.mjs` | JavaScript string to a binary string of its UTF-8 bytes. |
| `fromArrayBuffer(buffer)` | `array-buffer.mjs` | `ArrayBuffer` to a binary string. Since 1.1 `update()` takes the buffer directly. |
| `toHex(binary)` | `hex.mjs` | Binary string (a digest) to lowercase hex. |
| `toBase64(binary)` | `base64.mjs` | Binary string to base64. |

These four work on binary strings, as in 0.8.5, and stay for compatibility. For new code prefer the [byte encoders](#byte-encoders).

## Errors

| Thrown | When |
|---|---|
| `TypeError` | `update()` (or an `Hmac` key or message) is not a string or bytes, or is a string with a character above `\xFF`; an option that is not a number. `Pbkdf2` and `Hkdf`: the same for the password, key material, `salt` and `info`, plus a missing `iterations`, a non-object `options` and an unknown option name. |
| `RangeError` | An option value outside the supported set (table above). `Pbkdf2` and `Hkdf`: `iterations` or `length` outside the ranges above. |

## Compatibility notes

- `getState()` objects from 0.8.x and 1.0 load into 1.1 hashers.
- 1.0 and 0.8.5 hashed a string with characters above `\xFF` without complaint and gave a meaningless result; convert text with `fromUtf()` first.
- Messages of 2 GiB and more are hashed correctly from 1.1 on.
- Environments without WebAssembly, or a page whose Content-Security-Policy blocks it, run the original JavaScript implementation and give identical results.
