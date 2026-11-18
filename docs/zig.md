# Zig API

The `crypto_api_ng` module (`src/lib.zig`) is the native Zig interface to the algorithms of crypto-api-ng. It does not use WebAssembly or JavaScript. It needs Zig 0.17.1.

## Installing

```sh
zig fetch --save git+https://github.com/Defense-Exploration-Holdings/crypto-api-ng#v1.4.0
```

`zig fetch` adds the dependency, with its hash, to your `build.zig.zon`. In `build.zig`:

```zig
const crypto_api_ng = b.dependency("crypto_api_ng", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("crypto_api_ng", crypto_api_ng.module("crypto_api_ng"));
```

[examples/zig](../examples/zig) is a complete project (it refers to the package by path instead of by URL).

## The hash interface

Every hash type has the interface of the hash functions in `std.crypto.hash`:

| Member | |
|---|---|
| `block_length` | the block size in bytes (the sponge rate for SHA-3 and Keccak), as HMAC uses it |
| `digest_length` | the digest size in bytes |
| `Options` | a struct of options; `.{}` gives the defaults |
| `init(options) Self` | a new hasher |
| `update(*Self, data)` | absorb bytes; call as often as needed |
| `final(*Self, out: *[digest_length]u8)` | write the digest and wipe the hasher |
| `finalResult(*Self) [digest_length]u8` | the same, returning the digest |
| `hash(data, out, options)` | one call: `init`, `update`, `final` |

A hasher is a plain value with no allocation. Copying it copies the state, so a copy can be finalized while the original continues. After `final` the hasher is zeroed; call `init` to start again.

```zig
const cryptoapi = @import("crypto_api_ng");

var h = cryptoapi.Sm3.init(.{});
h.update("part one, ");
h.update("part two");
const digest = h.finalResult(); // [32]u8
```

## Hash types

| Type | Digest | Notes |
|---|---|---|
| `Md2`, `Md4`, `Md5` | 16 bytes | broken, for compatibility only |
| `Sha0`, `Sha1` | 20 bytes | broken, for compatibility only |
| `Sha224`, `Sha256` | 28, 32 bytes | |
| `Sha384`, `Sha512`, `Sha512_224`, `Sha512_256` | 48, 64, 28, 32 bytes | |
| `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512` | 28, 32, 48, 64 bytes | FIPS 202 |
| `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512` | 28, 32, 48, 64 bytes | the original Keccak padding (`Keccak256` is Ethereum's keccak256) |
| `Shake128`, `Shake256` | any length | see [Extendable output](#extendable-output) |
| `Sm3` | 32 bytes | GB/T 32905-2016 |
| `Has160` | 20 bytes | TTAS.KO-12.0011/R2 |
| `Ripemd128`, `Ripemd160`, `Ripemd256`, `Ripemd320` | 16, 20, 32, 40 bytes | |
| `Whirlpool`, `Whirlpool0`, `WhirlpoolT` | 64 bytes | the final version, the 2000 original and the 2001 revision |
| `Snefru128`, `Snefru256` | 16, 32 bytes | 8 passes; `Snefru(bits, passes)` for other sizes (32 to 448 bits) and 1 to 8 passes |
| `Tiger`, `Tiger160`, `Tiger128`, `Tiger2` | 24, 20, 16, 24 bytes | `Tiger160` and `Tiger128` are prefixes of `Tiger` |
| `Streebog256`, `Streebog512` | 32, 64 bytes | GOST R 34.11-2012, RFC 6986 |
| `Blake2b512`, `Blake2b384`, `Blake2b256`, `Blake2b160`, `Blake2b128` | 64 to 16 bytes | `Blake2b(bits)` for any size from 8 to 512 bits |
| `Blake2s256`, `Blake2s224`, `Blake2s160`, `Blake2s128` | 32 to 16 bytes | `Blake2s(bits)` for any size from 8 to 256 bits |
| `Blake3` | 32 bytes, or any length | see [BLAKE3](#blake3) |
| `Crc32`, `Crc32c` | 4 bytes | checksums, not cryptographic; most significant byte first |
| `XxHash32`, `XxHash64` | 4, 8 bytes | checksums, not cryptographic; most significant byte first; `Options.seed` |

The digest sizes are compile-time parameters, so a wrong size is a compile error and digests are fixed-size arrays.

## Options

Most types have no options. The others:

```zig
// BLAKE2: key (up to 64 bytes for BLAKE2b, 32 for BLAKE2s), salt and
// personalization (up to 16 or 8 bytes each). Longer values panic.
cryptoapi.Blake2b256.hash(message, &out, .{ .key = key, .salt = salt, .context = "my-app" });

// xxHash: a seed.
cryptoapi.XxHash64.hash(message, &out8, .{ .seed = 42 });

// BLAKE3: a 32-byte key for the keyed mode.
cryptoapi.Blake3.hash(message, &out, .{ .key = key32 });
```

## Extendable output

`Shake128` and `Shake256` write as many bytes as `out` holds, and `squeeze` continues the output:

```zig
var x = cryptoapi.Shake256.init(.{});
x.update(message);
var first: [64]u8 = undefined;
x.final(&first);
var more: [1000]u8 = undefined;
x.squeeze(&more);
```

## BLAKE3

`Blake3.final` and `Blake3.hash` take an output slice of any length; 32 bytes is the standard digest. `init(.{ .key = key })` selects the keyed hash, and `initKdf(context)` the key derivation mode, where `context` is a fixed string naming the application and purpose and the key material is passed to `update`:

```zig
var kdf = cryptoapi.Blake3.initKdf("example.com 2026-11-17 session keys");
kdf.update(input_key_material);
var session_key: [32]u8 = undefined;
kdf.final(&session_key);
```

## HMAC, PBKDF2 and HKDF

These take the hash type as a compile-time parameter and accept every type above with a fixed `digest_length`, and the `std.crypto.hash` types.

```zig
// HMAC (RFC 2104). Same interface as std.crypto.auth.hmac.Hmac.
const HmacWhirlpool = cryptoapi.Hmac(cryptoapi.Whirlpool);
var tag: [HmacWhirlpool.mac_length]u8 = undefined;
HmacWhirlpool.create(&tag, message, key);

var m = HmacWhirlpool.init(key);
m.update(part1);
m.update(part2);
m.final(&tag);

// PBKDF2 (RFC 8018). Returns error.WeakParameters for 0 rounds.
var derived: [32]u8 = undefined;
try cryptoapi.pbkdf2(&derived, password, salt, 600_000, cryptoapi.Streebog256);

// HKDF (RFC 5869). Same interface as std.crypto.kdf.hkdf.Hkdf.
const H = cryptoapi.Hkdf(cryptoapi.Sm3);
const prk = H.extract(salt, input_key_material);
var okm: [42]u8 = undefined;
H.expand(&okm, "context info", prk);
```

`pbkdf2` and `Hkdf` are the `std.crypto` implementations instantiated with this module's `Hmac`, which wipes its copies of the key when it is done.

## Differences from the JavaScript API

The Zig API implements the standard algorithms only. The JavaScript hashers also accept options kept for compatibility with crypto-api 0.8.5, such as `rounds` (reduced-round variants) and arbitrary `length` values for SHA-512/t; those are not part of the Zig API, except for the Snefru pass count. There is no state export (`getState`/`setState`): copy the hasher value instead.

## Security

MD2, MD4, MD5, SHA-0, SHA-1, HAS-160 and Snefru with few passes are not collision resistant; use them only where an existing format or protocol requires them. CRC-32, CRC-32C, XXH32 and XXH64 are checksums and offer no security. No function claims constant-time execution. See [SECURITY.md](../SECURITY.md) to report a vulnerability.

## Testing

`zig build test` runs the unit tests of the algorithm cores, the tests of this API (including agreement with `std.crypto` for every algorithm both have) and the JSON test vectors in `test/vectors`, which the JavaScript tests also use. CI runs them on Linux, macOS and Windows, on 32-bit x86, and on aarch64 and s390x (big-endian) under QEMU.
