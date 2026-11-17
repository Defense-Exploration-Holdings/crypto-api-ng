# crypto-api-ng

[![npm](https://img.shields.io/npm/v/crypto-api-ng)](https://www.npmjs.com/package/crypto-api-ng)
[![license](https://img.shields.io/npm/l/crypto-api-ng)](LICENSE)
[![types](https://img.shields.io/npm/types/crypto-api-ng)](docs/api.md)
[![JSR](https://jsr.io/badges/@defense-exploration/crypto-api-ng)](https://jsr.io/@defense-exploration/crypto-api-ng)

A hashing library for JavaScript with no dependencies: [`crypto-api`](https://github.com/nf404/crypto-api) 0.8.5 ported to Zig, with the compression functions compiled to WebAssembly. The same Zig code is also a native [Zig package](#zig-package).

Version 1 is a drop-in replacement for `crypto-api@0.8.5`: same classes, import paths, options, digests and `getState()` output, bugs included. Where an input or option falls outside what the WebAssembly code models exactly, or WebAssembly is unavailable, the original JavaScript runs instead, so results are identical either way. Version 1.1 fixes the 0.8.5 bugs that 1.0 keeps (see "Changes in 1.1" in the package README); algorithms the original lacks are added on top of it, starting with SHA-3.

## Install

```sh
npm install crypto-api-ng
```

On Deno, from [JSR](https://jsr.io/@defense-exploration/crypto-api-ng):

```sh
deno add jsr:@defense-exploration/crypto-api-ng
```

## Quick start

```javascript
const CryptoApi = require('crypto-api-ng');

CryptoApi.hash('sha256', 'abc');
// 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

CryptoApi.hmac('key', 'message', CryptoApi.getHasher('md5'));

CryptoApi.hashBytes('sha256', new Uint8Array([1, 2, 3]));   // Uint8Array(32), bytes in and out
```

Runs on Node.js 18 and newer, Bun 1.1 and newer, Deno 2 and newer, and current browsers, and falls back to plain JavaScript where WebAssembly is unavailable. TypeScript declarations are included.

The full API is in the [API reference](docs/api.md). Usage for Node.js, bundlers and browsers is in [packages/crypto-api/README.md](packages/crypto-api/README.md).

## Algorithms

HAS-160, MD2, MD4, MD5, RIPEMD-128/160/256/320, SHA-0, SHA-1, SHA-224/256, SHA-384/512, SHA-512/224, SHA-512/256, SM3, Snefru v2.0 and v2.5, Whirlpool, Whirlpool-0 and Whirlpool-T, plus HMAC and the hex, base64 and UTF-8 encoders of the original.

Added by this package, not in the original: SHA3-224/256/384/512, SHAKE128/256 and Keccak-224/256/384/512 (the pre-standard padding, as used by Ethereum), BLAKE2b and BLAKE2s (any digest length, keyed, salted, personalized) and BLAKE3 (keyed hash, key derivation, extendable output), Tiger and Tiger2, Streebog (GOST R 34.11-2012, 256 and 512 bits), and the non-cryptographic checksums CRC-32, CRC-32C, XXH32 and XXH64. They have no 0.8.5 behavior to match, and run in plain JavaScript where WebAssembly is unavailable.

## Zig package

The algorithms are written in Zig, and the repository is also a Zig package with a native API in the style of `std.crypto.hash`. It needs Zig 0.17.1. Add it to a project:

```sh
zig fetch --save git+https://github.com/Defense-Exploration-Holdings/crypto-api-ng#v1.3.0
```

Then import the module in `build.zig`:

```zig
const crypto_api_ng = b.dependency("crypto_api_ng", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("crypto_api_ng", crypto_api_ng.module("crypto_api_ng"));
```

And use it:

```zig
const cryptoapi = @import("crypto_api_ng");

var h = cryptoapi.Whirlpool.init(.{});
h.update("The quick brown fox ");
h.update("jumps over the lazy dog");
var digest: [cryptoapi.Whirlpool.digest_length]u8 = undefined;
h.final(&digest);

var ripemd: [20]u8 = undefined;
cryptoapi.Ripemd160.hash("abc", &ripemd, .{});

var mac: [32]u8 = undefined;
cryptoapi.Hmac(cryptoapi.Streebog256).create(&mac, "message", "key");

var key: [32]u8 = undefined;
try cryptoapi.pbkdf2(&key, "password", "salt", 600_000, cryptoapi.Sm3);
```

Zig's standard library already has MD5, SHA-1, SHA-2, SHA-3, Keccak, BLAKE2, BLAKE3, CRC-32 and xxHash. This package adds hash functions it does not have: MD2, MD4, SHA-0, RIPEMD-128/160/256/320, HAS-160, SM3, Whirlpool (with Whirlpool-0 and Whirlpool-T), Snefru, Tiger and Tiger2, and Streebog. Every type has the same interface (`init`, `update`, `final`, `finalResult`, `hash`, `digest_length`, `block_length`), so `Hmac`, `pbkdf2` and `Hkdf` work with all of them, and with code written for `std.crypto` hashes. The algorithms `std` has are included as well, so a project can use one API for all of them, and their outputs are tested against `std`.

The full list of types and options is in [docs/zig.md](docs/zig.md), and [examples/zig](examples/zig) is a complete project that uses the package. The tests run with `zig build test` on Linux, macOS and Windows, on 32-bit x86 and on a big-endian target (s390x), against the same JSON test vectors as the JavaScript tests.

## Compatibility

Compatibility with 0.8.5 is tested, not assumed. The original's own 286 tests run unmodified against this package, and a differential fuzzer compares both implementations across every documented option, including state round trips and the `getState()` JSON. See [docs/test-harness.md](docs/test-harness.md). The few deliberate differences are listed under "Differences from crypto-api 0.8.5" in the package README.

## Security

Several algorithms are provided for compatibility and are not collision resistant, and the library does not claim constant-time execution. See "Security notes" in the [package README](packages/crypto-api/README.md) and [SECURITY.md](SECURITY.md), which also explains how to report a vulnerability.

## Performance

Measured on Node 22 against the same public API, v1 is 3.7x to 4.1x faster than 0.8.5 on average (geometric mean over 24 algorithm variants), and no measured throughput case is slower. The SHA-384/512 family gains the most (about 15x on larger inputs), followed by Whirlpool (about 8x) and MD5 (about 6x). MD2 gains the least (about 1.2x) because its cost is a chain of dependent table lookups.

The trade-offs are size and start-up: the original JavaScript is kept as the fallback, so an import is about 1.8x to 4.3x larger after gzip, and loading a hasher costs roughly 1.5 to 3 milliseconds more at start-up. Full results, methodology and caveats are in [docs/benchmarks.md](docs/benchmarks.md).

![Speedup of v1 over 0.8.5 per algorithm](docs/benchmarks/speedup.svg)

## Building from source

You need Zig 0.17.1 (pinned in `.zig-version`; `scripts/install-zig.sh` installs it) and Node.js 22 or newer.

```sh
zig build check                   # Zig tests, then Node tests against the built WebAssembly
zig build test                    # only the Zig tests (no Node.js needed)
zig build wasm --release=small    # the shipped, size-optimized module
```

[CONTRIBUTING.md](CONTRIBUTING.md) covers the other commands, the parity tests and how to add an algorithm.

## Repository layout

```
src/lib.zig                the public Zig API (the `crypto_api_ng` module)
src/hash/<algo>.zig        algorithm cores (target-agnostic, with tests)
src/wasm/<family>.zig      WebAssembly exports, one module per algorithm family
js/                        loader for the WebAssembly modules
packages/crypto-api/       the npm package: JavaScript facades and the original 0.8.5 code
test/                      Node tests, parity harness against the original
bench/                     benchmark suite
examples/zig/              a Zig project that depends on the package
docs/                      ABI, porting guide, test harness, benchmark results
```

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2015 nf404 (the original `crypto-api`) and (c) 2026 Defense Exploration Holdings LLC (the Zig/WebAssembly port). The WebAssembly modules are built with Zig's standard library, which is MIT-licensed.
