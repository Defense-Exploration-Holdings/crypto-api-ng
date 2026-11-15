# crypto-api-ng

[![npm](https://img.shields.io/npm/v/crypto-api-ng)](https://www.npmjs.com/package/crypto-api-ng)
[![license](https://img.shields.io/npm/l/crypto-api-ng)](LICENSE)
[![types](https://img.shields.io/npm/types/crypto-api-ng)](docs/api.md)

A hashing library for JavaScript with no dependencies: [`crypto-api`](https://github.com/nf404/crypto-api) 0.8.5 ported to Zig, with the compression functions compiled to WebAssembly.

Version 1 is a drop-in replacement for `crypto-api@0.8.5`: same classes, import paths, options, digests and `getState()` output, bugs included. Where an input or option falls outside what the WebAssembly code models exactly, or WebAssembly is unavailable, the original JavaScript runs instead, so results are identical either way. Version 1.1 fixes the 0.8.5 bugs that 1.0 keeps (see "Changes in 1.1" in the package README); algorithms the original lacks are added on top of it, starting with SHA-3.

## Install

```sh
npm install crypto-api-ng
```

## Quick start

```javascript
const CryptoApi = require('crypto-api-ng');

CryptoApi.hash('sha256', 'abc');
// 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

CryptoApi.hmac('key', 'message', CryptoApi.getHasher('md5'));
```

Runs on Node.js 18 and newer, Bun, Deno and current browsers, and falls back to plain JavaScript where WebAssembly is unavailable. TypeScript declarations are included.

The full API is in the [API reference](docs/api.md). Usage for Node.js, bundlers and browsers is in [packages/crypto-api/README.md](packages/crypto-api/README.md).

## Algorithms

HAS-160, MD2, MD4, MD5, RIPEMD-128/160/256/320, SHA-0, SHA-1, SHA-224/256, SHA-384/512, SHA-512/224, SHA-512/256, SM3, Snefru v2.0 and v2.5, Whirlpool, Whirlpool-0 and Whirlpool-T, plus HMAC and the hex, base64 and UTF-8 encoders of the original.

Added by this package, not in the original: SHA3-224/256/384/512, SHAKE128/256 and Keccak-224/256/384/512 (the pre-standard padding, as used by Ethereum).

## Compatibility

Compatibility with 0.8.5 is tested, not assumed. The original's own 286 tests run unmodified against this package, and a differential fuzzer compares both implementations across every documented option, including state round trips and the `getState()` JSON. See [docs/test-harness.md](docs/test-harness.md). The few deliberate differences are listed under "Differences from crypto-api 0.8.5" in the package README.

## Performance

Measured on Node 22 against the same public API, v1 is 3.7x to 4.1x faster than 0.8.5 on average (geometric mean over 24 algorithm variants), and no measured throughput case is slower. The SHA-384/512 family gains the most (about 15x on larger inputs), followed by Whirlpool (about 8x) and MD5 (about 6x). MD2 gains the least (about 1.2x) because its cost is a chain of dependent table lookups.

The trade-offs are size and start-up: the original JavaScript is kept as the fallback, so an import is about 1.8x to 4.3x larger after gzip, and loading a hasher costs roughly 1.5 to 3 milliseconds more at start-up. Full results, methodology and caveats are in [docs/benchmarks.md](docs/benchmarks.md).

![Speedup of v1 over 0.8.5 per algorithm](docs/benchmarks/speedup.svg)

## Building from source

You need Zig 0.17.1 (pinned in `.zig-version`; `scripts/install-zig.sh` installs it) and Node.js 22 or newer.

```sh
zig build check                   # Zig tests, then Node tests against the built WebAssembly
zig build wasm --release=small    # the shipped, size-optimized module
```

[CONTRIBUTING.md](CONTRIBUTING.md) covers the other commands, the parity tests and how to add an algorithm.

## Repository layout

```
src/hash/<algo>.zig        algorithm cores (target-agnostic, with tests)
src/wasm/<family>.zig      WebAssembly exports, one module per algorithm family
js/                        loader for the WebAssembly modules
packages/crypto-api/       the npm package: JavaScript facades and the original 0.8.5 code
test/                      Node tests, parity harness against the original
bench/                     benchmark suite
docs/                      ABI, porting guide, test harness, benchmark results
```

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2015 nf404 (the original `crypto-api`) and (c) 2026 Defense Exploration Holdings LLC (the Zig/WebAssembly port). The WebAssembly modules are built with Zig's standard library, which is MIT-licensed.
