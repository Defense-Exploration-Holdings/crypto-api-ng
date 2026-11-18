# wasm ABI conventions

Target: `wasm32-freestanding`, single-threaded, no imports. Everything the module needs from the host is passed in as bytes; the module never calls out. This keeps it portable (Node, browsers, workers, Deno, Bun) and makes it trivially sandboxable.

## Memory

- Pointers and lengths are `u32` offsets/sizes into the module's linear memory.
- The host allocates with `alloc(len) -> ptr` and releases with `free(ptr, len)`. `alloc` returns `0` on failure or when `len == 0`.
- Linear memory can grow during any call that allocates. After such a call, **re-create** `Uint8Array` views from `memory.buffer`; never cache a view across calls. `Runtime.view()` in `js/index.js` always builds a fresh one.
- Copy results out (`Runtime.read`) before freeing them.

## Errors

- Fallible exports return `i32`: `0` = ok, non-zero = a `runtime.Status` code (see `src/runtime.zig`). Codes are append-only once released.
- Zig panics trap (`unreachable`), surfacing in JS as `WebAssembly.RuntimeError`. Algorithm code must validate inputs and return a `Status` instead of relying on traps.

## Versioning

- `abi_version()` returns `runtime.abi_version`. The JS loader rejects a mismatch. Bump it on any incompatible change to exports or conventions.
- Version 2: `<algo>_update`, `<algo>_blocks` and `<algo>_final` of MD4, MD5, HAS-160 and RIPEMD return an `i32` Status instead of nothing (the other families already did). Version 1 modules returned nothing and trusted `State.buffered`.

## Algorithm export shape

Settled by the MD5 port. Streaming primitives export:

```
<algo>_state_size() -> u32                  // sizeof the Zig State; JS checks it at load
<algo>_init(state)
<algo>_update(state, data, len) -> Status   // buffering + counting, like the Zig reference
<algo>_blocks(state, data, len) -> Status   // whole blocks only, hash words only; what the v1 facade calls
<algo>_final(state, out) -> Status          // pads, compresses, writes the digest, mutates state like the original finalize()
```

`state`, `data` and `out` are absolute addresses into linear memory. There is no per-hasher allocation: the facade writes the hasher's state into one shared scratch `State`, calls, and reads the result back, so wasm memory never grows and nothing needs freeing.

The 32-bit little-endian hashers other than MD5 (MD4, HAS-160, RIPEMD) share one generic implementation, `src/hash/le32.zig`, and export through `src/wasm/le32_exports.zig`. Differences from the MD5 shape: `<algo>_init(state, param)` takes one extra argument, and `State` has a `param` field (HAS-160 `rounds`; 0 elsewhere) that `<algo>_blocks` and `<algo>_final` read. Their `update`, `blocks` and `final` (and MD5's) refuse, with `Status.invalid_state` and without touching anything, a State whose `buffered` is not below 64 (it indexes the State's buffer, and `small` builds have no bounds checks), and `blocks` refuses a `len` that is not a multiple of 64 with `Status.invalid_argument`. The families with a `rounds` field (MD2, SHA-0, SHA-1, SHA-224/256, SM3, SHA-384/512, Whirlpool) refuse a `rounds` outside what the compression function supports in the same way. `State` layout, with `n` hash words: `hash` at 0, `length` (u64) at `align8(4n)`, `buffered` (u32) at `length + 8`, `param` (u32) at `length + 12`, `buf` (64 bytes) at `length + 16`. Sizes: 96 (n=4), 104 (n=5), 112 (n=8), 120 (n=10). The JS side computes the same offsets in `packages/crypto-api/src/wasm/le32.mjs` and checks `<algo>_state_size()` at load.

Snefru is the one family whose block size depends on an option (`16 - words` words, with `words` = `length / 32`), so it has its own shape in `src/hash/snefru.zig` and `src/wasm/snefru.zig`: `snefru_init(state, words, rounds)`, `snefru_update`, `snefru_blocks`, `snefru_final`, all returning a `Status` (0 ok, 1 `invalid_argument`, 3 `invalid_state`) because the State's `words`, `rounds` and `buffered` bytes are used as indices and are validated on every call. `State` is exactly 128 bytes: `hash` (15 x u32) at 0, `words` (u8) at 60, `rounds` (u8) at 61, `buffered` (u8) at 62, `length` (u32, only `ToInt32(length)` matters) at 64, `buf` (60 bytes) at 68. `snefru_final` writes `4 * words` digest bytes at the output offset and refuses `words` = 15, which the original cannot finalize either. The S-boxes (16 KiB) are computed at compile time from `src/hash/snefru_rand.zig`, which `scripts/gen-snefru-rand.mjs` generates from the vendored original.

SHA-3, SHAKE and Keccak share one sponge, `src/hash/keccak.zig`, exported by `src/wasm/keccak.zig`. The block size (`rate`, a multiple of 8 from 8 to 192) and the domain suffix byte (0x06 SHA-3, 0x1f SHAKE, 0x01 Keccak) are arguments, so the module has no per-algorithm code. `State` is 208 bytes: 25 little-endian `u64` lanes at 0, `rate` (u32) at 200, `pos` (u32, the squeeze position) at 204; JS reads and writes the lanes as 50 int32 words. There is no buffer in it: the facade keeps the unabsorbed tail of the message and passes it to `keccak_final` as a separate argument. Exports, all returning a `Status`: `keccak_init(state, rate)`, `keccak_blocks(state, data, len)` (`len` a multiple of the rate), `keccak_final(state, data, len, suffix, out, out_len)` (`len` below the rate; pads, permutes and writes the first `out_len` output bytes) and `keccak_squeeze(state, out, out_len)` (more output after `final`). The State overlaps the usual output slot, so the facade puts the tail at the input offset (+256) and the output at +512, 65280 bytes of capacity per call. `keccak_p_blocks(state, data, len, rounds)`, `keccak_p_final(state, data, len, suffix, out, out_len, rounds)` and `keccak_p_squeeze(state, out, out_len, rounds)` are the same calls with the number of rounds (1 to 24, the last rounds of Keccak-f[1600]) as the last argument; TurboSHAKE and KangarooTwelve use 12. The three without it run 24 rounds. cSHAKE, KMAC, TupleHash, ParallelHash and KangarooTwelve are put together in JavaScript from these calls; the module has no code of its own for them.

## Family modules and the scratch region

Algorithms ship in one wasm module per family (`src/wasm/<family>.zig`, names in `families` in `build.zig`), each carrying only its own code. A family root begins with `comptime { _ = @import("common.zig"); }`, which adds:

```
abi_version() / version_ptr() / version_len()
scratch_ptr() -> u32     // address of the fixed scratch region
scratch_len() -> u32     // 256 + input capacity (64 KiB)
```

Scratch layout, identical in every family (offsets from `scratch_ptr()`): algorithm `State` at +0 (up to 128 bytes), output at +128 (up to 128 bytes), input chunk at +256. A `State` larger than 128 bytes (SHA-384/512: 216, Whirlpool: 152) overlaps the output slot, so such a family tells the facade to take the digest at +256 instead (`outOff` in `createAccelerator`); `*_final` does not read the input region, and `*_blocks` only reads the head of the State. Family modules are linked with a fixed 2-page memory (`initial_memory == max_memory`), 16 KiB stack and no imports; they export no `alloc`/`free`. Only `src/wasm.zig` (the general runtime used by `js/index.js`) keeps those. Zig forbids relative imports above a module root, so family roots reach the library through `@import("core")` (`src/root.zig`).

The facades treat any non-zero status as a refusal: they have not modified `this` yet (or have applied only the whole blocks an earlier chunk of the same call completed) and give the work to the original JavaScript code, so a refused call costs speed, never a wrong or stale digest. `test/wasm-status.test.js` calls the raw exports with bad values and forces refusals in every facade.

The SHA-3/SHAKE/Keccak, BLAKE2 and BLAKE3 facades check every status too. A refused call is redone by their plain-JavaScript engine on the untouched state (the wasm side works on a copy in the scratch region, and the facade only reads it back after the last call of a sequence succeeded), and nothing is read from the output region of a refused call; BLAKE3 starts `blake3_xof` only after `blake3_root` succeeded in the same call. A state that no engine can work on (a `hash` of the wrong length or with non-integer words, a block size that is not a sponge rate, a BLAKE2 `counter` that is not a whole number of blocks, a BLAKE3 `stack` that does not match `chunks`, an empty last block or chunk after blocks or chunks were compressed) is refused before either engine runs, with a `TypeError` or `RangeError` that is the same with and without WebAssembly. `blake3_xof` cannot fail and trusts its `params`, which only the facade writes, in the same call.

Nothing a call was given stays in the module. The facade zeroes the scratch region on every way out of a call, including the fallbacks that hand the rest of the work back to the original JavaScript: the state and output slots and the input bytes it wrote (`wipe()` in `family.mjs`), after the digest string has been built. On the wasm side, the exports clear the `tail` and padding buffers of the `final` functions and, after the call, the stack area the compression frames used (`scrubStack` in `src/wasm/common.zig`, called through `@call(.never_inline, ...)` so the callee's frames lie below the export's own). `test/memory-wipe.test.js` scans the whole linear memory of every family for message bytes, HMAC pad blocks, keys and digests. The SHA-3/SHAKE/Keccak, BLAKE2 and BLAKE3 families are covered the same way, on every exit path including a refused call: the glue zeroes the State and output slots and every input-region byte it wrote (the BLAKE2 key block, the BLAKE3 key words in the State, the stack of chaining values at +256 and the data and output at +2304, the sponge tail at +256 and its output at +512, long outputs up to the largest call), after it has built the result string, and their export roots call the core through `@call(.never_inline, ...)` and `scrubStack` afterwards. `final` of BLAKE2 clears its padded last block and the copy of the chaining value, BLAKE3 clears the chunk-end and parent blocks it builds. Copies on the JavaScript side (the `Hmac` pads and saved states, the digest string) are ordinary values and cannot be wiped.

Embedded bytes for synchronous loading are written to `packages/crypto-api/wasm/<family>.mjs` by `zig build js` (gitignored). The package-internal loader is `packages/crypto-api/src/wasm/family.mjs`; its `ABI_VERSION` must equal `runtime.abi_version` (a test compares it with `js/index.js`).

## BLAKE2 and BLAKE3

These have no 0.8.5 original, so their JS hashers keep all buffering, the key block and the parameter block, and wasm only compresses. Three family modules, `blake2b`, `blake2s` and `blake3`, all returning a `Status` (0 ok, 1 `invalid_argument`).

BLAKE2 (`src/hash/blake2.zig`, `src/wasm/blake2_exports.zig`; `<p>` is `blake2b` or `blake2s`):

```
<p>_state_size() -> u32                            // 72 (blake2b) or 40 (blake2s)
<p>_blocks(state, data, len)                       // len % block == 0; none of the blocks is the final one
<p>_final(state, tail, tail_len, out)              // tail_len <= block; writes the whole 64 or 32 digest bytes to out
```

`State` is the chaining value `h` (8 words, little-endian) followed by the byte counter `t` (u64): `h` at 0, `t` at 64 (blake2b) or 32 (blake2s). `blocks` adds the block size to `t` before each block; `final` adds `tail_len` to a copy and does not modify `state`. The key, salt, personalization and digest length are in the initial `h`, which JS computes.

BLAKE3 (`src/hash/blake3.zig`, `src/wasm/blake3.zig`):

```
blake3_state_size() -> u32                         // 48
blake3_update(state, stack, data, nchunks)         // nchunks whole 1024-byte chunks into the tree
blake3_root(state, stack, tail, tail_len, params)  // tail_len <= 1024; writes the 104-byte root parameters
blake3_xof(params, seek, out, out_len)             // output bytes from output block `seek` (64 bytes per block)
```

`State` is `key` (8 words) at 0, `flags` (u32) at 32 and `chunks` (u64, chunks added so far) at 40. The `stack` argument is the chaining values of the finished subtrees, 32 bytes each, `popcount(chunks)` entries, up to 54 (1728 bytes); it does not fit the 128-byte state slot, so the JS side places it at the start of the input region (+256) and the data at +2304 (leaving 62 chunks per call). `params` (the cv, the last block, its length and flags) is written to the output slot at +128. The JS hasher holds back the last chunk, so a chunk only enters the tree when more input follows.

## Tiger, Streebog, CRC-32, xxHash, XXH3, SipHash and MurmurHash3

These have no 0.8.5 original and use the same shape as BLAKE2: the JS hashers (`src/blocks/base.mjs`) keep the buffer and hold back the last 1 to 64 (16, 32) bytes, and wasm only compresses and finishes. XXH3 holds back more: its last stripe is the last 64 bytes of the message, so once a block has been compressed the tail is 64 to 1087 bytes. Their exports are produced by the same wrapper (`exportHasherScrub` in `src/wasm/blake2_exports.zig`, which also takes the size of the stack area to clear), and all return a `Status`:

```
<p>_state_size() -> u32
<p>_blocks(state, data, len)                       // len % block == 0
<p>_final(state, tail, tail_len, out)              // tail_len <= block (XXH3: <= 1087, and >= 64 when t != 0); writes the whole digest to out
```

| Family module | `<p>` | block | digest | `State` (little-endian words) |
|---|---|---|---|---|
| `tiger` | `tiger`, `tiger2` | 64 | 24 | `t` u64 at 0, `h` 3 x u64 at 8 (32 bytes) |
| `streebog` | `streebog256`, `streebog512` | 64 | 32, 64 | `t` u64 at 0, `h` 8 x u64 at 8, `sigma` 8 x u64 at 72 (136 bytes) |
| `crc32` | `crc32`, `crc32c` | 64 | 4 | `t` u64 at 0, `crc` u32 at 8 (16 bytes) |
| `xxhash` | `xxhash32` | 16 | 4 | `t` u64 at 0, `v` 4 x u32 at 8, `seed` u32 at 24 (32 bytes) |
| `xxhash` | `xxhash64` | 32 | 8 | `t` u64 at 0, `v` 4 x u64 at 8, `seed` u64 at 40 (48 bytes) |
| `xxh3` | `xxh3`, `xxh128` | 1024 | 8, 16 | `t` u64 at 0, `acc` 8 x u64 at 8, `seed` u64 at 72 (80 bytes) |
| `siphash` | `siphash24`, `siphash13` | 8 | 8 | `t` u64 at 0, `v` 4 x u64 at 8 (40 bytes) |
| `murmur3` | `murmur3_32` | 4 | 4 | `t` u64 at 0, `h1` u32 at 8, padding (16 bytes) |
| `murmur3` | `murmur3_128` | 16 | 16 | `t` u64 at 0, `h1` u64 at 8, `h2` u64 at 16 (24 bytes) |

`t` is the number of bytes compressed so far; `blocks` adds to it and `final` works on a copy, so `state` is never modified by `final`. The JS side writes `t` and the hash words of `state.hash` (int32, the 64-bit words low half first) and reads the words back after `blocks`. Streebog's 136-byte `State` does not fit the 128-byte state slot, so its digest is written behind the input region's last block (at +320) instead of the output slot at +128. Tiger derives its S-boxes at compile time; Streebog derives its 16 KiB of combined tables from the typed-in S-box and matrix. The Streebog digest is the last 32 bytes of the final value for `streebog256`, all 64 for `streebog512`; CRC-32, xxHash, XXH3 and MurmurHash3 x86_32 write the checksum most significant byte first (XXH128: the high 64 bits first); SipHash and MurmurHash3 x64_128 write the bytes of their reference implementations (little-endian words). XXH3 derives the secret of a seed on every call, so the state holds no secret. The SipHash key only sets the initial `v` words, which the JS side computes.

## Argon2 and scrypt: growable memory

The password-hashing families need far more memory than the 64 KiB scratch region: Argon2 a table of `m` KiB, scrypt `128 r (N + p + 2)` bytes. Their modules, `argon2` and `scrypt`, are the only ones linked with growable memory (4 pages initially, up to 65535 pages) and a 64 KiB stack, and they take work memory from `memory.grow` with a bump allocator (`src/wasm/pwhash.zig`) that never frees. The JS side (`packages/crypto-api/src/wasm/pwhash.mjs`) compiles the module once and creates a new instance for every derivation, so linear memory, which cannot shrink, is released with the instance instead of staying at its largest size.

```
alloc(len) -> ptr                                  // 16-byte aligned, above the initial memory; 0 on failure or for len 0
argon2_hash(mode, t, m, p, pwd, pwd_len, salt, salt_len,
            secret, secret_len, ad, ad_len, out, out_len) -> Status
scrypt_hash(ln, r, p, pwd, pwd_len, salt, salt_len, out, out_len) -> Status
```

`mode` is 0 (Argon2d), 1 (Argon2i) or 2 (Argon2id); `m` is in KiB; `ln` is log2(N). A zero length takes no pointer (0 is fine). Both return 1 (`invalid_argument`) for parameters outside their RFC (the checks of `src/kdf/argon2.zig` and `src/kdf/scrypt.zig`) and 2 (`out_of_memory`) when memory cannot grow far enough, and write nothing in either case. The JS side gives any non-zero status, and an instance that cannot be created, to its plain-JavaScript engine.

Wiping: the cores zero the whole work memory and every local block before they return, and the exports clear the stack area the core used (`scrubStack`, 8 KiB for Argon2, 4 KiB for scrypt). The JS side zeroes every byte it handed to `alloc` (inputs and output) after reading the result, then drops the instance. `test/pwhash.test.js` checks that every byte above the initial memory is zero afterwards and that no input or output bytes remain anywhere in memory.

## Loading: async and sync

The original crypto-api is fully synchronous, so v1 needs a sync path. `js/index.js` exports `load()` (async: fetch or fs) and `loadSync(bytes)`. `js/sync.js` embeds the wasm as base64 (`zig build js` writes `js/generated/wasm-bytes.js`, which is gitignored) and instantiates on import. Browsers limit synchronous compilation on the main thread, so keep the module small (target under 64 KB).
