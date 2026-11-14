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

## Algorithm export shape

Settled by the MD5 port (see [porting-guide.md](porting-guide.md)). Streaming primitives export:

```
<algo>_state_size() -> u32                  // sizeof the Zig State; JS checks it at load
<algo>_init(state)
<algo>_update(state, data, len)             // buffering + counting, like the Zig reference
<algo>_blocks(state, data, len)             // whole blocks only, hash words only; what the v1 facade calls
<algo>_final(state, out)                    // pads, compresses, writes the digest, mutates state like the original finalize()
```

`state`, `data` and `out` are absolute addresses into linear memory. There is no per-hasher allocation: the facade writes the hasher's state into one shared scratch `State`, calls, and reads the result back, so wasm memory never grows and nothing needs freeing.

The 32-bit little-endian hashers other than MD5 (MD4, HAS-160, RIPEMD) share one generic implementation, `src/hash/le32.zig`, and export through `src/wasm/le32_exports.zig`. Differences from the MD5 shape: `<algo>_init(state, param)` takes one extra argument, and `State` has a `param` field (HAS-160 `rounds`; 0 elsewhere) that `<algo>_blocks` and `<algo>_final` read. `State` layout, with `n` hash words: `hash` at 0, `length` (u64) at `align8(4n)`, `buffered` (u32) at `length + 8`, `param` (u32) at `length + 12`, `buf` (64 bytes) at `length + 16`. Sizes: 96 (n=4), 104 (n=5), 112 (n=8), 120 (n=10). The JS side computes the same offsets in `packages/crypto-api/src/wasm/le32.mjs` and checks `<algo>_state_size()` at load.

## Family modules and the scratch region

Algorithms ship in one wasm module per family (`src/wasm/<family>.zig`, names in `families` in `build.zig`), each carrying only its own code. A family root begins with `comptime { _ = @import("common.zig"); }`, which adds:

```
abi_version() / version_ptr() / version_len()
scratch_ptr() -> u32     // address of the fixed scratch region
scratch_len() -> u32     // 256 + input capacity (64 KiB)
```

Scratch layout, identical in every family (offsets from `scratch_ptr()`): algorithm `State` at +0 (up to 128 bytes), output at +128 (up to 128 bytes), input chunk at +256. A `State` larger than 128 bytes (SHA-384/512: 216) overlaps the output slot, so such a family tells the facade to take the digest at +256 instead (`outOff` in `createAccelerator`); `*_final` does not read the input region, and `*_blocks` only reads the head of the State. Family modules are linked with a fixed 2-page memory (`initial_memory == max_memory`), 16 KiB stack and no imports; they export no `alloc`/`free`. Only `src/wasm.zig` (the general runtime used by `js/index.js`) keeps those. Zig forbids relative imports above a module root, so family roots reach the library through `@import("core")` (`src/root.zig`).

Embedded bytes for synchronous loading are written to `packages/crypto-api/wasm/<family>.mjs` by `zig build js` (gitignored). The package-internal loader is `packages/crypto-api/src/wasm/family.mjs`; its `ABI_VERSION` must equal `runtime.abi_version` (a test compares it with `js/index.js`).

## Loading: async and sync

The original crypto-api is fully synchronous, so v1 needs a sync path. `js/index.js` exports `load()` (async: fetch or fs) and `loadSync(bytes)`. `js/sync.js` embeds the wasm as base64 (`zig build js` writes `js/generated/wasm-bytes.js`, which is gitignored) and instantiates on import. Browsers limit synchronous compilation on the main thread, so keep the module small (target under 64 KB).
