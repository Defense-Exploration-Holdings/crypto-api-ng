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

## Algorithm export shape (proposed, to be refined by the first ports)

Streaming primitives (hashes, MACs, ciphers) expose an opaque state held in wasm memory:

```
<algo>_state_size() -> u32          // bytes needed for the state
<algo>_init(state_ptr, ...) -> i32
<algo>_update(state_ptr, data_ptr, data_len) -> i32
<algo>_final(state_ptr, out_ptr, out_len) -> i32
```

One-shot helpers (`<algo>_hash(data_ptr, data_len, out_ptr)`) may be added on top. The first real port should confirm or amend this shape here.
