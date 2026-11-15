//! wasm root for the "blake3" family. Compiled to zig-out/wasm/blake3.wasm by
//! build.zig. Export shape: see docs/abi.md.
//!
//! The JS hasher keeps the buffering and the key words, so wasm only hashes
//! chunks and produces output:
//!
//!     blake3_state_size() -> u32
//!     blake3_update(state, stack, data, nchunks) -> status
//!     blake3_root(state, stack, tail, tail_len, params) -> status
//!     blake3_xof(params, seek, out, out_len) -> status
//!
//! The stack of subtree chaining values (`blake3.Stack`, up to 1728 bytes) is a
//! separate buffer because it is larger than the 128-byte state slot of the
//! scratch region (see packages/crypto-api/src/hasher/blake3.mjs).

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const blake3 = core.blake3;
const Status = core.runtime.Status;

const invalid: i32 = @backingInt(Status.invalid_argument);

export fn blake3_state_size() u32 {
    return @sizeOf(blake3.State);
}

/// Chunk counts stay below 2^53, so the stack (54 entries) cannot overflow.
const max_chunks: u64 = 1 << 53;

fn okState(st: *const blake3.State) bool {
    return st.chunks < max_chunks;
}

/// Add `nchunks` complete chunks at `data`; updates `state.chunks` and the stack.
export fn blake3_update(state: u32, stack: u32, data: u32, nchunks: u32) i32 {
    const st: *blake3.State = @ptrFromInt(state);
    if (!okState(st) or st.chunks + nchunks >= max_chunks) return invalid;
    const p: [*]const u8 = @ptrFromInt(data);
    blake3.update(st, @ptrFromInt(stack), p[0 .. @as(usize, nchunks) * blake3.chunk_len]);
    return 0;
}

/// Write the root compression parameters of the hash that ends with `tail`
/// (1..1024 bytes; 0 only for an empty message) to `params`.
export fn blake3_root(state: u32, stack: u32, tail: u32, tail_len: u32, params: u32) i32 {
    const st: *const blake3.State = @ptrFromInt(state);
    if (!okState(st) or tail_len > blake3.chunk_len) return invalid;
    if (tail_len == 0 and st.chunks != 0) return invalid;
    const p: [*]const u8 = @ptrFromInt(tail);
    const out: *blake3.RootParams = @ptrFromInt(params);
    out.* = blake3.root(st, @ptrFromInt(stack), p[0..tail_len]);
    return 0;
}

/// Write `out_len` output bytes starting at output block `seek`.
export fn blake3_xof(params: u32, seek: u32, out: u32, out_len: u32) i32 {
    const pr: *const blake3.RootParams = @ptrFromInt(params);
    const o: [*]u8 = @ptrFromInt(out);
    blake3.xof(pr, seek, o[0..out_len]);
    return 0;
}
