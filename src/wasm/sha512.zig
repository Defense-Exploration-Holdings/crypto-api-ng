//! wasm root for the "sha512" family: SHA-384, SHA-512, SHA-512/224 and
//! SHA-512/256 (one State and one compression; the IV is chosen by
//! `sha512_init` or written by the JS facade, which takes a prefix of the 64
//! output bytes). Compiled to zig-out/wasm/sha512.wasm by build.zig. Export
//! shape: see src/wasm/md.zig and docs/abi.md. `*_blocks` and
//! `*_final` return a `runtime.Status` (non-zero when `rounds` is outside
//! 1..160, which the JS facade never sends).
//!
//! The State (216 bytes) does not fit the 128-byte state slot of the scratch
//! region, so unlike the other families the facade passes `out` at the input
//! offset (`final` does not read the input region). See `src/hash/sha512.zig`.

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const scrubStack = @import("common.zig").scrubStack;
const sha512 = core.sha512;
const Status = core.runtime.Status;

fn statePtr(p: u32) *sha512.State {
    return @ptrFromInt(p);
}

fn okRounds(st: *const sha512.State) bool {
    return st.rounds >= 1 and st.rounds <= sha512.max_rounds;
}

export fn sha512_state_size() u32 {
    return @sizeOf(sha512.State);
}

/// `length` selects the IV for 384, 224 and 256; anything else gets the SHA-512 IV.
export fn sha512_init(state: u32, length: u32, rounds: u32) i32 {
    if (rounds < 1 or rounds > sha512.max_rounds) return @backingInt(Status.invalid_argument);
    sha512.init(statePtr(state), length, rounds);
    return 0;
}

export fn sha512_update(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st) or st.buffered >= sha512.block_len) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    defer scrubStack(1024);
    @call(.never_inline, sha512.update, .{ st, p[0..len] });
    return 0;
}

/// Compress `len` bytes (a multiple of 128) into the hash words at `state`.
export fn sha512_blocks(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st) or len % sha512.block_len != 0) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    defer scrubStack(1024);
    @call(.never_inline, sha512.blocks, .{ st, p[0..len] });
    return 0;
}

/// Writes all 64 bytes of the hash words to `out`.
export fn sha512_final(state: u32, out: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st) or st.buffered >= sha512.block_len) return @backingInt(Status.invalid_argument);
    defer scrubStack(1024);
    @call(.never_inline, sha512.final, .{ st, @as(*[sha512.digest_len]u8, @ptrFromInt(out)) });
    return 0;
}
