//! wasm root for the "snefru" family. Compiled to zig-out/wasm/snefru.wasm by
//! build.zig. Export shape (see docs/abi.md):
//!
//!     snefru_state_size() -> u32
//!     snefru_init(state, words, rounds) -> Status
//!     snefru_update(state, data, len) -> Status
//!     snefru_blocks(state, data, len) -> Status   whole blocks only, hash words only
//!     snefru_final(state, out) -> Status          writes 4 * words digest bytes
//!
//! The block size depends on the digest length (`16 - words` words), so, unlike
//! the fixed-size families, every call that reads a State validates it first
//! and returns `Status.invalid_argument` rather than indexing out of range
//! (bounds checks are off in `small` builds).

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const snefru = core.snefru;
const Status = core.runtime.Status;

fn statePtr(p: u32) *snefru.State {
    return @ptrFromInt(p);
}

fn status(s: Status) i32 {
    return @backingInt(s);
}

export fn snefru_state_size() u32 {
    return @sizeOf(snefru.State);
}

export fn snefru_init(state: u32, words: u32, rounds: u32) i32 {
    if (words < 1 or words > snefru.max_words or rounds < 1 or rounds > snefru.max_rounds) {
        return status(.invalid_argument);
    }
    snefru.init(statePtr(state), @intCast(words), @intCast(rounds));
    return status(.ok);
}

export fn snefru_update(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!st.valid()) return status(.invalid_state);
    const p: [*]const u8 = @ptrFromInt(data);
    snefru.update(st, p[0..len]);
    return status(.ok);
}

/// Compress `len` bytes (a multiple of the block size) into the hash words at
/// offset 0 of the State; nothing else in the State is touched.
export fn snefru_blocks(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!st.valid()) return status(.invalid_state);
    if (len % st.blockLen() != 0) return status(.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    snefru.blocks(st, p[0..len]);
    return status(.ok);
}

/// Pad, compress the last block(s) and write `4 * words` bytes to `out`.
/// Refuses `words` = 15, which the original cannot finalize either.
export fn snefru_final(state: u32, out: u32) i32 {
    const st = statePtr(state);
    if (!st.valid() or st.words > 14) return status(.invalid_state);
    const p: [*]u8 = @ptrFromInt(out);
    snefru.final(st, p[0 .. 4 * @as(usize, st.words)]);
    return status(.ok);
}
