//! wasm root for the "sm3" family. Compiled to zig-out/wasm/sm3.wasm by
//! build.zig. Export shape: see src/wasm/md.zig and docs/porting-guide.md.
//! `*_blocks` and `*_final` return a `runtime.Status` (non-zero when `rounds`
//! is outside 1..64, which the JS facade never sends).

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const sm3 = core.sm3;
const Status = core.runtime.Status;

fn statePtr(p: u32) *sm3.State {
    return @ptrFromInt(p);
}

fn okRounds(st: *const sm3.State) bool {
    return st.rounds >= 1 and st.rounds <= sm3.max_rounds;
}

export fn sm3_state_size() u32 {
    return @sizeOf(sm3.State);
}

export fn sm3_init(state: u32, rounds: u32) i32 {
    if (rounds < 1 or rounds > sm3.max_rounds) return @backingInt(Status.invalid_argument);
    sm3.init(statePtr(state), rounds);
    return 0;
}

export fn sm3_update(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st)) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    sm3.update(st, p[0..len]);
    return 0;
}

/// Compress `len` bytes (a multiple of 64) into the hash words at `state`.
export fn sm3_blocks(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st) or len % sm3.block_len != 0) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    sm3.blocks(st, p[0..len]);
    return 0;
}

export fn sm3_final(state: u32, out: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st) or st.buffered >= sm3.block_len) return @backingInt(Status.invalid_argument);
    sm3.final(st, @ptrFromInt(out));
    return 0;
}
