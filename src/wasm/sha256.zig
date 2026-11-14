//! wasm root for the "sha256" family: SHA-224 and SHA-256 (the same State and
//! code; `length` only picks the IV in `sha256_init`, and the JS facade takes a
//! 28-byte prefix of the 32-byte output for SHA-224). Compiled to
//! zig-out/wasm/sha256.wasm by build.zig. Export shape: see src/wasm/md.zig and
//! docs/porting-guide.md. `*_blocks` and `*_final` return a `runtime.Status`
//! (non-zero when `rounds` is outside 1..64, which the JS facade never sends).

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const sha256 = core.sha256;
const Status = core.runtime.Status;

fn statePtr(p: u32) *sha256.State {
    return @ptrFromInt(p);
}

fn okRounds(st: *const sha256.State) bool {
    return st.rounds >= 1 and st.rounds <= sha256.max_rounds;
}

export fn sha256_state_size() u32 {
    return @sizeOf(sha256.State);
}

/// `length` is the original's option: 224 selects the SHA-224 IV, anything else SHA-256.
export fn sha256_init(state: u32, length: u32, rounds: u32) i32 {
    if (rounds < 1 or rounds > sha256.max_rounds) return @intFromEnum(Status.invalid_argument);
    sha256.init(statePtr(state), length, rounds);
    return 0;
}

export fn sha256_update(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st)) return @intFromEnum(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    sha256.update(st, p[0..len]);
    return 0;
}

/// Compress `len` bytes (a multiple of 64) into the hash words at `state`.
export fn sha256_blocks(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st) or len % sha256.block_len != 0) return @intFromEnum(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    sha256.blocks(st, p[0..len]);
    return 0;
}

/// Writes all 32 bytes of the hash words to `out`.
export fn sha256_final(state: u32, out: u32) i32 {
    const st = statePtr(state);
    if (!okRounds(st) or st.buffered >= sha256.block_len) return @intFromEnum(Status.invalid_argument);
    sha256.final(st, @ptrFromInt(out));
    return 0;
}
