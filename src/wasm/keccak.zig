//! wasm root for the "keccak" family: SHA-3, SHAKE and Keccak (one State, one
//! permutation; the rate and the domain suffix come from the caller).
//! Compiled to zig-out/wasm/keccak.wasm by build.zig. Export shape: see
//! docs/abi.md. Every fallible export returns a `runtime.Status`, because the
//! rate and position in the State are used as bounds and are validated on every call.
//!
//!     keccak_state_size() -> u32
//!     keccak_init(state, rate)
//!     keccak_blocks(state, data, len)                       len % rate == 0, lanes only
//!     keccak_final(state, data, len, suffix, out, out_len)  len < rate; pad, permute, squeeze
//!     keccak_squeeze(state, out, out_len)                   more output after `final`
//!
//! The State (208 bytes) does not fit the 128-byte state slot of the scratch
//! region, so the facade places the tail at the input offset and the output
//! 256 bytes above it (`final` reads the tail before it writes the output).

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const scrubStack = @import("common.zig").scrubStack;
/// The permutation keeps its lanes in registers and the State (which the facade zeroes); no frame leaked
/// at any size in test/memory-wipe.test.js, so this is a margin.
const scrub_len = 512;
const keccak = core.keccak;
const Status = core.runtime.Status;

fn statePtr(p: u32) *keccak.State {
    return @ptrFromInt(p);
}

fn bad(st: *const keccak.State) bool {
    return !keccak.validRate(st.rate) or st.pos > st.rate;
}

export fn keccak_state_size() u32 {
    return @sizeOf(keccak.State);
}

export fn keccak_init(state: u32, rate: u32) i32 {
    if (!keccak.validRate(rate)) return @backingInt(Status.invalid_argument);
    keccak.init(statePtr(state), rate);
    return 0;
}

/// Absorb `len` bytes (a multiple of the rate) into the lanes at `state`.
export fn keccak_blocks(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (bad(st)) return @backingInt(Status.invalid_state);
    if (len % st.rate != 0) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    defer scrubStack(scrub_len);
    @call(.never_inline, keccak.blocks, .{ st, p[0..len] });
    return 0;
}

/// Absorb the `len`-byte tail (shorter than the rate), pad with `suffix`,
/// permute and write `out_len` bytes of output to `out`. Mutates the State.
export fn keccak_final(state: u32, data: u32, len: u32, suffix: u32, out: u32, out_len: u32) i32 {
    const st = statePtr(state);
    if (bad(st)) return @backingInt(Status.invalid_state);
    if (len >= st.rate or suffix < 1 or suffix > 0x7f) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    const o: [*]u8 = @ptrFromInt(out);
    defer scrubStack(scrub_len);
    @call(.never_inline, keccak.final, .{ st, p[0..len], @as(u8, @intCast(suffix)), o[0..out_len] });
    return 0;
}

/// `out_len` more output bytes, continuing a stream that `keccak_final` started.
export fn keccak_squeeze(state: u32, out: u32, out_len: u32) i32 {
    const st = statePtr(state);
    if (bad(st)) return @backingInt(Status.invalid_state);
    const o: [*]u8 = @ptrFromInt(out);
    defer scrubStack(scrub_len);
    @call(.never_inline, keccak.squeeze, .{ st, o[0..out_len] });
    return 0;
}
