//! Exports every family wasm module carries: ABI/version metadata and the
//! scratch region used for allocation-free calls. `src/wasm.zig` (the general
//! module) keeps its own copies plus `alloc`/`free`.
//!
//! A family root (`src/wasm/<family>.zig`) must start with
//!
//!     comptime { _ = @import("common.zig"); }
//!
//! so these exports are linked in.

const std = @import("std");

const runtime = @import("core").runtime;

/// Fixed scratch region that the JS facade fills and drains. Layout (offsets
/// from `scratch_ptr()`), identical for every family:
///
///     [0, 128)        algorithm state (copied in before a call, out after)
///     [128, 256)      output (digests; up to 128 bytes)
///     [256, 256+cap)  input chunk, cap = scratch_len() - 256
///
/// Memory never grows after instantiation (max_memory == initial_memory in
/// build.zig), so JS may cache one `Uint8Array` over the whole buffer.
pub const state_off = 0;
pub const out_off = 128;
pub const input_off = 256;
pub const input_cap = 64 * 1024;

var scratch: [input_off + input_cap]u8 align(16) = undefined;

/// Overwrite the stack area the callee's frames just used. The compression
/// functions keep message words and working variables in their frames, which are
/// dead but still readable after the call returns. Export wrappers `defer` this
/// around each call that touches message bytes or hash words, so that nothing of
/// them stays in linear memory after the call.
///
/// `release_len` is how many bytes below the caller to clear in release builds
/// (twice what the deepest frame of the family needs, measured with
/// test/memory-wipe.test.js); a debug build keeps every local in memory and
/// clears 12 KiB. Call it from the export function itself, after the callee
/// returned through `@call(.never_inline, ...)`, so that the callee's frames lie
/// in the area this function's frame covers.
pub noinline fn scrubStack(comptime release_len: usize) void {
    const len = if (@import("builtin").mode == .debug) 12 * 1024 else release_len;
    var pad: [len]u8 = undefined;
    std.crypto.secureZero(u8, &pad);
}

export fn abi_version() u32 {
    return runtime.abi_version;
}

export fn version_ptr() [*]const u8 {
    return runtime.version.ptr;
}

export fn version_len() u32 {
    return runtime.version.len;
}

export fn scratch_ptr() u32 {
    return @intFromPtr(&scratch);
}

export fn scratch_len() u32 {
    return scratch.len;
}
