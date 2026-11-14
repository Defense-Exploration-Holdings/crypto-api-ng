//! Exports every family wasm module carries: ABI/version metadata and the
//! scratch region used for allocation-free calls. `src/wasm.zig` (the general
//! module) keeps its own copies plus `alloc`/`free`.
//!
//! A family root (`src/wasm/<family>.zig`) must start with
//!
//!     comptime { _ = @import("common.zig"); }
//!
//! so these exports are linked in.

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
