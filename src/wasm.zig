//! wasm32 export surface. Only this file (and files it imports) is compiled
//! into crypto-api.wasm, so exports are explicit and reviewable.
//!
//! Conventions (details in docs/abi.md):
//!   * all pointers are u32 offsets into linear memory
//!   * JS allocates input/output buffers with `alloc`, releases them with `free`
//!   * fallible exports return a `runtime.Status` as i32

const std = @import("std");
const runtime = @import("root.zig").runtime;

const allocator = std.heap.wasm_allocator;

// ---- module metadata -----------------------------------------------------

export fn abi_version() u32 {
    return runtime.abi_version;
}

/// Returns a pointer to the NUL-free version string; length from `version_len`.
export fn version_ptr() [*]const u8 {
    return runtime.version.ptr;
}

export fn version_len() u32 {
    return runtime.version.len;
}

// ---- memory management ---------------------------------------------------

/// Allocate `len` bytes. Returns 0 on failure (or when len == 0).
export fn alloc(len: u32) u32 {
    if (len == 0) return 0;
    const buf = allocator.alloc(u8, len) catch return 0;
    return @intFromPtr(buf.ptr);
}

/// Release a buffer previously returned by `alloc` with the same `len`.
export fn free(ptr: u32, len: u32) void {
    if (ptr == 0 or len == 0) return;
    const p: [*]u8 = @ptrFromInt(ptr);
    allocator.free(p[0..len]);
}

// ---- smoke-test export ---------------------------------------------------
// Proves the JS <-> wasm buffer plumbing end to end without any algorithm.
// Removed or replaced once the first real algorithm lands.

/// XOR-fold of `len` bytes at `ptr`. Returns the 8-bit result in the low byte.
export fn smoke_xor(ptr: u32, len: u32) u32 {
    if (len == 0) return 0;
    const p: [*]const u8 = @ptrFromInt(ptr);
    var acc: u8 = 0;
    for (p[0..len]) |byte| acc ^= byte;
    return acc;
}
