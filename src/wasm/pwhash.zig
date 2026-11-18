//! Memory for the password-hashing families (`argon2`, `scrypt`): a bump
//! allocator over `memory.grow`. These modules are the only ones whose linear
//! memory grows (build.zig links them with a large `max_memory`). The JS side
//! instantiates a fresh module for every derivation and drops it afterwards, so
//! nothing is ever freed here and the memory goes away with the instance.
//!
//! Every byte handed out lies above the memory size at instantiation, past the
//! stack, the data and the scratch region of `common.zig`.

const page = 64 * 1024;

var top: u64 = 0;

/// `len` bytes aligned to 16, or null when memory cannot grow that far.
pub fn grab(len: usize) ?[*]u8 {
    if (top == 0) top = @as(u64, @wasmMemorySize(0)) * page;
    const start = (top + 15) & ~@as(u64, 15);
    const end = start + len;
    // Keep every address and the end itself representable in a u32.
    if (end > 0xFFFF_0000) return null;
    const have = @as(u64, @wasmMemorySize(0)) * page;
    if (end > have) {
        const pages: u32 = @intCast((end - have + page - 1) / page);
        if (@wasmMemoryGrow(0, pages) < 0) return null;
    }
    top = end;
    return @ptrFromInt(@as(usize, @intCast(start)));
}

/// The `alloc` export of both families: `len` bytes for inputs and outputs,
/// 0 on failure or for `len == 0`.
pub fn alloc(len: u32) callconv(.c) u32 {
    if (len == 0) return 0;
    const p = grab(len) orelse return 0;
    return @intFromPtr(p);
}
