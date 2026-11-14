//! wasm root for the "md" family (MD5 and MD4 now; MD2 joins in a later work
//! package). Compiled to zig-out/wasm/md.wasm by build.zig.
//!
//! Export shape (see docs/abi.md and docs/porting-guide.md):
//!
//!     <algo>_state_size() -> u32
//!     <algo>_init(state_ptr)
//!     <algo>_update(state_ptr, data_ptr, len)
//!     <algo>_blocks(state_ptr, data_ptr, len)   whole blocks only, hash words only
//!     <algo>_final(state_ptr, out_ptr)
//!
//! There is no allocation. The facade writes the hasher's current state and an
//! input chunk into the scratch region from common.zig, calls, and reads the
//! new hash words (and digest) back.

comptime {
    _ = @import("common.zig");
    @import("le32_exports.zig").exportHasher("md4", @import("core").md4);
}

const md5 = @import("core").md5;

fn statePtr(p: u32) *md5.State {
    return @ptrFromInt(p);
}

export fn md5_state_size() u32 {
    return @sizeOf(md5.State);
}

export fn md5_init(state: u32) void {
    md5.init(statePtr(state));
}

export fn md5_update(state: u32, data: u32, len: u32) void {
    const p: [*]const u8 = @ptrFromInt(data);
    md5.update(statePtr(state), p[0..len]);
}

/// Compress `len` bytes (a multiple of 64) into the four hash words at
/// `state` (offset 0 of the State), ignoring the rest of the state.
export fn md5_blocks(state: u32, data: u32, len: u32) void {
    const p: [*]const u8 = @ptrFromInt(data);
    md5.blocks(&statePtr(state).hash, p[0..len]);
}

export fn md5_final(state: u32, out: u32) void {
    md5.final(statePtr(state), @ptrFromInt(out));
}
