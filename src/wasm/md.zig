//! wasm root for the "md" family (MD4 and MD5; MD2 has its own root). Compiled to zig-out/wasm/md.wasm by build.zig.
//!
//! Export shape (see docs/abi.md):
//!
//!     <algo>_state_size() -> u32
//!     <algo>_init(state_ptr)
//!     <algo>_update(state_ptr, data_ptr, len) -> Status
//!     <algo>_blocks(state_ptr, data_ptr, len) -> Status   whole blocks only, hash words only
//!     <algo>_final(state_ptr, out_ptr) -> Status
//!
//! `update`, `blocks` and `final` return a `runtime.Status`: non-zero, with
//! nothing touched, when `State.buffered` is not below the block size (it
//! indexes the State's buffer) or, for `blocks`, when `len` is not a multiple
//! of the block size. The JS facade never sends such values.
//!
//! There is no allocation. The facade writes the hasher's current state and an
//! input chunk into the scratch region from common.zig, calls, and reads the
//! new hash words (and digest) back.

comptime {
    _ = @import("common.zig");
    @import("le32_exports.zig").exportHasher("md4", @import("core").md4);
}

const md5 = @import("core").md5;
const Status = @import("core").runtime.Status;
const scrubStack = @import("common.zig").scrubStack;

fn statePtr(p: u32) *md5.State {
    return @ptrFromInt(p);
}

export fn md5_state_size() u32 {
    return @sizeOf(md5.State);
}

export fn md5_init(state: u32) void {
    md5.init(statePtr(state));
}

export fn md5_update(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (st.buffered >= md5.block_len) return @backingInt(Status.invalid_state);
    const p: [*]const u8 = @ptrFromInt(data);
    defer scrubStack(1024);
    @call(.never_inline, md5.update, .{ st, p[0..len] });
    return 0;
}

/// Compress `len` bytes (a multiple of 64) into the four hash words at
/// `state` (offset 0 of the State), ignoring the rest of the state.
export fn md5_blocks(state: u32, data: u32, len: u32) i32 {
    if (len % md5.block_len != 0) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    defer scrubStack(1024);
    @call(.never_inline, md5.blocks, .{ &statePtr(state).hash, p[0..len] });
    return 0;
}

export fn md5_final(state: u32, out: u32) i32 {
    const st = statePtr(state);
    if (st.buffered >= md5.block_len) return @backingInt(Status.invalid_state);
    defer scrubStack(1024);
    @call(.never_inline, md5.final, .{ st, @as(*[md5.digest_len]u8, @ptrFromInt(out)) });
    return 0;
}
