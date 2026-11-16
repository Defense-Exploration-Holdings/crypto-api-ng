//! Export wrappers shared by the 32-bit little-endian hashers (MD4, HAS-160,
//! RIPEMD). MD5 writes its five wrappers out by hand in `md.zig`; this does the
//! same for any `le32.Hasher(...)` type:
//!
//!     <prefix>_state_size() -> u32
//!     <prefix>_init(state, param)
//!     <prefix>_update(state, data, len) -> Status
//!     <prefix>_blocks(state, data, len) -> Status   whole blocks only, hash words only (reads State.param)
//!     <prefix>_final(state, out) -> Status
//!
//! `update`, `blocks` and `final` return a `runtime.Status`: non-zero, with
//! nothing touched, when `State.buffered` is not below the block size (it
//! indexes the State's buffer) or, for `blocks`, when `len` is not a multiple
//! of the block size. The JS facade never sends such values.
//!
//! `state`, `data` and `out` are absolute addresses in the family module's
//! scratch region (common.zig). A family root calls `exportHasher` from a
//! `comptime` block.

const Status = @import("core").runtime.Status;
const scrubStack = @import("common.zig").scrubStack;

const block_len = @import("core").le32.block_len;

pub fn exportHasher(comptime prefix: []const u8, comptime Core: type) void {
    const W = struct {
        fn statePtr(p: u32) *Core.State {
            return @ptrFromInt(p);
        }
        fn stateSize() callconv(.c) u32 {
            return @sizeOf(Core.State);
        }
        fn init(state: u32, param: u32) callconv(.c) void {
            Core.init(statePtr(state), param);
        }
        fn update(state: u32, data: u32, len: u32) callconv(.c) i32 {
            const st = statePtr(state);
            if (st.buffered >= block_len) return @backingInt(Status.invalid_state);
            const p: [*]const u8 = @ptrFromInt(data);
            defer scrubStack(1024);
            @call(.never_inline, Core.update, .{ st, p[0..len] });
            return 0;
        }
        fn blocks(state: u32, data: u32, len: u32) callconv(.c) i32 {
            if (len % block_len != 0) return @backingInt(Status.invalid_argument);
            const p: [*]const u8 = @ptrFromInt(data);
            defer scrubStack(1024);
            @call(.never_inline, Core.blocks, .{ statePtr(state), p[0..len] });
            return 0;
        }
        fn final(state: u32, out: u32) callconv(.c) i32 {
            const st = statePtr(state);
            if (st.buffered >= block_len) return @backingInt(Status.invalid_state);
            defer scrubStack(1024);
            @call(.never_inline, Core.final, .{ st, @as(*[Core.digest_len]u8, @ptrFromInt(out)) });
            return 0;
        }
    };
    @export(&W.stateSize, .{ .name = prefix ++ "_state_size" });
    @export(&W.init, .{ .name = prefix ++ "_init" });
    @export(&W.update, .{ .name = prefix ++ "_update" });
    @export(&W.blocks, .{ .name = prefix ++ "_blocks" });
    @export(&W.final, .{ .name = prefix ++ "_final" });
}
