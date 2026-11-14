//! Export wrappers shared by the 32-bit little-endian hashers (MD4, HAS-160,
//! RIPEMD). MD5 writes its five wrappers out by hand in `md.zig`; this does the
//! same for any `le32.Hasher(...)` type:
//!
//!     <prefix>_state_size() -> u32
//!     <prefix>_init(state, param)
//!     <prefix>_update(state, data, len)
//!     <prefix>_blocks(state, data, len)   whole blocks only, hash words only (reads State.param)
//!     <prefix>_final(state, out)
//!
//! `state`, `data` and `out` are absolute addresses in the family module's
//! scratch region (common.zig). A family root calls `exportHasher` from a
//! `comptime` block.

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
        fn update(state: u32, data: u32, len: u32) callconv(.c) void {
            const p: [*]const u8 = @ptrFromInt(data);
            Core.update(statePtr(state), p[0..len]);
        }
        fn blocks(state: u32, data: u32, len: u32) callconv(.c) void {
            const p: [*]const u8 = @ptrFromInt(data);
            Core.blocks(statePtr(state), p[0..len]);
        }
        fn final(state: u32, out: u32) callconv(.c) void {
            Core.final(statePtr(state), @ptrFromInt(out));
        }
    };
    @export(&W.stateSize, .{ .name = prefix ++ "_state_size" });
    @export(&W.init, .{ .name = prefix ++ "_init" });
    @export(&W.update, .{ .name = prefix ++ "_update" });
    @export(&W.blocks, .{ .name = prefix ++ "_blocks" });
    @export(&W.final, .{ .name = prefix ++ "_final" });
}
