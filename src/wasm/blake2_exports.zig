//! Export wrappers shared by BLAKE2b and BLAKE2s (see `src/hash/blake2.zig`):
//!
//!     <prefix>_state_size() -> u32
//!     <prefix>_blocks(state, data, len) -> status    len % block == 0, none final
//!     <prefix>_final(state, tail, tail_len, out) -> status    out gets the whole digest_len bytes
//!
//! A family root calls `exportHasher` from a `comptime` block.

const Status = @import("core").runtime.Status;
const scrubStack = @import("common.zig").scrubStack;
/// Twice the stack the deepest frame leaves (about 576 bytes), measured with test/memory-wipe.test.js.
const scrub_len = 1280;

pub fn exportHasher(comptime prefix: []const u8, comptime Core: type) void {
    const invalid: i32 = @backingInt(Status.invalid_argument);
    const W = struct {
        fn stateSize() callconv(.c) u32 {
            return @sizeOf(Core.State);
        }
        fn blocks(state: u32, data: u32, len: u32) callconv(.c) i32 {
            if (len % Core.block_len != 0) return invalid;
            const st: *Core.State = @ptrFromInt(state);
            const p: [*]const u8 = @ptrFromInt(data);
            defer scrubStack(scrub_len);
            @call(.never_inline, Core.blocks, .{ st, p[0..len] });
            return 0;
        }
        fn final(state: u32, tail: u32, tail_len: u32, out: u32) callconv(.c) i32 {
            if (tail_len > Core.block_len) return invalid;
            const st: *const Core.State = @ptrFromInt(state);
            const p: [*]const u8 = @ptrFromInt(tail);
            defer scrubStack(scrub_len);
            @call(.never_inline, Core.final, .{ st, p[0..tail_len], @as(*[Core.digest_len]u8, @ptrFromInt(out)) });
            return 0;
        }
    };
    @export(&W.stateSize, .{ .name = prefix ++ "_state_size" });
    @export(&W.blocks, .{ .name = prefix ++ "_blocks" });
    @export(&W.final, .{ .name = prefix ++ "_final" });
}
