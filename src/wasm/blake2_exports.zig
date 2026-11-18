//! Export wrappers shared by BLAKE2b and BLAKE2s (see `src/hash/blake2.zig`), and by every
//! other hasher whose core has the same shape (Tiger, Streebog, CRC-32, xxHash, XXH3, SipHash,
//! MurmurHash3): a `State`, `block_len`, `digest_len`, `blocks(*State, data)` and
//! `final(*const State, tail, *[digest_len]u8)`.
//!
//!     <prefix>_state_size() -> u32
//!     <prefix>_blocks(state, data, len) -> status    len % block == 0, none final
//!     <prefix>_final(state, tail, tail_len, out) -> status    out gets the whole digest_len bytes
//!
//! A core whose last stripe reaches back into the previous block (XXH3) declares `keep_len`
//! and `tail_max`: once `state.t` is not 0 the tail must hold at least `keep_len` bytes, and it
//! may hold up to `tail_max` (default `block_len`).
//!
//! A family root calls `exportHasher` from a `comptime` block.

const Status = @import("core").runtime.Status;
const scrubStack = @import("common.zig").scrubStack;
/// Twice the stack the deepest BLAKE2 frame leaves (about 576 bytes), measured with test/memory-wipe.test.js.
const default_scrub_len = 1280;

pub fn exportHasher(comptime prefix: []const u8, comptime Core: type) void {
    exportHasherScrub(prefix, Core, default_scrub_len);
}

/// Like `exportHasher`, for a core whose frames are bigger: `scrub_len` is how many bytes of
/// stack `scrubStack` clears after each call in release builds.
pub fn exportHasherScrub(comptime prefix: []const u8, comptime Core: type, comptime scrub_len: usize) void {
    const invalid: i32 = @backingInt(Status.invalid_argument);
    const tail_max = if (@hasDecl(Core, "tail_max")) Core.tail_max else Core.block_len;
    const keep_len = if (@hasDecl(Core, "keep_len")) Core.keep_len else 0;
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
            if (tail_len > tail_max) return invalid;
            const st: *const Core.State = @ptrFromInt(state);
            if (keep_len > 0 and st.t != 0 and tail_len < keep_len) return invalid;
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
