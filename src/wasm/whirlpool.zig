//! wasm root for the "whirlpool" family: the final Whirlpool, Whirlpool-T and
//! Whirlpool-0 in one module (they share the compression code and differ only
//! in tables, so one module is smaller than three). Compiled to
//! zig-out/wasm/whirlpool.wasm by build.zig. Export shape: see src/wasm/md.zig
//! and docs/abi.md; each variant has its own export prefix,
//! `whirlpool_*`, `whirlpool0_*` and `whirlpoolt_*`, and the same State.
//! `*_blocks` and `*_final` return a `runtime.Status` (non-zero when `rounds`
//! is outside 1..10, which the JS facade never sends).
//!
//! `State` is 152 bytes, larger than the 128-byte state slot of the scratch
//! region, so the JS facade passes `out` at the input offset (+256), like SHA-512;
//! `*_final` does not read the input region.

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const scrubStack = @import("common.zig").scrubStack;
const whirlpool = core.whirlpool;
const Status = core.runtime.Status;

fn statePtr(p: u32) *whirlpool.State {
    return @ptrFromInt(p);
}

fn okRounds(st: *const whirlpool.State) bool {
    return st.rounds >= 1 and st.rounds <= whirlpool.max_rounds;
}

fn Exports(comptime A: type) type {
    return struct {
        fn stateSize() callconv(.c) u32 {
            return @sizeOf(whirlpool.State);
        }

        fn init(state: u32, rounds: u32) callconv(.c) i32 {
            if (rounds < 1 or rounds > whirlpool.max_rounds) return @backingInt(Status.invalid_argument);
            A.init(statePtr(state), rounds);
            return 0;
        }

        fn update(state: u32, data: u32, len: u32) callconv(.c) i32 {
            const st = statePtr(state);
            if (!okRounds(st) or st.buffered >= whirlpool.block_len) return @backingInt(Status.invalid_argument);
            const p: [*]const u8 = @ptrFromInt(data);
            defer scrubStack(1024);
            @call(.never_inline, A.update, .{ st, p[0..len] });
            return 0;
        }

        /// Compress `len` bytes (a multiple of 64) into the hash words at `state`.
        fn blocks(state: u32, data: u32, len: u32) callconv(.c) i32 {
            const st = statePtr(state);
            if (!okRounds(st) or len % whirlpool.block_len != 0) return @backingInt(Status.invalid_argument);
            const p: [*]const u8 = @ptrFromInt(data);
            defer scrubStack(1024);
            @call(.never_inline, A.blocks, .{ st, p[0..len] });
            return 0;
        }

        /// Writes the 64 digest bytes to `out`.
        fn final(state: u32, out: u32) callconv(.c) i32 {
            const st = statePtr(state);
            if (!okRounds(st) or st.buffered >= whirlpool.block_len) return @backingInt(Status.invalid_argument);
            defer scrubStack(1024);
            @call(.never_inline, A.final, .{ st, @as(*[64]u8, @ptrFromInt(out)) });
            return 0;
        }
    };
}

fn exportVariant(comptime A: type, comptime prefix: []const u8) void {
    const E = Exports(A);
    @export(&E.stateSize, .{ .name = prefix ++ "_state_size" });
    @export(&E.init, .{ .name = prefix ++ "_init" });
    @export(&E.update, .{ .name = prefix ++ "_update" });
    @export(&E.blocks, .{ .name = prefix ++ "_blocks" });
    @export(&E.final, .{ .name = prefix ++ "_final" });
}

comptime {
    exportVariant(whirlpool.whirlpool, "whirlpool");
    exportVariant(whirlpool.whirlpool0, "whirlpool0");
    exportVariant(whirlpool.whirlpoolT, "whirlpoolt");
}
