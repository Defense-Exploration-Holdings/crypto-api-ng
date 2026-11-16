//! wasm root for the "sha1" family: SHA-0 and SHA-1. Compiled to
//! zig-out/wasm/sha1.wasm by build.zig. Export shape: see src/wasm/md.zig and
//! docs/abi.md. `rounds` lives in the State; `*_blocks` and `*_final`
//! return a `runtime.Status` (non-zero when `rounds` is outside 1..80, which
//! the JS facade never sends), so a bad state cannot write out of bounds.

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const scrubStack = @import("common.zig").scrubStack;
const sha1 = core.sha1;
const Status = core.runtime.Status;

fn statePtr(p: u32) *sha1.State {
    return @ptrFromInt(p);
}

fn okRounds(st: *const sha1.State) bool {
    return st.rounds >= 1 and st.rounds <= sha1.max_rounds;
}

fn Exports(comptime variant: sha1.Variant) type {
    return struct {
        fn stateSize() u32 {
            return @sizeOf(sha1.State);
        }
        fn init(state: u32, rounds: u32) i32 {
            if (rounds < 1 or rounds > sha1.max_rounds) return @backingInt(Status.invalid_argument);
            sha1.init(statePtr(state), rounds);
            return 0;
        }
        fn update(state: u32, data: u32, len: u32) i32 {
            const st = statePtr(state);
            if (!okRounds(st) or st.buffered >= sha1.block_len) return @backingInt(Status.invalid_argument);
            const p: [*]const u8 = @ptrFromInt(data);
            defer scrubStack(2048);
            @call(.never_inline, sha1.update, .{ variant, st, p[0..len] });
            return 0;
        }
        /// Compress `len` bytes (a multiple of 64) into the hash words at `state`.
        fn blocks(state: u32, data: u32, len: u32) i32 {
            const st = statePtr(state);
            if (!okRounds(st) or len % sha1.block_len != 0) return @backingInt(Status.invalid_argument);
            const p: [*]const u8 = @ptrFromInt(data);
            defer scrubStack(2048);
            @call(.never_inline, sha1.blocks, .{ variant, st, p[0..len] });
            return 0;
        }
        fn final(state: u32, out: u32) i32 {
            const st = statePtr(state);
            if (!okRounds(st) or st.buffered >= sha1.block_len) return @backingInt(Status.invalid_argument);
            defer scrubStack(2048);
            @call(.never_inline, sha1.final, .{ variant, st, @as(*[sha1.digest_len]u8, @ptrFromInt(out)) });
            return 0;
        }
    };
}

const Sha0 = Exports(.sha0);
const Sha1 = Exports(.sha1);

export fn sha0_state_size() u32 {
    return Sha0.stateSize();
}
export fn sha0_init(state: u32, rounds: u32) i32 {
    return Sha0.init(state, rounds);
}
export fn sha0_update(state: u32, data: u32, len: u32) i32 {
    return Sha0.update(state, data, len);
}
export fn sha0_blocks(state: u32, data: u32, len: u32) i32 {
    return Sha0.blocks(state, data, len);
}
export fn sha0_final(state: u32, out: u32) i32 {
    return Sha0.final(state, out);
}

export fn sha1_state_size() u32 {
    return Sha1.stateSize();
}
export fn sha1_init(state: u32, rounds: u32) i32 {
    return Sha1.init(state, rounds);
}
export fn sha1_update(state: u32, data: u32, len: u32) i32 {
    return Sha1.update(state, data, len);
}
export fn sha1_blocks(state: u32, data: u32, len: u32) i32 {
    return Sha1.blocks(state, data, len);
}
export fn sha1_final(state: u32, out: u32) i32 {
    return Sha1.final(state, out);
}
