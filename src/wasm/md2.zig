//! wasm root for the "md2" family (MD2 alone: a byte-oriented 16-byte-block
//! hasher with its own `State`, so it does not share a module with the 32-bit
//! families). Compiled to zig-out/wasm/md2.wasm by build.zig. Export shape: see
//! src/wasm/md.zig and docs/abi.md. `*_blocks` and `*_final` return a
//! `runtime.Status` (non-zero when `rounds` is 0 or the buffer length is out of
//! range, which the JS facade never sends).

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const md2 = core.md2;
const Status = core.runtime.Status;

fn statePtr(p: u32) *md2.State {
    return @ptrFromInt(p);
}

export fn md2_state_size() u32 {
    return @sizeOf(md2.State);
}

export fn md2_init(state: u32, rounds: u32) i32 {
    if (rounds < 1) return @backingInt(Status.invalid_argument);
    md2.init(statePtr(state), rounds);
    return 0;
}

export fn md2_update(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (st.rounds < 1 or st.buffered >= md2.block_len) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    md2.update(st, p[0..len]);
    return 0;
}

/// Compress `len` bytes (a multiple of 16) into the hash and checksum at `state`.
export fn md2_blocks(state: u32, data: u32, len: u32) i32 {
    const st = statePtr(state);
    if (st.rounds < 1 or len % md2.block_len != 0) return @backingInt(Status.invalid_argument);
    const p: [*]const u8 = @ptrFromInt(data);
    md2.blocks(st, p[0..len]);
    return 0;
}

/// Pads, processes the last two blocks and writes the 16 digest bytes to `out`.
export fn md2_final(state: u32, out: u32) i32 {
    const st = statePtr(state);
    if (st.rounds < 1 or st.buffered >= md2.block_len) return @backingInt(Status.invalid_argument);
    md2.final(st, @ptrFromInt(out));
    return 0;
}
