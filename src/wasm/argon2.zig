//! wasm root for the "argon2" family. Compiled to zig-out/wasm/argon2.wasm by
//! build.zig. Exports (see docs/abi.md):
//!
//!     alloc(len) -> ptr
//!     argon2_hash(mode, t, m, p, pwd, pwd_len, salt, salt_len,
//!                 secret, secret_len, ad, ad_len, out, out_len) -> status
//!
//! `argon2_hash` takes the memory matrix from `memory.grow` and zeroes it (and
//! the stack it used) before returning.

comptime {
    _ = @import("common.zig");
}

const std = @import("std");
const core = @import("core");
const argon2 = core.argon2;
const Status = core.runtime.Status;
const pwhash = @import("pwhash.zig");
const scrubStack = @import("common.zig").scrubStack;

/// Twice the deepest frame (`fillBlock` holds two blocks, 2 KiB).
const scrub_len = 8 * 1024;

comptime {
    @export(&pwhash.alloc, .{ .name = "alloc" });
}

fn slice(ptr: u32, len: u32) []const u8 {
    if (len == 0) return "";
    const p: [*]const u8 = @ptrFromInt(ptr);
    return p[0..len];
}

export fn argon2_hash(
    mode: u32,
    t: u32,
    m: u32,
    p: u32,
    pwd: u32,
    pwd_len: u32,
    salt: u32,
    salt_len: u32,
    secret: u32,
    secret_len: u32,
    ad: u32,
    ad_len: u32,
    out: u32,
    out_len: u32,
) i32 {
    const invalid: i32 = @backingInt(Status.invalid_argument);
    if (mode > 2 or out == 0) return invalid;
    const params: argon2.Params = .{ .t = t, .m = m, .p = p, .secret = slice(secret, secret_len), .ad = slice(ad, ad_len) };
    argon2.check(out_len, pwd_len, salt_len, params) catch return invalid;
    const blocks = argon2.blockCount(params);
    if (blocks > (0xFFFF_0000 / argon2.block_len)) return @backingInt(Status.out_of_memory);
    const mem = pwhash.grab(@intCast(blocks * argon2.block_len)) orelse return @backingInt(Status.out_of_memory);
    const matrix: [*]argon2.Block = @ptrCast(@alignCast(mem));
    const o: [*]u8 = @ptrFromInt(out);
    defer scrubStack(scrub_len);
    @call(.never_inline, argon2.hash, .{ o[0..out_len], slice(pwd, pwd_len), slice(salt, salt_len), params, @as(argon2.Mode, @fromBackingInt(@intCast(mode))), matrix[0..@intCast(blocks)] });
    return 0;
}
