//! wasm root for the "scrypt" family. Compiled to zig-out/wasm/scrypt.wasm by
//! build.zig. Exports (see docs/abi.md):
//!
//!     alloc(len) -> ptr
//!     scrypt_hash(ln, r, p, pwd, pwd_len, salt, salt_len, out, out_len) -> status
//!
//! `scrypt_hash` takes its work buffer (B, V, X and Y) from `memory.grow` and
//! zeroes it (and the stack it used) before returning.

comptime {
    _ = @import("common.zig");
}

const core = @import("core");
const scrypt = core.scrypt;
const Status = core.runtime.Status;
const pwhash = @import("pwhash.zig");
const scrubStack = @import("common.zig").scrubStack;

/// Twice the deepest frame (HMAC-SHA-256 states and the Salsa20/8 words).
const scrub_len = 4 * 1024;

comptime {
    @export(&pwhash.alloc, .{ .name = "alloc" });
}

fn slice(ptr: u32, len: u32) []const u8 {
    if (len == 0) return "";
    const p: [*]const u8 = @ptrFromInt(ptr);
    return p[0..len];
}

export fn scrypt_hash(ln: u32, r: u32, p: u32, pwd: u32, pwd_len: u32, salt: u32, salt_len: u32, out: u32, out_len: u32) i32 {
    const invalid: i32 = @backingInt(Status.invalid_argument);
    if (ln == 0 or ln > 63 or out == 0) return invalid;
    const params: scrypt.Params = .{ .ln = @intCast(ln), .r = r, .p = p };
    scrypt.check(out_len, params) catch return invalid;
    const words = scrypt.workWords(params) orelse return @backingInt(Status.out_of_memory);
    if (words > 0xFFFF_0000 / 4) return @backingInt(Status.out_of_memory);
    const mem = pwhash.grab(words * 4) orelse return @backingInt(Status.out_of_memory);
    const work: [*]u32 = @ptrCast(@alignCast(mem));
    const o: [*]u8 = @ptrFromInt(out);
    defer scrubStack(scrub_len);
    @call(.never_inline, scrypt.hash, .{ o[0..out_len], slice(pwd, pwd_len), slice(salt, salt_len), params, work[0..words] });
    return 0;
}
