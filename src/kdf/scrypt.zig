//! scrypt (RFC 7914) over the SHA-256 core of `src/hash/sha256.zig`.
//!
//! New in crypto-api-ng (0.8.5 has no password hashing). The core is
//! target-agnostic and allocation-free: the caller passes one work buffer of
//! `workWords(params)` 32-bit words (`B`, `V` and the BlockMix scratch), which
//! `hash` zeroes before it returns.

const std = @import("std");
const sha256 = @import("../hash/sha256.zig");

pub const Params = struct {
    /// log2 of the cost parameter N (N = 2^ln), 1 to 63.
    ln: u6,
    /// Block size parameter r, at least 1.
    r: u32,
    /// Parallelization parameter p, at least 1; r * p < 2^30.
    p: u32,
};

pub const Error = error{ WeakParameters, OutputTooLong };

/// Check the parameters against RFC 7914 section 2: N > 1, N < 2^(128 r / 8),
/// r * p < 2^30, and the derived key at most (2^32 - 1) * 32 bytes.
pub fn check(out_len: usize, params: Params) Error!void {
    if (out_len == 0) return error.WeakParameters;
    if (out_len / 32 > std.math.maxInt(u32) or (out_len / 32 == std.math.maxInt(u32) and out_len % 32 != 0)) return error.OutputTooLong;
    if (params.ln == 0 or params.r == 0 or params.p == 0) return error.WeakParameters;
    if (@as(u64, params.r) * params.p >= 1 << 30) return error.WeakParameters;
    if (@as(u64, params.ln) >= 16 * @as(u64, params.r)) return error.WeakParameters;
}

/// 32-bit words the work buffer needs: 32 r p (B), 32 r N (V) and 64 r (X, Y).
/// Null when it does not fit in a `usize` count of bytes.
pub fn workWords(params: Params) ?usize {
    const n = @as(u128, 1) << params.ln;
    const words = 32 * @as(u128, params.r) * (@as(u128, params.p) + n + 2);
    if (words * 4 > std.math.maxInt(usize)) return null;
    return @intCast(words);
}

// ---- HMAC-SHA-256 and PBKDF2 with one iteration ------------------------------

const Sha = struct {
    st: sha256.State,

    fn init() Sha {
        var self: Sha = undefined;
        sha256.init(&self.st, 256, sha256.max_rounds);
        return self;
    }

    fn update(self: *Sha, data: []const u8) void {
        sha256.update(&self.st, data);
    }

    fn final(self: *Sha, out: *[32]u8) void {
        sha256.final(&self.st, out);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

const Hmac = struct {
    inner: Sha,
    outer: Sha,

    fn init(key: []const u8) Hmac {
        var k: [64]u8 = @splat(0);
        defer std.crypto.secureZero(u8, &k);
        if (key.len > 64) {
            var h = Sha.init();
            h.update(key);
            h.final(k[0..32]);
        } else {
            @memcpy(k[0..key.len], key);
        }
        var pad: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &pad);
        var self: Hmac = .{ .inner = Sha.init(), .outer = Sha.init() };
        for (&pad, k) |*p, b| p.* = b ^ 0x36;
        self.inner.update(&pad);
        for (&pad, k) |*p, b| p.* = b ^ 0x5c;
        self.outer.update(&pad);
        return self;
    }

    fn final(self: *Hmac, out: *[32]u8) void {
        var ih: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &ih);
        self.inner.final(&ih);
        self.outer.update(&ih);
        self.outer.final(out);
    }
};

/// PBKDF2-HMAC-SHA-256 with one iteration (all scrypt needs).
fn pbkdf2(out: []u8, password: []const u8, salt: []const u8) void {
    var keyed = Hmac.init(password);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keyed));
    var t: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &t);
    var block: u32 = 1;
    var pos: usize = 0;
    while (pos < out.len) : ({
        pos += 32;
        block +%= 1;
    }) {
        var mac = keyed;
        mac.inner.update(salt);
        var be: [4]u8 = undefined;
        std.mem.writeInt(u32, &be, block, .big);
        mac.inner.update(&be);
        mac.final(&t);
        const n = @min(32, out.len - pos);
        @memcpy(out[pos..][0..n], t[0..n]);
    }
}

// ---- Salsa20/8, BlockMix, ROMix ----------------------------------------------

fn salsa8(b: *[16]u32) void {
    var x = b.*;
    var i: usize = 0;
    while (i < 8) : (i += 2) {
        x[4] ^= std.math.rotl(u32, x[0] +% x[12], 7);
        x[8] ^= std.math.rotl(u32, x[4] +% x[0], 9);
        x[12] ^= std.math.rotl(u32, x[8] +% x[4], 13);
        x[0] ^= std.math.rotl(u32, x[12] +% x[8], 18);
        x[9] ^= std.math.rotl(u32, x[5] +% x[1], 7);
        x[13] ^= std.math.rotl(u32, x[9] +% x[5], 9);
        x[1] ^= std.math.rotl(u32, x[13] +% x[9], 13);
        x[5] ^= std.math.rotl(u32, x[1] +% x[13], 18);
        x[14] ^= std.math.rotl(u32, x[10] +% x[6], 7);
        x[2] ^= std.math.rotl(u32, x[14] +% x[10], 9);
        x[6] ^= std.math.rotl(u32, x[2] +% x[14], 13);
        x[10] ^= std.math.rotl(u32, x[6] +% x[2], 18);
        x[3] ^= std.math.rotl(u32, x[15] +% x[11], 7);
        x[7] ^= std.math.rotl(u32, x[3] +% x[15], 9);
        x[11] ^= std.math.rotl(u32, x[7] +% x[3], 13);
        x[15] ^= std.math.rotl(u32, x[11] +% x[7], 18);
        x[1] ^= std.math.rotl(u32, x[0] +% x[3], 7);
        x[2] ^= std.math.rotl(u32, x[1] +% x[0], 9);
        x[3] ^= std.math.rotl(u32, x[2] +% x[1], 13);
        x[0] ^= std.math.rotl(u32, x[3] +% x[2], 18);
        x[6] ^= std.math.rotl(u32, x[5] +% x[4], 7);
        x[7] ^= std.math.rotl(u32, x[6] +% x[5], 9);
        x[4] ^= std.math.rotl(u32, x[7] +% x[6], 13);
        x[5] ^= std.math.rotl(u32, x[4] +% x[7], 18);
        x[11] ^= std.math.rotl(u32, x[10] +% x[9], 7);
        x[8] ^= std.math.rotl(u32, x[11] +% x[10], 9);
        x[9] ^= std.math.rotl(u32, x[8] +% x[11], 13);
        x[10] ^= std.math.rotl(u32, x[9] +% x[8], 18);
        x[12] ^= std.math.rotl(u32, x[15] +% x[14], 7);
        x[13] ^= std.math.rotl(u32, x[12] +% x[15], 9);
        x[14] ^= std.math.rotl(u32, x[13] +% x[12], 13);
        x[15] ^= std.math.rotl(u32, x[14] +% x[13], 18);
    }
    for (b, x) |*w, v| w.* +%= v;
    std.crypto.secureZero(u32, &x);
}

/// scryptBlockMix (RFC 7914 section 4): `y` = BlockMix(`b`), both 32 r words.
fn blockMix(b: []const u32, y: []u32, r: usize) void {
    var x: [16]u32 = b[(2 * r - 1) * 16 ..][0..16].*;
    defer std.crypto.secureZero(u32, &x);
    for (0..2 * r) |i| {
        for (&x, b[i * 16 ..][0..16]) |*w, v| w.* ^= v;
        salsa8(&x);
        // Even blocks go to the first half, odd blocks to the second.
        const at = (i / 2 + (i % 2) * r) * 16;
        y[at..][0..16].* = x;
    }
}

/// scryptROMix (RFC 7914 section 5) on one 128 r byte block `b` (as words).
fn roMix(b: []u32, v: []u32, xy: []u32, r: usize, n: u64) void {
    const len = 32 * r;
    const x = xy[0..len];
    const y = xy[len..][0..len];
    @memcpy(x, b);
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        @memcpy(v[@intCast(i * len)..][0..len], x);
        blockMix(x, y, r);
        @memcpy(x, y);
    }
    i = 0;
    while (i < n) : (i += 1) {
        const last = x[(2 * r - 1) * 16 ..];
        const j = ((@as(u64, last[1]) << 32) | last[0]) & (n - 1);
        for (x, v[@intCast(j * len)..][0..len]) |*w, t| w.* ^= t;
        blockMix(x, y, r);
        @memcpy(x, y);
    }
    @memcpy(b, x);
}

/// Derive `out` from `password` and `salt`. `work` must hold `workWords(params)`
/// words; it is zeroed on return. The parameters must have passed `check`.
pub fn hash(out: []u8, password: []const u8, salt: []const u8, params: Params, work: []u32) void {
    std.debug.assert(work.len == workWords(params).?);
    defer std.crypto.secureZero(u32, work);
    const r: usize = params.r;
    const n = @as(u64, 1) << params.ln;
    const block_words = 32 * r;
    const b = work[0 .. block_words * params.p];
    const v = work[b.len..][0..@intCast(block_words * n)];
    const xy = work[b.len + v.len ..][0 .. 2 * block_words];

    const b_bytes = std.mem.sliceAsBytes(b);
    pbkdf2(b_bytes, password, salt);
    // The words of B are little-endian; on a big-endian target, swap in place.
    if (@import("builtin").cpu.arch.endian() == .big) {
        for (b) |*w| w.* = @byteSwap(w.*);
    }
    var i: usize = 0;
    while (i < params.p) : (i += 1) {
        roMix(b[i * block_words ..][0..block_words], v, xy, r, n);
    }
    if (@import("builtin").cpu.arch.endian() == .big) {
        for (b) |*w| w.* = @byteSwap(w.*);
    }
    pbkdf2(out, password, b_bytes);
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn derive(out: []u8, password: []const u8, salt: []const u8, params: Params) !void {
    try check(out.len, params);
    const work = try testing.allocator.alloc(u32, workWords(params).?);
    defer testing.allocator.free(work);
    hash(out, password, salt, params, work);
    for (work) |w| try testing.expectEqual(@as(u32, 0), w);
}

fn expectHex(want: []const u8, got: []const u8) !void {
    var buf: [128]u8 = undefined;
    const w = try std.fmt.hexToBytes(&buf, want);
    try testing.expectEqualSlices(u8, w, got);
}

test "RFC 7914 section 12" {
    var dk: [64]u8 = undefined;
    try derive(&dk, "", "", .{ .ln = 4, .r = 1, .p = 1 });
    try expectHex("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906", &dk);
    try derive(&dk, "password", "NaCl", .{ .ln = 10, .r = 8, .p = 16 });
    try expectHex("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", &dk);
    try derive(&dk, "pleaseletmein", "SodiumChloride", .{ .ln = 14, .r = 8, .p = 1 });
    try expectHex("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887", &dk);
}

test "RFC 7914 section 8: Salsa20/8 core" {
    var b: [16]u32 = undefined;
    var bytes: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1dee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e");
    for (&b, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    salsa8(&b);
    for (b, 0..) |w, i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], w, .little);
    try expectHex("a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81", &bytes);
}

test "RFC 7914 section 11: PBKDF2-HMAC-SHA256" {
    var dk: [64]u8 = undefined;
    pbkdf2(&dk, "passwd", "salt");
    try expectHex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783", &dk);
}

test "parameter checks" {
    try check(1, .{ .ln = 1, .r = 1, .p = 1 });
    try testing.expectError(error.WeakParameters, check(0, .{ .ln = 1, .r = 1, .p = 1 }));
    try testing.expectError(error.WeakParameters, check(32, .{ .ln = 0, .r = 1, .p = 1 }));
    try testing.expectError(error.WeakParameters, check(32, .{ .ln = 16, .r = 1, .p = 1 }));
    try check(32, .{ .ln = 15, .r = 1, .p = 1 });
    try testing.expectError(error.WeakParameters, check(32, .{ .ln = 1, .r = 1 << 15, .p = 1 << 15 }));
    try check(32, .{ .ln = 1, .r = 1 << 15, .p = (1 << 15) - 1 });
}

test "agrees with std.crypto.pwhash.scrypt" {
    const S = std.crypto.pwhash.scrypt;
    var input: [200]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @truncate(i *% 53 +% 7);
    const cases = [_]struct { ln: u6, r: u30, p: u30, len: usize, pw: usize, salt: usize }{
        .{ .ln = 1, .r = 1, .p = 1, .len = 1, .pw = 0, .salt = 0 },
        .{ .ln = 3, .r = 2, .p = 3, .len = 33, .pw = 65, .salt = 7 },
        .{ .ln = 8, .r = 1, .p = 2, .len = 100, .pw = 64, .salt = 64 },
        .{ .ln = 6, .r = 5, .p = 1, .len = 32, .pw = 150, .salt = 1 },
        .{ .ln = 10, .r = 3, .p = 4, .len = 64, .pw = 8, .salt = 16 },
    };
    for (cases) |c| {
        var ours: [100]u8 = undefined;
        var theirs: [100]u8 = undefined;
        try derive(ours[0..c.len], input[0..c.pw], input[3 .. 3 + c.salt], .{ .ln = c.ln, .r = c.r, .p = c.p });
        try S.kdf(testing.allocator, theirs[0..c.len], input[0..c.pw], input[3 .. 3 + c.salt], .{ .ln = c.ln, .r = c.r, .p = c.p });
        try testing.expectEqualSlices(u8, theirs[0..c.len], ours[0..c.len]);
    }
}
