//! Tiger and Tiger2 (Anderson and Biham, 1995), 192-bit digests, three passes.
//!
//! These are new algorithms (crypto-api 0.8.5 has no Tiger), so there is no
//! original to stay compatible with. As for BLAKE2, the state that JS keeps
//! between calls is only the chaining value and the byte counter; buffering
//! stays in the JS hasher and wasm compresses (`blocks`) and finishes (`final`).
//! `blocks` never pads, so the caller keeps the last 1..64 bytes of a message
//! for `final`. `final` does not modify the state.
//!
//! Tiger2 differs from Tiger in one byte: the padding starts with 0x80 instead
//! of 0x01.
//!
//! The four S-boxes (4 x 256 words) are not typed in: they are derived at
//! compile time with the generator published with the design (the compression
//! function run over a fixed text, five passes of swaps), and a test checks
//! the result against words copied from the specification.

const std = @import("std");

/// Tiger: padding byte 0x01.
pub const Tiger = TigerImpl(0x01);
/// Tiger2: padding byte 0x80.
pub const Tiger2 = TigerImpl(0x80);

pub const iv = [3]u64{ 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187 };

/// The S-boxes, derived at compile time (see `generate`).
pub const sbox: [4 * 256]u64 = blk: {
    @setEvalBranchQuota(200_000_000);
    break :blk generate();
};

/// The text the S-box generator is keyed with (64 bytes, exactly one block).
pub const sbox_seed = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham";

/// The S-box word `base`-table at byte `shift / 8` of `v` (`base` is 0, 256, 512 or 768).
inline fn look(t: *const [1024]u64, v: u64, comptime shift: u6, comptime base: usize) u64 {
    return t[base + @as(usize, @intCast((v >> shift) & 0xff))];
}

/// One round of the compression function: `c ^= x`, then `a` and `b` are
/// updated from the S-boxes looked up with the bytes of `c`.
inline fn round(t: *const [1024]u64, a: *u64, b: *u64, c: *u64, x: u64, mul: u64) void {
    c.* ^= x;
    const v = c.*;
    a.* -%= look(t, v, 0, 0) ^ look(t, v, 16, 256) ^ look(t, v, 32, 512) ^ look(t, v, 48, 768);
    b.* +%= look(t, v, 8, 768) ^ look(t, v, 24, 512) ^ look(t, v, 40, 256) ^ look(t, v, 56, 0);
    b.* *%= mul;
}

inline fn keySchedule(x: *[8]u64) void {
    x[0] -%= x[7] ^ 0xA5A5A5A5A5A5A5A5;
    x[1] ^= x[0];
    x[2] +%= x[1];
    x[3] -%= x[2] ^ (~x[1] << 19);
    x[4] ^= x[3];
    x[5] +%= x[4];
    x[6] -%= x[5] ^ (~x[4] >> 23);
    x[7] ^= x[6];
    x[0] +%= x[7];
    x[1] -%= x[0] ^ (~x[7] << 19);
    x[2] ^= x[1];
    x[3] +%= x[2];
    x[4] -%= x[3] ^ (~x[2] >> 23);
    x[5] ^= x[4];
    x[6] +%= x[5];
    x[7] -%= x[6] ^ 0x0123456789ABCDEF;
}

/// The compression function over the S-boxes `t`: `h` absorbs the 8 words `m`.
fn compressWith(t: *const [1024]u64, h: *[3]u64, m: *const [8]u64) void {
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var x = m.*;
    inline for (.{ 5, 7, 9 }, 0..) |mul, pass| {
        if (pass != 0) keySchedule(&x);
        round(t, &a, &b, &c, x[0], mul);
        round(t, &b, &c, &a, x[1], mul);
        round(t, &c, &a, &b, x[2], mul);
        round(t, &a, &b, &c, x[3], mul);
        round(t, &b, &c, &a, x[4], mul);
        round(t, &c, &a, &b, x[5], mul);
        round(t, &a, &b, &c, x[6], mul);
        round(t, &b, &c, &a, x[7], mul);
        // The roles rotate between passes: (a, b, c) = (c, a, b).
        const old_a = a;
        a = c;
        c = b;
        b = old_a;
    }
    h[0] ^= a;
    h[1] = b -% h[1];
    h[2] +%= c;
}

/// The S-box generator of the Tiger design: every byte column of the four
/// tables starts as the identity and is permuted by swaps chosen by the
/// bytes of a chaining value that the compression function evolves, in
/// five passes, over the (changing) tables themselves.
fn generate() [4 * 256]u64 {
    var t: [1024]u64 = undefined;
    for (&t, 0..) |*w, i| w.* = @as(u64, i & 0xff) * 0x0101010101010101;
    var seed: [8]u64 = undefined;
    for (&seed, 0..) |*w, i| w.* = std.mem.readInt(u64, sbox_seed[8 * i ..][0..8], .little);
    var state = iv;
    var abc: usize = 2;
    for (0..5) |_| {
        for (0..256) |i| {
            var sb: usize = 0;
            while (sb < 1024) : (sb += 256) {
                abc += 1;
                if (abc == 3) {
                    abc = 0;
                    compressWith(&t, &state, &seed);
                }
                const w = state[abc];
                for (0..8) |col| {
                    const shift: u6 = @intCast(8 * col);
                    const j = sb + @as(usize, @truncate((w >> shift) & 0xff));
                    const at_i = (t[sb + i] >> shift) & 0xff;
                    const at_j = (t[j] >> shift) & 0xff;
                    const mask = @as(u64, 0xff) << shift;
                    t[sb + i] = (t[sb + i] & ~mask) | (at_j << shift);
                    t[j] = (t[j] & ~mask) | (at_i << shift);
                }
            }
        }
    }
    return t;
}

fn TigerImpl(comptime pad: u8) type {
    return struct {
        pub const block_len = 64;
        pub const digest_len = 24;

        /// Layout is part of the wasm ABI (packages/crypto-api/src/wasm/blocks.mjs
        /// writes these offsets); a change bumps `runtime.abi_version`. Words are
        /// little-endian in memory.
        pub const State = extern struct {
            /// Bytes compressed so far.
            t: u64,
            /// The chaining value (`a`, `b`, `c`).
            h: [3]u64,

            comptime {
                std.debug.assert(@sizeOf(State) == 32);
                std.debug.assert(@offsetOf(State, "h") == 8);
            }
        };

        pub fn init(st: *State) void {
            st.h = iv;
            st.t = 0;
        }

        fn compress(h: *[3]u64, block: *const [64]u8) void {
            var m: [8]u64 = undefined;
            for (&m, 0..) |*w, i| w.* = std.mem.readInt(u64, block[8 * i ..][0..8], .little);
            compressWith(&sbox, h, &m);
            std.crypto.secureZero(u64, &m);
        }

        /// Compress whole blocks (`data.len % 64 == 0`), advancing `st.t`.
        pub fn blocks(st: *State, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            var i: usize = 0;
            while (i < data.len) : (i += block_len) {
                compress(&st.h, data[i..][0..block_len]);
                st.t += block_len;
            }
        }

        /// Finish: `tail` (0..64 bytes) is the end of the message. Writes the
        /// whole 24-byte digest, each word little-endian; the caller keeps the
        /// prefix it wants. `st` is not modified.
        pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
            std.debug.assert(tail.len <= block_len);
            var h = st.h;
            defer std.crypto.secureZero(u64, &h);
            var buf = @as([2 * block_len]u8, @splat(0));
            defer std.crypto.secureZero(u8, &buf);
            @memcpy(buf[0..tail.len], tail);
            buf[tail.len] = pad;
            // One block when the length field fits behind the padding byte, else two.
            const total: usize = if (tail.len + 1 + 8 <= block_len) block_len else 2 * block_len;
            std.mem.writeInt(u64, buf[total - 8 ..][0..8], (st.t + tail.len) *% 8, .little);
            compress(&h, buf[0..block_len]);
            if (total > block_len) compress(&h, buf[block_len..][0..block_len]);
            for (h, 0..) |w, i| std.mem.writeInt(u64, out[8 * i ..][0..8], w, .little);
        }
    };
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

fn hexTo(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Whole-message hash over `blocks`/`final`, buffering like the JS hasher does
/// (the last 1..64 bytes are held back), with the data fed in `piece`-byte updates.
fn oneShot(comptime T: type, message: []const u8, piece: usize, out: *[Tiger.digest_len]u8) void {
    var st: T.State = undefined;
    T.init(&st);
    var buf: [Tiger.block_len]u8 = undefined;
    var n: usize = 0;
    var rest = message;
    while (rest.len > 0) {
        const chunk = rest[0..@min(piece, rest.len)];
        rest = rest[chunk.len..];
        var data = chunk;
        while (data.len > 0) {
            if (n == Tiger.block_len) {
                T.blocks(&st, buf[0..Tiger.block_len]);
                n = 0;
            }
            const take = @min(data.len, Tiger.block_len - n);
            @memcpy(buf[n..][0..take], data[0..take]);
            n += take;
            data = data[take..];
        }
    }
    T.final(&st, buf[0..n], out);
}

test "S-boxes: words copied from the specification, and the permutation property" {
    // The first and last words of each table, from the reference implementation's table.
    try testing.expectEqual(@as(u64, 0x02AAB17CF7E90C5E), sbox[0]);
    try testing.expectEqual(@as(u64, 0xAC424B03E243A8EC), sbox[1]);
    try testing.expectEqual(@as(u64, 0x72CD5BE30DD5FCD3), sbox[2]);
    try testing.expectEqual(@as(u64, 0x6D019B93F6F97F3A), sbox[3]);
    try testing.expectEqual(@as(u64, 0xCD9978FFD21F9193), sbox[4]);
    // The generator only swaps: in every table and byte column, each value appears exactly once.
    for (0..4) |tab| {
        for (0..8) |col| {
            var seen = @as([256]bool, @splat(false));
            for (0..256) |i| {
                const b: u8 = @truncate(sbox[256 * tab + i] >> @intCast(8 * col));
                try testing.expect(!seen[b]);
                seen[b] = true;
            }
        }
    }
}

const published = [_]struct { msg: []const u8, tiger: []const u8, tiger2: ?[]const u8 }{
    .{ .msg = "", .tiger = "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", .tiger2 = "4441be75f6018773c206c22745374b924aa8313fef919f41" },
    .{ .msg = "abc", .tiger = "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93", .tiger2 = "f68d7bc5af4b43a06e048d7829560d4a9415658bb0b1f3bf" },
    .{ .msg = "Tiger", .tiger = "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937", .tiger2 = null },
    .{ .msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-", .tiger = "f71c8583902afb879edfe610f82c0d4786a3a534504486b5", .tiger2 = null },
    .{ .msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789", .tiger = "48ceeb6308b87d46e95d656112cdf18d97915f9765658957", .tiger2 = null },
    .{ .msg = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham", .tiger = "8a866829040a410c729ad23f5ada711603b3cdd357e4c15e", .tiger2 = null },
};

test "published Tiger and Tiger2 test vectors, at every update size" {
    for (published) |v| {
        const want = hexTo(Tiger.digest_len, v.tiger);
        const want2 = if (v.tiger2) |h| hexTo(Tiger.digest_len, h) else null;
        for ([_]usize{ 1, 7, 63, 64, 65, 1000 }) |piece| {
            var got: [Tiger.digest_len]u8 = undefined;
            oneShot(Tiger, v.msg, piece, &got);
            try testing.expectEqualSlices(u8, &want, &got);
            if (want2) |w2| {
                oneShot(Tiger2, v.msg, piece, &got);
                try testing.expectEqualSlices(u8, &w2, &got);
            }
        }
    }
}

test "one million 'a' (the published long vector)" {
    const msg = try testing.allocator.alloc(u8, 1_000_000);
    defer testing.allocator.free(msg);
    @memset(msg, 'a');
    var got: [Tiger.digest_len]u8 = undefined;
    oneShot(Tiger, msg, 4096, &got);
    try testing.expectEqualSlices(u8, &hexTo(Tiger.digest_len, "6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41"), &got);
}

test "padding boundaries: lengths 55 to 57 and 63 to 65 agree between update splits" {
    var msg: [200]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    for (0..msg.len) |len| {
        var one: [Tiger.digest_len]u8 = undefined;
        oneShot(Tiger, msg[0..len], 1000, &one);
        var split: [Tiger.digest_len]u8 = undefined;
        oneShot(Tiger, msg[0..len], 5, &split);
        try testing.expectEqualSlices(u8, &one, &split);
    }
}

test "final does not change the state" {
    var st: Tiger.State = undefined;
    Tiger.init(&st);
    const before = st;
    var out: [Tiger.digest_len]u8 = undefined;
    Tiger.final(&st, "abc", &out);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
