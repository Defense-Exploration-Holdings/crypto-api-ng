//! RIPEMD-128/160/256/320 cores, a faithful port of crypto-api 0.8.5
//! `src/hasher/ripemd.mjs` (`processBlock128/160/256/320`).
//!
//! Target-agnostic (no wasm/OS code). The wasm export wrapper is
//! `src/wasm/ripemd.zig`. Padding, buffering and the original's 32-bit length
//! field quirk come from `le32.zig`.
//!
//! The original picks the variant from `options.length` (128, 256, 320, and
//! anything else means 160). The JS facade does not look at `options`: it
//! derives the variant from which `processBlock*` function the instance
//! currently holds, and calls the matching `ripemd<N>_*` exports.

const std = @import("std");
const le32 = @import("le32.zig");

pub const block_len = le32.block_len;
pub const lengthField = le32.lengthField;

pub const Ripemd128 = le32.Hasher(4, .{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 }, compress128);
pub const Ripemd160 = le32.Hasher(5, iv160, compress160);
pub const Ripemd256 = le32.Hasher(8, .{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
    0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567,
}, compress256);
pub const Ripemd320 = le32.Hasher(10, .{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
    0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567, 0x3c2d1e0f,
}, compress320);

const iv160 = [5]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

const ZL = [80]u8{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};
const ZR = [80]u8{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};
const SL = [80]u5{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};
const SR = [80]u5{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};

fn F(x: u32, y: u32, z: u32) u32 {
    return x ^ y ^ z;
}
fn G(x: u32, y: u32, z: u32) u32 {
    return (x & y) | (~x & z);
}
fn H(x: u32, y: u32, z: u32) u32 {
    return (x | ~y) ^ z;
}
fn I(x: u32, y: u32, z: u32) u32 {
    return (x & z) | (y & ~z);
}
fn J(x: u32, y: u32, z: u32) u32 {
    return x ^ (y | ~z);
}

/// Left line function for round `r` (the original's `Ripemd.T`, whose `i`
/// selects the round as `i / 16`). `r` is comptime so no branch is left in
/// the step loops.
inline fn tLeft(comptime r: usize, b: u32, c: u32, d: u32) u32 {
    return switch (r) {
        0 => F(b, c, d),
        1 => G(b, c, d) +% 0x5a827999,
        2 => H(b, c, d) +% 0x6ed9eba1,
        3 => I(b, c, d) +% 0x8f1bbcdc,
        else => J(b, c, d) +% 0xa953fd4e,
    };
}

/// Right line function of the 4-round variants (`Ripemd.T64`).
inline fn tRight64(comptime r: usize, b: u32, c: u32, d: u32) u32 {
    return switch (r) {
        0 => I(b, c, d) +% 0x50a28be6,
        1 => H(b, c, d) +% 0x5c4dd124,
        2 => G(b, c, d) +% 0x6d703ef3,
        else => F(b, c, d),
    };
}

/// Right line function of the 5-round variants (`Ripemd.T80`).
inline fn tRight80(comptime r: usize, b: u32, c: u32, d: u32) u32 {
    return switch (r) {
        0 => J(b, c, d) +% 0x50a28be6,
        1 => I(b, c, d) +% 0x5c4dd124,
        2 => H(b, c, d) +% 0x6d703ef3,
        3 => G(b, c, d) +% 0x7a6d76e9,
        else => F(b, c, d),
    };
}

fn rotl(x: u32, s: u5) u32 {
    return std.math.rotl(u32, x, s);
}

fn compress128(hash: *[4]u32, block: *const [le32.block_len]u8, param: u32) void {
    _ = param;
    const x = le32.loadWords(block);
    var al = hash[0];
    var bl = hash[1];
    var cl = hash[2];
    var dl = hash[3];
    var ar = al;
    var br = bl;
    var cr = cl;
    var dr = dl;

    inline for (0..4) |r| {
        for (r * 16..r * 16 + 16) |i| {
            var t = rotl(al +% x[ZL[i]] +% tLeft(r, bl, cl, dl), SL[i]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;

            t = rotl(ar +% x[ZR[i]] +% tRight64(r, br, cr, dr), SR[i]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;
        }
    }
    const t = hash[1] +% cl +% dr;
    hash[1] = hash[2] +% dl +% ar;
    hash[2] = hash[3] +% al +% br;
    hash[3] = hash[0] +% bl +% cr;
    hash[0] = t;
}

fn compress160(hash: *[5]u32, block: *const [le32.block_len]u8, param: u32) void {
    _ = param;
    const x = le32.loadWords(block);
    var al = hash[0];
    var bl = hash[1];
    var cl = hash[2];
    var dl = hash[3];
    var el = hash[4];
    var ar = al;
    var br = bl;
    var cr = cl;
    var dr = dl;
    var er = el;

    inline for (0..5) |r| {
        for (r * 16..r * 16 + 16) |i| {
            var t = rotl(al +% x[ZL[i]] +% tLeft(r, bl, cl, dl), SL[i]) +% el;
            al = el;
            el = dl;
            dl = rotl(cl, 10);
            cl = bl;
            bl = t;

            t = rotl(ar +% x[ZR[i]] +% tRight80(r, br, cr, dr), SR[i]) +% er;
            ar = er;
            er = dr;
            dr = rotl(cr, 10);
            cr = br;
            br = t;
        }
    }
    const t = hash[1] +% cl +% dr;
    hash[1] = hash[2] +% dl +% er;
    hash[2] = hash[3] +% el +% ar;
    hash[3] = hash[4] +% al +% br;
    hash[4] = hash[0] +% bl +% cr;
    hash[0] = t;
}

fn compress256(hash: *[8]u32, block: *const [le32.block_len]u8, param: u32) void {
    _ = param;
    const x = le32.loadWords(block);
    var al = hash[0];
    var bl = hash[1];
    var cl = hash[2];
    var dl = hash[3];
    var ar = hash[4];
    var br = hash[5];
    var cr = hash[6];
    var dr = hash[7];

    inline for (0..4) |r| {
        for (r * 16..r * 16 + 16) |i| {
            var t = rotl(al +% x[ZL[i]] +% tLeft(r, bl, cl, dl), SL[i]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;

            t = rotl(ar +% x[ZR[i]] +% tRight64(r, br, cr, dr), SR[i]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;
        }
        // After the last step of each round the original swaps one pair (i = 15, 31, 47, 63).
        switch (r) {
            0 => std.mem.swap(u32, &al, &ar),
            1 => std.mem.swap(u32, &bl, &br),
            2 => std.mem.swap(u32, &cl, &cr),
            else => std.mem.swap(u32, &dl, &dr),
        }
    }
    hash[0] +%= al;
    hash[1] +%= bl;
    hash[2] +%= cl;
    hash[3] +%= dl;
    hash[4] +%= ar;
    hash[5] +%= br;
    hash[6] +%= cr;
    hash[7] +%= dr;
}

fn compress320(hash: *[10]u32, block: *const [le32.block_len]u8, param: u32) void {
    _ = param;
    const x = le32.loadWords(block);
    var al = hash[0];
    var bl = hash[1];
    var cl = hash[2];
    var dl = hash[3];
    var el = hash[4];
    var ar = hash[5];
    var br = hash[6];
    var cr = hash[7];
    var dr = hash[8];
    var er = hash[9];

    inline for (0..5) |r| {
        for (r * 16..r * 16 + 16) |i| {
            var t = rotl(al +% x[ZL[i]] +% tLeft(r, bl, cl, dl), SL[i]) +% el;
            al = el;
            el = dl;
            dl = rotl(cl, 10);
            cl = bl;
            bl = t;

            t = rotl(ar +% x[ZR[i]] +% tRight80(r, br, cr, dr), SR[i]) +% er;
            ar = er;
            er = dr;
            dr = rotl(cr, 10);
            cr = br;
            br = t;
        }
        // After the last step of each round the original swaps one pair (i = 15, 31, 47, 63, 79).
        switch (r) {
            0 => std.mem.swap(u32, &bl, &br),
            1 => std.mem.swap(u32, &dl, &dr),
            2 => std.mem.swap(u32, &al, &ar),
            3 => std.mem.swap(u32, &cl, &cr),
            else => std.mem.swap(u32, &el, &er),
        }
    }
    hash[0] +%= al;
    hash[1] +%= bl;
    hash[2] +%= cl;
    hash[3] +%= dl;
    hash[4] +%= el;
    hash[5] +%= ar;
    hash[6] +%= br;
    hash[7] +%= cr;
    hash[8] +%= dr;
    hash[9] +%= er;
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn hexOf(comptime Core: type, data: []const u8) [Core.digest_len * 2]u8 {
    var st: Core.State = undefined;
    Core.init(&st, 0);
    Core.update(&st, data);
    var out: [Core.digest_len]u8 = undefined;
    Core.final(&st, &out);
    return std.fmt.bytesToHex(out, .lower);
}

const long80 = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
const abcdbcde = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

test "RIPEMD-128 vectors" {
    const C = Ripemd128;
    try testing.expectEqualStrings("cdf26213a150dc3ecb610f18f6b38b46", &hexOf(C, ""));
    try testing.expectEqualStrings("86be7afa339d0fc7cfc785e72f578d33", &hexOf(C, "a"));
    try testing.expectEqualStrings("c14a12199c66e4ba84636b0f69144c77", &hexOf(C, "abc"));
    try testing.expectEqualStrings("9e327b3d6e523062afc1132d7df9d1b8", &hexOf(C, "message digest"));
    try testing.expectEqualStrings("a1aa0689d0fafa2ddc22e88b49133a06", &hexOf(C, abcdbcde));
    try testing.expectEqualStrings("3f45ef194732c2dbb2c4a2c769795fa3", &hexOf(C, long80));
}

test "RIPEMD-160 vectors" {
    const C = Ripemd160;
    try testing.expectEqualStrings("9c1185a5c5e9fc54612808977ee8f548b2258d31", &hexOf(C, ""));
    try testing.expectEqualStrings("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", &hexOf(C, "a"));
    try testing.expectEqualStrings("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", &hexOf(C, "abc"));
    try testing.expectEqualStrings("5d0689ef49d2fae572b881b123a85ffa21595f36", &hexOf(C, "message digest"));
    try testing.expectEqualStrings("12a053384a9c0c88e405a06c27dcf49ada62eb2b", &hexOf(C, abcdbcde));
    try testing.expectEqualStrings("9b752e45573d4b39f4dbd3323cab82bf63326bfb", &hexOf(C, long80));
}

test "RIPEMD-256 vectors" {
    const C = Ripemd256;
    try testing.expectEqualStrings("02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", &hexOf(C, ""));
    try testing.expectEqualStrings("f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925", &hexOf(C, "a"));
    try testing.expectEqualStrings("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", &hexOf(C, "abc"));
    try testing.expectEqualStrings("3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f", &hexOf(C, abcdbcde));
    try testing.expectEqualStrings("06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd", &hexOf(C, long80));
}

test "RIPEMD-320 vectors" {
    const C = Ripemd320;
    try testing.expectEqualStrings("22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8", &hexOf(C, ""));
    try testing.expectEqualStrings("ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d", &hexOf(C, "a"));
    try testing.expectEqualStrings("de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d", &hexOf(C, "abc"));
    try testing.expectEqualStrings("d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac", &hexOf(C, abcdbcde));
    try testing.expectEqualStrings("557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42", &hexOf(C, long80));
}

test "State layouts are stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 96), @sizeOf(Ripemd128.State));
    try testing.expectEqual(@as(usize, 104), @sizeOf(Ripemd160.State));
    try testing.expectEqual(@as(usize, 112), @sizeOf(Ripemd256.State));
    try testing.expectEqual(@as(usize, 120), @sizeOf(Ripemd320.State));
    try testing.expectEqual(@as(usize, 16), @offsetOf(Ripemd128.State, "length"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(Ripemd160.State, "length"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(Ripemd256.State, "length"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(Ripemd320.State, "length"));
}

fn splitsEqualOneShot(comptime Core: type, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);

    for (0..data.len + 1) |len| {
        var one: Core.State = undefined;
        Core.init(&one, 0);
        Core.update(&one, data[0..len]);
        var want: [Core.digest_len]u8 = undefined;
        Core.final(&one, &want);

        var st: Core.State = undefined;
        Core.init(&st, 0);
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 70));
            Core.update(&st, data[pos..][0..n]);
            pos += n;
        }
        var got: [Core.digest_len]u8 = undefined;
        Core.final(&st, &got);
        try testing.expectEqualSlices(u8, &want, &got);
        try testing.expectEqual(@as(u64, len), st.length);
    }

    var a: Core.State = undefined;
    Core.init(&a, 0);
    Core.update(&a, data[0..256]);
    var b: Core.State = undefined;
    Core.init(&b, 0);
    Core.blocks(&b, data[0..256]);
    try testing.expectEqualSlices(u32, &a.hash, &b.hash);
    try testing.expectEqual(@as(u64, 0), b.length);
}

test "update() with random splits equals one shot, blocks() equals update()" {
    try splitsEqualOneShot(Ripemd128, 128);
    try splitsEqualOneShot(Ripemd160, 160);
    try splitsEqualOneShot(Ripemd256, 256);
    try splitsEqualOneShot(Ripemd320, 320);
}

test "state after final matches the original (values from crypto-api 0.8.5)" {
    const cases = .{
        .{ Ripemd128, "c14a12199c66e4ba84636b0f69144c77", [4]i32{ 420629185, -1159436644, 258696068, 2001474665 }, "582a0862286b53ad1722363893c42cb4" },
        .{ Ripemd160, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", [5]i32{ -150424946, 2056805856, -1907751781, -2018457960, -66364687 }, "02e893df6d1a0b5f21e11befabb5b5da314d32c8" },
        .{ Ripemd256, "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", [8]i32{ 577682863, -1148412533, 768275918, -1579424253, 2109521930, 241755339, -372096482, 1704674677 }, "75fd6e7575fb544d3031a6e80216bc5cce00b5e8e028de8b2a6d4674eb6b34ba" },
        .{ Ripemd320, "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d", [10]i32{ -1291760418, 814305029, -1375101529, 814911091, 135748126, -1040322725, 1897320888, 804811838, 1289110185, 761840859 }, "0a4f76b07014b03d6fadb18214c8e5e2784fa05547fcff1ee969bca9f294239aa8373e4e7503ba82" },
    };
    inline for (cases) |c| {
        const Core = c[0];
        var st: Core.State = undefined;
        Core.init(&st, 0);
        Core.update(&st, "abc");
        var out: [Core.digest_len]u8 = undefined;
        Core.final(&st, &out);
        try testing.expectEqualStrings(c[1], &std.fmt.bytesToHex(out, .lower));
        try testing.expectEqual(@as(u32, 0), st.buffered);
        try testing.expectEqual(@as(u64, 3), st.length);
        for (st.hash, c[2]) |w, want| try testing.expectEqual(want, @as(i32, @bitCast(w)));
        // A second final() runs another padded block on the advanced hash.
        Core.final(&st, &out);
        try testing.expectEqualStrings(c[3], &std.fmt.bytesToHex(out, .lower));
    }
}
