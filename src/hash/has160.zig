//! HAS-160 core, a faithful port of crypto-api 0.8.5 `src/hasher/has160.mjs`.
//!
//! Target-agnostic (no wasm/OS code). The wasm export wrapper is
//! `src/wasm/has160.zig`. Padding, buffering and the original's 32-bit length
//! field quirk come from `le32.zig`.
//!
//! The original takes a `rounds` option (default 80) and runs the step loop
//! `rounds` times. `State.param` carries it; the JS facade only passes values
//! 0..80 (anything else goes to the original code).

const std = @import("std");
const le32 = @import("le32.zig");

const Core = le32.Hasher(5, iv, compress);

pub const block_len = le32.block_len;
pub const digest_len = Core.digest_len;
pub const State = Core.State;
pub const init = Core.init;
pub const update = Core.update;
pub const blocks = Core.blocks;
pub const final = Core.final;
pub const lengthField = le32.lengthField;

/// The original's initial words are written as unsigned literals, so before the
/// first block is processed `getState()` shows them unsigned. That is a JS
/// representation detail the facade keeps by never touching `state.hash` until
/// a block has actually been processed.
pub const iv = [5]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

pub const default_rounds = 80;

const K = [4]u32{ 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc };
const ROT = [20]u5{ 5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13 };
const ROT2 = [4]u5{ 10, 17, 25, 30 };
const IND = [80]u8{
    18, 0,  1, 2,  3,  19, 4,  5,  6, 7,  16, 8,  9,  10, 11, 17, 12, 13, 14, 15,
    22, 3,  6, 9,  12, 23, 15, 2,  5, 8,  20, 11, 14, 1,  4,  21, 7,  10, 13, 0,
    26, 12, 5, 14, 7,  27, 0,  9,  2, 11, 24, 4,  13, 6,  15, 25, 8,  1,  10, 3,
    30, 7,  2, 13, 8,  31, 3,  14, 9, 4,  28, 15, 10, 5,  0,  29, 11, 6,  1,  12,
};

fn compress(hash: *[5]u32, block: *const [le32.block_len]u8, rounds: u32) void {
    var w: [32]u32 = undefined;
    const m = le32.loadWords(block);
    w[0..16].* = m;
    w[16] = w[0] ^ w[1] ^ w[2] ^ w[3];
    w[17] = w[4] ^ w[5] ^ w[6] ^ w[7];
    w[18] = w[8] ^ w[9] ^ w[10] ^ w[11];
    w[19] = w[12] ^ w[13] ^ w[14] ^ w[15];
    w[20] = w[3] ^ w[6] ^ w[9] ^ w[12];
    w[21] = w[2] ^ w[5] ^ w[8] ^ w[15];
    w[22] = w[1] ^ w[4] ^ w[11] ^ w[14];
    w[23] = w[0] ^ w[7] ^ w[10] ^ w[13];
    w[24] = w[5] ^ w[7] ^ w[12] ^ w[14];
    w[25] = w[0] ^ w[2] ^ w[9] ^ w[11];
    w[26] = w[4] ^ w[6] ^ w[13] ^ w[15];
    w[27] = w[1] ^ w[3] ^ w[8] ^ w[10];
    w[28] = w[2] ^ w[7] ^ w[8] ^ w[13];
    w[29] = w[3] ^ w[4] ^ w[9] ^ w[14];
    w[30] = w[0] ^ w[5] ^ w[10] ^ w[15];
    w[31] = w[1] ^ w[6] ^ w[11] ^ w[12];

    var a = hash[0];
    var b = hash[1];
    var c = hash[2];
    var d = hash[3];
    var e = hash[4];

    // The original runs `rounds` steps (default 80). The stage (i / 20) is a
    // comptime constant so the round function and constant need no branch.
    const n = @min(rounds, 80);
    rounds_loop: inline for (0..4) |stage| {
        for (stage * 20..stage * 20 + 20) |i| {
            if (i >= n) break :rounds_loop;
            const f: u32 = switch (stage) {
                0 => (b & c) | (~b & d),
                2 => c ^ (b | ~d),
                else => b ^ c ^ d,
            };
            const t = std.math.rotl(u32, a, ROT[i % 20]) +% e +% w[IND[i]] +% K[stage] +% f;
            e = d;
            d = c;
            c = std.math.rotl(u32, b, ROT2[stage]);
            b = a;
            a = t;
        }
    }

    hash[0] +%= a;
    hash[1] +%= b;
    hash[2] +%= c;
    hash[3] +%= d;
    hash[4] +%= e;
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn hexDigest(data: []const u8, rounds: u32) [40]u8 {
    var st: State = undefined;
    init(&st, rounds);
    update(&st, data);
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    return std.fmt.bytesToHex(out, .lower);
}

test "reference vectors (from the original crypto-api test suite)" {
    const cases = [_]struct { in: []const u8, hex: []const u8 }{
        .{ .in = "", .hex = "307964ef34151d37c8047adec7ab50f4ff89762d" },
        .{ .in = "a", .hex = "4872bcbc4cd0f0a9dc7c2f7045e5b43b6c830db8" },
        .{ .in = "abc", .hex = "975e810488cf2a3d49838478124afce4b1c78804" },
        .{ .in = "message digest", .hex = "2338dbc8638d31225f73086246ba529f96710bc6" },
        .{ .in = "abcdefghijklmnopqrstuvwxyz", .hex = "596185c9ab6703d0d0dbb98702bc0f5729cd1d3c" },
        .{ .in = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", .hex = "cb5d7efbca2f02e0fb7167cabb123af5795764e5" },
        .{ .in = "12345678901234567890123456789012345678901234567890123456789012345678901234567890", .hex = "07f05c8c0773c55ca3a5a695ce6aca4c438911b5" },
    };
    for (cases) |c| try testing.expectEqualStrings(c.hex, &hexDigest(c.in, default_rounds));
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 104), @sizeOf(State));
    try testing.expectEqual(@as(usize, 24), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 36), @offsetOf(State, "param"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(State, "buf"));
}

test "rounds option (values captured from crypto-api 0.8.5, message 'abc')" {
    const cases = [_]struct { rounds: u32, hex: []const u8 }{
        .{ .rounds = 0, .hex = "02468ace12579bdffcb97531eca86420e0c3a587" }, // only reachable by mutating options.rounds
        .{ .rounds = 1, .hex = "1b4277ac8ace1257bd0469cf7431eda8663605d4" },
        .{ .rounds = 20, .hex = "87c7809243487b291e4a2f6039243556b1bdcb68" },
        .{ .rounds = 33, .hex = "a8db691638f5f3dc40336e6fb731b0d235ea0a70" },
        .{ .rounds = 79, .hex = "0047a2b4b844f46e9ad2846d373ae8508ded1842" },
        .{ .rounds = 80, .hex = "975e810488cf2a3d49838478124afce4b1c78804" },
    };
    for (cases) |c| try testing.expectEqualStrings(c.hex, &hexDigest("abc", c.rounds));
}

test "update() with random splits equals one shot, and blocks() equals update()" {
    var prng = std.Random.DefaultPrng.init(0x4841_53);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);

    for ([_]u32{ 80, 33, 1, 0 }) |rounds| {
        for (0..data.len + 1) |len| {
            var one: State = undefined;
            init(&one, rounds);
            update(&one, data[0..len]);
            var want: [digest_len]u8 = undefined;
            final(&one, &want);

            var st: State = undefined;
            init(&st, rounds);
            var pos: usize = 0;
            while (pos < len) {
                const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 70));
                update(&st, data[pos..][0..n]);
                pos += n;
            }
            var got: [digest_len]u8 = undefined;
            final(&st, &got);
            try testing.expectEqualSlices(u8, &want, &got);
            try testing.expectEqual(@as(u64, len), st.length);
        }
    }

    var a: State = undefined;
    init(&a, 80);
    update(&a, data[0..256]);
    var b: State = undefined;
    init(&b, 80);
    blocks(&b, data[0..256]);
    try testing.expectEqualSlices(u32, &a.hash, &b.hash);
    try testing.expectEqual(@as(u64, 0), b.length);
}

test "state after final matches the original (values from crypto-api 0.8.5)" {
    var st: State = undefined;
    init(&st, default_rounds);
    update(&st, "abc");
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    try testing.expectEqualStrings("975e810488cf2a3d49838478124afce4b1c78804", &std.fmt.bytesToHex(out, .lower));
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    const hash_after = [5]i32{ 75587223, 1026215816, 2021950281, -453228014, 76072881 };
    for (st.hash, hash_after) |w, want| try testing.expectEqual(want, @as(i32, @bitCast(w)));
    // A second final() runs another padded block on the advanced hash.
    final(&st, &out);
    try testing.expectEqualStrings("9c4b4a6865925485785efb1288e6cdbfcb39ee7e", &std.fmt.bytesToHex(out, .lower));
}
