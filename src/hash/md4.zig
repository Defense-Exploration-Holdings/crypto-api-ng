//! MD4 core, a faithful port of crypto-api 0.8.5 `src/hasher/md4.mjs`.
//!
//! Target-agnostic (no wasm/OS code). The wasm export wrapper is
//! `src/wasm/md.zig`. Padding, buffering and the original's 32-bit length
//! field quirk come from `le32.zig`.

const std = @import("std");
const le32 = @import("le32.zig");

const Core = le32.Hasher(4, iv, compress);

pub const block_len = le32.block_len;
pub const digest_len = Core.digest_len;
pub const State = Core.State;
pub const init = Core.init;
pub const update = Core.update;
pub const blocks = Core.blocks;
pub const final = Core.final;
pub const lengthField = le32.lengthField;

pub const iv = [4]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

const G: u32 = 0x5a827999;
const H: u32 = 0x6ed9eba1;

/// Shift amounts per round, repeated every four steps (the original's `S`).
const S = [3][4]u5{
    .{ 3, 7, 11, 19 },
    .{ 3, 5, 9, 13 },
    .{ 3, 9, 11, 15 },
};

/// Message word order for rounds 2 and 3.
const order2 = [16]u8{ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
const order3 = [16]u8{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };

fn compress(hash: *[4]u32, block: *const [le32.block_len]u8, param: u32) void {
    _ = param;
    const m = le32.loadWords(block);
    var v = hash.*; // a, b, c, d; rotated each step like the original's a/d/c/b sequence

    inline for (0..48) |i| {
        const round = i / 16;
        const idx = i % 16;
        // a is the variable being updated; the roles rotate as in the RFC.
        const a = (4 - i % 4) % 4;
        const b = (a + 1) % 4;
        const c = (a + 2) % 4;
        const d = (a + 3) % 4;
        const f: u32 = switch (round) {
            0 => (v[b] & v[c]) | (~v[b] & v[d]),
            1 => (v[b] & v[c]) | (v[b] & v[d]) | (v[c] & v[d]),
            else => v[b] ^ v[c] ^ v[d],
        };
        const k: u32 = switch (round) {
            0 => 0,
            1 => G,
            else => H,
        };
        const w = switch (round) {
            0 => m[idx],
            1 => m[order2[idx]],
            else => m[order3[idx]],
        };
        v[a] = std.math.rotl(u32, v[a] +% f +% w +% k, @as(u5, S[round][idx % 4]));
    }

    hash[0] +%= v[0];
    hash[1] +%= v[1];
    hash[2] +%= v[2];
    hash[3] +%= v[3];
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn hexDigest(data: []const u8) [32]u8 {
    var st: State = undefined;
    init(&st, 0);
    update(&st, data);
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    return std.fmt.bytesToHex(out, .lower);
}

test "RFC 1320 vectors" {
    const cases = [_]struct { in: []const u8, hex: []const u8 }{
        .{ .in = "", .hex = "31d6cfe0d16ae931b73c59d7e0c089c0" },
        .{ .in = "a", .hex = "bde52cb31de33e46245e05fbdbd6fb24" },
        .{ .in = "abc", .hex = "a448017aaf21d8525fc10ae87aa6729d" },
        .{ .in = "message digest", .hex = "d9130a8164549fe818874806e1c7014b" },
        .{ .in = "abcdefghijklmnopqrstuvwxyz", .hex = "d79e1c308aa5bbcdeea8ed63df412da9" },
        .{ .in = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", .hex = "043f8582f241db351ce627e153e7f0e4" },
        .{ .in = "12345678901234567890123456789012345678901234567890123456789012345678901234567890", .hex = "e33b4ddc9c38f2199c3e7b164fcc0536" },
    };
    for (cases) |c| try testing.expectEqualStrings(c.hex, &hexDigest(c.in));
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 96), @sizeOf(State));
    try testing.expectEqual(@as(usize, 16), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(State, "buf"));
}

test "update() with random splits equals one shot, and blocks() equals update() on whole blocks" {
    var prng = std.Random.DefaultPrng.init(0x4d44_34);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);

    for (0..data.len + 1) |len| {
        var one: State = undefined;
        init(&one, 0);
        update(&one, data[0..len]);
        var want: [digest_len]u8 = undefined;
        final(&one, &want);

        var st: State = undefined;
        init(&st, 0);
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

    var a: State = undefined;
    init(&a, 0);
    update(&a, data[0..256]);
    var b: State = undefined;
    init(&b, 0);
    blocks(&b, data[0..256]);
    try testing.expectEqualSlices(u32, &a.hash, &b.hash);
    try testing.expectEqual(@as(u64, 0), b.length);
}

test "state after final matches the original (values from crypto-api 0.8.5)" {
    var st: State = undefined;
    init(&st, 0);
    update(&st, "abc");
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    try testing.expectEqualStrings("a448017aaf21d8525fc10ae87aa6729d", &std.fmt.bytesToHex(out, .lower));
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    const hash_after = [4]i32{ 2046904484, 1389896111, -401948321, -1653430662 };
    for (st.hash, hash_after) |w, want| try testing.expectEqual(want, @as(i32, @bitCast(w)));
    // A second final() runs another padded block on the advanced hash.
    final(&st, &out);
    try testing.expectEqualStrings("7e72d0828101568be6c35565117321d3", &std.fmt.bytesToHex(out, .lower));
}
