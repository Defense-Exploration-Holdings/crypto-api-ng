//! SHA-0 and SHA-1, a faithful port of crypto-api 0.8.5 `src/hasher/sha0.mjs`
//! and `src/hasher/sha1.mjs`, including the `rounds` option.
//!
//! `rounds` is the number of steps run per block, 1..80 (the original uses
//! `options.rounds || 80`, so 0 means 80; JS normalizes that). Values outside
//! 1..80 make the original read undefined constants, so the JS facade keeps
//! those on the original code and this module never sees them.
//!
//! The only difference between the two algorithms is the 1-bit rotation in the
//! message schedule. `State` carries no variant: the wasm exports (`sha0_*`,
//! `sha1_*`) pick it.

const std = @import("std");
const be32 = @import("be32.zig");

pub const block_len = be32.block_size;
pub const digest_len = 20;
pub const max_rounds = 80;

pub const Variant = enum { sha0, sha1 };

/// Layout is part of the wasm ABI (JS writes these offsets, see
/// packages/crypto-api/src/hasher/sha1.mjs); a change bumps `runtime.abi_version`.
pub const State = extern struct {
    /// a..e, stored as u32; JS exposes int32 like the original's JSON.
    hash: [5]u32,
    /// Steps per block, 1..80.
    rounds: u32,
    /// Total bytes passed to `update`. Only the low 32 bits matter (`be32.lengthField`).
    length: u64,
    /// Bytes currently buffered in `buf` (0..63).
    buffered: u32,
    _reserved: u32,
    buf: [block_len]u8,

    comptime {
        std.debug.assert(@sizeOf(State) == 104);
        std.debug.assert(@offsetOf(State, "hash") == 0);
        std.debug.assert(@offsetOf(State, "rounds") == 20);
        std.debug.assert(@offsetOf(State, "length") == 24);
        std.debug.assert(@offsetOf(State, "buffered") == 32);
        std.debug.assert(@offsetOf(State, "buf") == 40);
    }
};

pub const iv = [5]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

const K = [4]u32{ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

pub fn init(st: *State, rounds: u32) void {
    st.* = .{ .hash = iv, .rounds = rounds, .length = 0, .buffered = 0, ._reserved = 0, .buf = @splat(0) };
}

/// Compress one block into `h`, running `rounds` steps (1..80, caller checks).
pub fn compress(comptime variant: Variant, h: *[5]u32, block: *const [block_len]u8, rounds: u32) void {
    std.debug.assert(rounds >= 1 and rounds <= max_rounds);
    var w: [max_rounds]u32 = undefined;
    const m = be32.loadBlock(block);

    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];

    var i: u32 = 0;
    while (i < rounds) : (i += 1) {
        if (i < 16) {
            w[i] = m[i];
        } else {
            const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = if (variant == .sha1) std.math.rotl(u32, x, 1) else x;
        }
        const f = switch (i / 20) {
            0 => (b & c) | (~b & d),
            1, 3 => b ^ c ^ d,
            else => (b & c) | (b & d) | (c & d),
        };
        const t = std.math.rotl(u32, a, 5) +% e +% w[i] +% K[i / 20] +% f;
        e = d;
        d = c;
        c = std.math.rotl(u32, b, 30);
        b = a;
        a = t;
    }

    h[0] +%= a;
    h[1] +%= b;
    h[2] +%= c;
    h[3] +%= d;
    h[4] +%= e;
}

/// Compress whole blocks (`data.len % 64 == 0`) into `st.hash`, touching nothing
/// else. This is what the JS facade calls: buffering and counting stay in JS.
pub fn blocks(comptime variant: Variant, st: *State, data: []const u8) void {
    std.debug.assert(data.len % block_len == 0);
    var rest = data;
    while (rest.len >= block_len) : (rest = rest[block_len..]) {
        compress(variant, &st.hash, rest[0..block_len], st.rounds);
    }
}

fn blocksFn(comptime variant: Variant) fn (*State, []const u8) void {
    return struct {
        fn f(st: *State, data: []const u8) void {
            blocks(variant, st, data);
        }
    }.f;
}

/// Absorb `data`, equivalent to the original `update()` for a binary string
/// whose code units are all <= 0xFF.
pub fn update(comptime variant: Variant, st: *State, data: []const u8) void {
    be32.update(State, blocksFn(variant), st, data);
}

/// Pad, process the final block(s) and write the 20-byte digest. Mutates `st`
/// the way the original `finalize()` mutates `this.state`.
pub fn final(comptime variant: Variant, st: *State, out: *[digest_len]u8) void {
    be32.finish(State, blocksFn(variant), st);
    be32.wordsToBytes(&st.hash, out);
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn digest(comptime variant: Variant, rounds: u32, data: []const u8) [digest_len]u8 {
    var st: State = undefined;
    init(&st, rounds);
    update(variant, &st, data);
    var out: [digest_len]u8 = undefined;
    final(variant, &st, &out);
    return out;
}

fn expectHex(comptime variant: Variant, input: []const u8, hex: []const u8) !void {
    var expected: [digest_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, &expected, &digest(variant, 80, input));
}

test "SHA-1 known answers (FIPS 180, RFC 3174)" {
    try expectHex(.sha1, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    try expectHex(.sha1, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    try expectHex(.sha1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

test "SHA-0 known answers (FIPS 180 of 1993)" {
    try expectHex(.sha0, "abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
    try expectHex(.sha0, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "d2516ee1acfa5baf33dfc1c471e438449ef134c8");
}

test "SHA-1 matches std.crypto at every length 0..300, one shot and split" {
    var prng = std.Random.DefaultPrng.init(0x5a1);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);
    for (0..data.len + 1) |len| {
        var want: [digest_len]u8 = undefined;
        std.crypto.hash.Sha1.hash(data[0..len], &want, .{});
        try testing.expectEqualSlices(u8, &want, &digest(.sha1, 80, data[0..len]));

        var st: State = undefined;
        init(&st, 80);
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 70));
            update(.sha1, &st, data[pos..][0..n]);
            pos += n;
        }
        var got: [digest_len]u8 = undefined;
        final(.sha1, &st, &got);
        try testing.expectEqualSlices(u8, &want, &got);
        try testing.expectEqual(@as(u64, len), st.length);
    }
}

test "reduced rounds: values captured from crypto-api 0.8.5" {
    // sha1/sha0 of "abc" with a reduced options.rounds (SHA-0 and SHA-1 agree up to 16 rounds, before the rotation matters).
    const cases = [_]struct { v: Variant, rounds: u32, hex: []const u8 }{
        .{ .v = .sha1, .rounds = 1, .hex = "685c1f345712ce8a14ae47e0a8ed3174d4053666" },
        .{ .v = .sha1, .rounds = 16, .hex = "8802f93009399a00fd051aa321b4420fdc9905e9" },
        .{ .v = .sha1, .rounds = 40, .hex = "9a233fbb3c660f8e8fd3c2cd14069c6cbb01ce22" },
        .{ .v = .sha1, .rounds = 79, .hex = "be7df8e275dacd5500d94af4e9304b239b8cbc15" },
        .{ .v = .sha0, .rounds = 16, .hex = "8802f93009399a00fd051aa321b4420fdc9905e9" },
        .{ .v = .sha0, .rounds = 79, .hex = "8c44a1d65ff6179090b4d61f3e4d6b0649d55768" },
    };
    inline for (cases) |c| try expectRounds(c.v, c.rounds, c.hex);
}

fn expectRounds(comptime variant: Variant, rounds: u32, hex: []const u8) !void {
    var expected: [digest_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, &expected, &digest(variant, rounds, "abc"));
}

test "state after final matches the original (second final, update after final)" {
    // Values captured from crypto-api 0.8.5.
    var st: State = undefined;
    init(&st, 80);
    update(.sha1, &st, "abc");
    var out: [digest_len]u8 = undefined;
    final(.sha1, &st, &out);
    try testing.expectEqualStrings("a9993e364706816aba3e25717850c26c9cd0d89d", &std.fmt.bytesToHex(out, .lower));
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    final(.sha1, &st, &out);
    try testing.expectEqualStrings("979fca7ba294b0df3d6cf73cc02c9be1caac0f5b", &std.fmt.bytesToHex(out, .lower));
}

test "blocks() matches update() on whole blocks and leaves length alone" {
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    var a: State = undefined;
    init(&a, 80);
    update(.sha1, &a, &data);
    var b: State = undefined;
    init(&b, 80);
    blocks(.sha1, &b, &data);
    try testing.expectEqualSlices(u32, &a.hash, &b.hash);
    try testing.expectEqual(@as(u64, 256), a.length);
    try testing.expectEqual(@as(u64, 0), b.length);
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 104), @sizeOf(State));
    try testing.expectEqual(@as(usize, 20), @offsetOf(State, "rounds"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(State, "buf"));
}
