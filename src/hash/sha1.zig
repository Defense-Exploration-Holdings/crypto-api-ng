//! SHA-0 and SHA-1 as implemented by crypto-api 0.8.5 (`src/hasher/sha0.mjs`,
//! `src/hasher/sha1.mjs`), including the `rounds` option.
//!
//! `rounds` is the number of steps run per block, 1..80 (the original treats
//! `options.rounds || 80`, so 0 means 80; that normalization happens in JS).
//! Values outside 1..80 make the original read undefined constants, so the JS
//! façade keeps them on the legacy engine and this module never sees them.
//!
//! The only difference between the two algorithms is the 1-bit rotation in the
//! message schedule.

const std = @import("std");
const be32 = @import("be32.zig");

pub const Variant = enum(u32) { sha0 = 0, sha1 = 1 };

pub const digest_size = 20;
pub const block_size = be32.block_size;
pub const max_rounds = 80;

pub const iv = [5]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

const K = [4]u32{ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

/// Compress one block into `h`, running `rounds` steps (1..80).
pub fn compress(variant: Variant, h: *[5]u32, block: *const [block_size]u8, rounds: u32) void {
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

/// Compress every whole block in `data` (`data.len` must be a multiple of 64).
pub fn compressBlocks(variant: Variant, h: *[5]u32, data: []const u8, rounds: u32) void {
    std.debug.assert(data.len % block_size == 0);
    var off: usize = 0;
    while (off < data.len) : (off += block_size) {
        compress(variant, h, data[off..][0..block_size], rounds);
    }
}

/// Pad the buffered `tail` (< 64 bytes) like the original `finalize()` and
/// compress the one or two resulting blocks into `h`. `len_lo` is the total
/// message length in bytes modulo 2^32 (JS `state.length >>> 0`).
pub fn finalizeInto(variant: Variant, h: *[5]u32, tail: []const u8, len_lo: u32, rounds: u32) void {
    var buf: [2 * block_size]u8 = undefined;
    compressBlocks(variant, h, be32.finalTail(tail, len_lo, &buf), rounds);
}

/// One-shot digest with the original's behavior for the given `rounds`.
pub fn hash(variant: Variant, data: []const u8, rounds: u32) [digest_size]u8 {
    var h = iv;
    const whole = data.len - data.len % block_size;
    compressBlocks(variant, &h, data[0..whole], rounds);
    finalizeInto(variant, &h, data[whole..], @truncate(data.len), rounds);
    var out: [digest_size]u8 = undefined;
    be32.wordsToBytes(&h, &out);
    return out;
}

// ---- tests -----------------------------------------------------------------

fn expectHex(variant: Variant, rounds: u32, input: []const u8, hex: []const u8) !void {
    const d = hash(variant, input, rounds);
    var expected: [digest_size]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try std.testing.expectEqualSlices(u8, &expected, &d);
}

test "SHA-1 known answers" {
    try expectHex(.sha1, 80, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    try expectHex(.sha1, 80, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    try expectHex(.sha1, 80, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

test "SHA-0 known answers" {
    try expectHex(.sha0, 80, "abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
    try expectHex(.sha0, 80, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "d2516ee1acfa5baf33dfc1c471e438449ef134c8");
}

test "SHA-1 matches std.crypto at every length around the block edges" {
    var buf: [300]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    for (0..buf.len) |n| {
        var expected: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(buf[0..n], &expected, .{});
        try std.testing.expectEqualSlices(u8, &expected, &hash(.sha1, buf[0..n], 80));
    }
}

test "fewer rounds give a different, deterministic digest" {
    const d80 = hash(.sha1, "abc", 80);
    const d79 = hash(.sha1, "abc", 79);
    try std.testing.expect(!std.mem.eql(u8, &d80, &d79));
    try std.testing.expectEqualSlices(u8, &d79, &hash(.sha1, "abc", 79));
}
