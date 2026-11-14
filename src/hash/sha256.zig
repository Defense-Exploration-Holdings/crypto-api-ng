//! SHA-224 / SHA-256 as implemented by crypto-api 0.8.5 (`src/hasher/sha256.mjs`),
//! including the `rounds` option.
//!
//! The JS side normalizes options (`length || 256`, `rounds || 64`) and only
//! hands the wasm engine `length` 224 or 256 and `rounds` 1..64; everything
//! else (for example `length: 160`, which the original runs with the SHA-256
//! IV and cuts to five words, or `rounds: 80`, which reads undefined
//! constants) stays on the legacy JS engine.

const std = @import("std");
const be32 = @import("be32.zig");

pub const block_size = be32.block_size;
pub const max_rounds = 64;

pub const iv256 = [8]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};
pub const iv224 = [8]u32{
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

/// Initial hash words for `length` (224 selects SHA-224, anything else SHA-256,
/// like the `switch` in the original `reset()`).
pub fn initialHash(length: u32) [8]u32 {
    return if (length == 224) iv224 else iv256;
}

const K = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline fn rotr(x: u32, comptime n: u5) u32 {
    return std.math.rotr(u32, x, n);
}

/// Compress one block into `h`, running `rounds` steps (1..64).
pub fn compress(h: *[8]u32, block: *const [block_size]u8, rounds: u32) void {
    std.debug.assert(rounds >= 1 and rounds <= max_rounds);
    var w: [max_rounds]u32 = undefined;
    const m = be32.loadBlock(block);

    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    var f = h[5];
    var g = h[6];
    var hh = h[7];

    var i: u32 = 0;
    while (i < rounds) : (i += 1) {
        if (i < 16) {
            w[i] = m[i];
        } else {
            const x = w[i - 15];
            const y = w[i - 2];
            w[i] = w[i - 16] +% (rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)) +%
                w[i - 7] +% (rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10));
        }
        const t1 = hh +% (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) +% ((e & f) ^ (~e & g)) +% K[i] +% w[i];
        const t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) +% ((a & b) ^ (a & c) ^ (b & c));
        hh = g;
        g = f;
        f = e;
        e = d +% t1;
        d = c;
        c = b;
        b = a;
        a = t1 +% t2;
    }

    h[0] +%= a;
    h[1] +%= b;
    h[2] +%= c;
    h[3] +%= d;
    h[4] +%= e;
    h[5] +%= f;
    h[6] +%= g;
    h[7] +%= hh;
}

/// Compress every whole block in `data` (`data.len` must be a multiple of 64).
pub fn compressBlocks(h: *[8]u32, data: []const u8, rounds: u32) void {
    std.debug.assert(data.len % block_size == 0);
    var off: usize = 0;
    while (off < data.len) : (off += block_size) {
        compress(h, data[off..][0..block_size], rounds);
    }
}

/// Pad the buffered `tail` (< 64 bytes) like the original `finalize()` and
/// compress the one or two resulting blocks into `h`. `len_lo` is the total
/// message length in bytes modulo 2^32 (JS `state.length >>> 0`).
pub fn finalizeInto(h: *[8]u32, tail: []const u8, len_lo: u32, rounds: u32) void {
    var buf: [2 * block_size]u8 = undefined;
    compressBlocks(h, be32.finalTail(tail, len_lo, &buf), rounds);
}

/// One-shot digest. `length` is 224 or 256, the output has `length / 8` bytes.
pub fn hash(length: u32, data: []const u8, rounds: u32, out: []u8) void {
    var h = initialHash(length);
    const whole = data.len - data.len % block_size;
    compressBlocks(&h, data[0..whole], rounds);
    finalizeInto(&h, data[whole..], @truncate(data.len), rounds);
    var full: [32]u8 = undefined;
    be32.wordsToBytes(&h, &full);
    @memcpy(out[0 .. length / 8], full[0 .. length / 8]);
}

// ---- tests -----------------------------------------------------------------

fn expectHex(length: u32, input: []const u8, hex: []const u8) !void {
    var d: [32]u8 = undefined;
    hash(length, input, max_rounds, &d);
    var expected: [32]u8 = undefined;
    const exp = try std.fmt.hexToBytes(&expected, hex);
    try std.testing.expectEqualSlices(u8, exp, d[0..exp.len]);
}

test "SHA-256 known answers" {
    try expectHex(256, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    try expectHex(256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try expectHex(256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

test "SHA-224 known answers" {
    try expectHex(224, "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    try expectHex(224, "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
}

test "SHA-224/256 match std.crypto at every length around the block edges" {
    var buf: [300]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 197 +% 3);
    for (0..buf.len) |n| {
        var e256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(buf[0..n], &e256, .{});
        var e224: [28]u8 = undefined;
        std.crypto.hash.sha2.Sha224.hash(buf[0..n], &e224, .{});
        var got: [32]u8 = undefined;
        hash(256, buf[0..n], 64, &got);
        try std.testing.expectEqualSlices(u8, &e256, &got);
        hash(224, buf[0..n], 64, &got);
        try std.testing.expectEqualSlices(u8, &e224, got[0..28]);
    }
}
