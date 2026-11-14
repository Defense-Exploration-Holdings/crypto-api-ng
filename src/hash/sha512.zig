//! SHA-384 / SHA-512 / SHA-512/224 / SHA-512/256, a faithful port of crypto-api
//! 0.8.5 `src/hasher/sha512.mjs`, including the `rounds` option.
//!
//! One compression function serves all four: they differ only in the initial
//! hash words (chosen by `init`, or written by the JS facade, which gets them
//! from the original `reset()`) and in how many leading digest bytes are kept
//! (the facade takes them; `final` always writes all 64).
//!
//! `rounds` is the original's `options.rounds` (default 160). The original
//! counts it in 32-bit half-steps: its loop runs `i = 0, 2, 4, ... < rounds`,
//! i.e. `ceil(rounds / 2)` 64-bit steps, so 159 and 160 are the same and so are
//! 1 and 2. The JS facade only sends 1..160; larger values make the original
//! read undefined constants, so it keeps them on the original code.
//!
//! The hash words are stored the way the original keeps them in
//! `state.hash`: sixteen 32-bit words, high word first (`hash[2k]` is the high
//! half of the 64-bit word `k`). JS can then read and write them as int32
//! without any conversion, and the compression joins each pair into a u64.

const std = @import("std");
const be32 = @import("be32.zig");

pub const block_len = 128;
pub const digest_len = 64;
pub const max_rounds = 160;

/// Layout is part of the wasm ABI (JS writes these offsets, see
/// packages/crypto-api/src/hasher/sha512.mjs); a change bumps `runtime.abi_version`.
/// At 216 bytes it is larger than the 128-byte state slot of the scratch
/// region, so the facade reads the digest from `out` placed at the input offset
/// (see `src/wasm/common.zig`); `final` does not use the input region.
pub const State = extern struct {
    /// Eight 64-bit words as (high, low) int32 pairs, like the original's `state.hash`.
    hash: [16]u32,
    /// Half-steps per block, 1..160 (`ceil(rounds / 2)` 64-bit steps are run).
    rounds: u32,
    _reserved0: u32,
    /// Total bytes passed to `update`. Only the low 32 bits matter (`be32.lengthField`).
    length: u64,
    /// Bytes currently buffered in `buf` (0..127).
    buffered: u32,
    _reserved1: u32,
    buf: [block_len]u8,

    comptime {
        std.debug.assert(@sizeOf(State) == 216);
        std.debug.assert(@offsetOf(State, "hash") == 0);
        std.debug.assert(@offsetOf(State, "rounds") == 64);
        std.debug.assert(@offsetOf(State, "length") == 72);
        std.debug.assert(@offsetOf(State, "buffered") == 80);
        std.debug.assert(@offsetOf(State, "buf") == 88);
    }
};

/// Initial hash words (FIPS 180-4), as (high, low) pairs. The tests derive them
/// from the square roots of primes and, for 224/256, from the SHA-512/t IV
/// generation function, and compare them with what the original's `reset()` makes.
pub const iv512 = [16]u32{
    0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
    0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
};
pub const iv384 = [16]u32{
    0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
    0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
};
pub const iv512_224 = [16]u32{
    0x8c3d37c8, 0x19544da2, 0x73e19966, 0x89dcd4d6, 0x1dfab7ae, 0x32ff9c82, 0x679dd514, 0x582f9fcf,
    0x0f6d2b69, 0x7bd44da8, 0x77e36f73, 0x04c48942, 0x3f9d85a8, 0x6a1d36c8, 0x1112e6ad, 0x91d692a1,
};
pub const iv512_256 = [16]u32{
    0x22312194, 0xfc2bf72c, 0x9f555fa3, 0xc84c64c2, 0x2393b86b, 0x6f53b151, 0x96387719, 0x5940eabd,
    0x96283ee2, 0xa88effe3, 0xbe5e1e25, 0x53863992, 0x2b0199fc, 0x2c85b8aa, 0x0eb72ddc, 0x81c52ca2,
};

/// Initial hash words for the four standard `length` values (the original's
/// `reset()` also derives an IV for any other `length`; the facade leaves that
/// to the original code, so it never reaches here).
pub fn initialHash(length: u32) [16]u32 {
    return switch (length) {
        384 => iv384,
        224 => iv512_224,
        256 => iv512_256,
        else => iv512,
    };
}

pub const K = [80]u64{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

inline fn rotr(x: u64, comptime n: u6) u64 {
    return std.math.rotr(u64, x, n);
}

/// Compress one block into `h`, running `ceil(rounds / 2)` steps (`rounds` 1..160).
pub fn compress(h: *[16]u32, block: *const [block_len]u8, rounds: u32) void {
    std.debug.assert(rounds >= 1 and rounds <= max_rounds);
    const steps = (rounds + 1) / 2;
    var w: [80]u64 = undefined;

    var v: [8]u64 = undefined;
    inline for (0..8) |k| {
        v[k] = @as(u64, h[2 * k]) << 32 | h[2 * k + 1];
    }
    var a = v[0];
    var b = v[1];
    var c = v[2];
    var d = v[3];
    var e = v[4];
    var f = v[5];
    var g = v[6];
    var hh = v[7];

    var i: u32 = 0;
    while (i < steps) : (i += 1) {
        if (i < 16) {
            w[i] = std.mem.readInt(u64, block[i * 8 ..][0..8], .big);
        } else {
            const x = w[i - 15];
            const y = w[i - 2];
            w[i] = w[i - 16] +% (rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)) +%
                w[i - 7] +% (rotr(y, 19) ^ rotr(y, 61) ^ (y >> 6));
        }
        const t1 = hh +% (rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)) +% ((e & f) ^ (~e & g)) +% K[i] +% w[i];
        const t2 = (rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)) +% ((a & b) ^ (a & c) ^ (b & c));
        hh = g;
        g = f;
        f = e;
        e = d +% t1;
        d = c;
        c = b;
        b = a;
        a = t1 +% t2;
    }

    const out = [8]u64{ v[0] +% a, v[1] +% b, v[2] +% c, v[3] +% d, v[4] +% e, v[5] +% f, v[6] +% g, v[7] +% hh };
    inline for (0..8) |k| {
        h[2 * k] = @truncate(out[k] >> 32);
        h[2 * k + 1] = @truncate(out[k]);
    }
}

pub fn init(st: *State, length: u32, rounds: u32) void {
    st.* = .{ .hash = initialHash(length), .rounds = rounds, ._reserved0 = 0, .length = 0, .buffered = 0, ._reserved1 = 0, .buf = @splat(0) };
}

/// Compress whole blocks (`data.len % 128 == 0`) into `st.hash`, touching nothing
/// else. This is what the JS facade calls: buffering and counting stay in JS.
pub fn blocks(st: *State, data: []const u8) void {
    std.debug.assert(data.len % block_len == 0);
    var rest = data;
    while (rest.len >= block_len) : (rest = rest[block_len..]) {
        compress(&st.hash, rest[0..block_len], st.rounds);
    }
}

/// The bytes the original `finalize()` compresses after the buffered tail: ISO
/// 7816-4 padding (`0x80`, then zeros) up to offset 112 (or 240 when the tail
/// is 112 bytes or more), eight zero bytes, then the same 8-byte length field as
/// the 32-bit hashers (`be32.lengthField`, bug included). `tail` is shorter than
/// one block. Returns the 128 or 256 bytes that remain to be compressed.
pub fn finalTail(tail: []const u8, len_lo: u32, out: *[2 * block_len]u8) []const u8 {
    std.debug.assert(tail.len < block_len);
    @memset(out, 0);
    @memcpy(out[0..tail.len], tail);
    out[tail.len] = 0x80;
    const total: usize = if (tail.len < 112) block_len else 2 * block_len;
    out[total - 8 ..][0..8].* = be32.lengthField(len_lo);
    return out[0..total];
}

/// Absorb `data`, equivalent to the original `update()` for a binary string
/// whose code units are all <= 0xFF (same buffering as `be32.update`, for
/// 128-byte blocks).
pub fn update(st: *State, data: []const u8) void {
    st.length +%= data.len;
    var rest = data;

    if (st.buffered != 0) {
        const room = block_len - st.buffered;
        const n = @min(room, rest.len);
        @memcpy(st.buf[st.buffered..][0..n], rest[0..n]);
        st.buffered += @intCast(n);
        rest = rest[n..];
        if (st.buffered < block_len) return;
        blocks(st, &st.buf);
        st.buffered = 0;
    }

    const whole = rest.len - rest.len % block_len;
    blocks(st, rest[0..whole]);
    rest = rest[whole..];

    @memcpy(st.buf[0..rest.len], rest);
    st.buffered = @intCast(rest.len);
}

/// Pad, process the final block(s) and write all 64 digest bytes (SHA-384 and
/// SHA-512/t callers use a prefix). Mutates `st` the way the original
/// `finalize()` mutates `this.state`: the buffer is drained, the hash words are
/// advanced and `length` is untouched, so a second `final` or an `update` after
/// it gives what crypto-api 0.8.5 gives.
pub fn final(st: *State, out: *[digest_len]u8) void {
    std.debug.assert(st.buffered < block_len);
    var buf: [2 * block_len]u8 = undefined;
    blocks(st, finalTail(st.buf[0..st.buffered], @truncate(st.length), &buf));
    st.buffered = 0;
    @memset(&st.buf, 0);
    inline for (0..16) |i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], st.hash[i], .big);
    }
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn digest(length: u32, rounds: u32, data: []const u8) [digest_len]u8 {
    var st: State = undefined;
    init(&st, length, rounds);
    update(&st, data);
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    return out;
}

/// Digest bytes the original returns for `length` (`(length / 32) | 0` words).
fn expectHex(length: u32, input: []const u8, hex: []const u8) !void {
    var expected: [digest_len]u8 = undefined;
    const exp = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, exp, digest(length, max_rounds, input)[0..exp.len]);
}

test "SHA-512 known answers (FIPS 180-4)" {
    try expectHex(512, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    try expectHex(512, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    try expectHex(512, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

test "SHA-384 known answers (FIPS 180-4)" {
    try expectHex(384, "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    try expectHex(384, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    try expectHex(384, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
}

test "SHA-512/224 and SHA-512/256 known answers (FIPS 180-4)" {
    try expectHex(224, "abc", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    try expectHex(224, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");
    try expectHex(256, "abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    try expectHex(256, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");
}

test "all four match std.crypto at every length 0..300, one shot and split" {
    const sha2 = std.crypto.hash.sha2;
    var prng = std.Random.DefaultPrng.init(0x512);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);
    for (0..data.len + 1) |len| {
        var w512: [64]u8 = undefined;
        sha2.Sha512.hash(data[0..len], &w512, .{});
        var w384: [48]u8 = undefined;
        sha2.Sha384.hash(data[0..len], &w384, .{});
        var w224: [28]u8 = undefined;
        sha2.Sha512_224.hash(data[0..len], &w224, .{});
        var w256: [32]u8 = undefined;
        sha2.Sha512_256.hash(data[0..len], &w256, .{});
        try testing.expectEqualSlices(u8, &w512, &digest(512, 160, data[0..len]));
        try testing.expectEqualSlices(u8, &w384, digest(384, 160, data[0..len])[0..48]);
        try testing.expectEqualSlices(u8, &w224, digest(224, 160, data[0..len])[0..28]);
        try testing.expectEqualSlices(u8, &w256, digest(256, 160, data[0..len])[0..32]);

        var st: State = undefined;
        init(&st, 512, 160);
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 150));
            update(&st, data[pos..][0..n]);
            pos += n;
        }
        var got: [digest_len]u8 = undefined;
        final(&st, &got);
        try testing.expectEqualSlices(u8, &w512, &got);
        try testing.expectEqual(@as(u64, len), st.length);
    }
}

/// floor(r^(1/k) * 2^64) for small `r`, by integer bisection (no float error):
/// the largest x with x^k <= r * 2^(64 k).
fn rootFrac(r: u64, comptime k: u8) u64 {
    const Wide = u256;
    const target: Wide = @as(Wide, r) << (64 * k);
    var lo: Wide = 0;
    var hi: Wide = @as(Wide, 32) << 64; // r < 1024 here, so the root is below 32
    while (lo < hi) {
        const mid = lo + (hi - lo + 1) / 2;
        if (std.math.pow(Wide, mid, k) <= target) lo = mid else hi = mid - 1;
    }
    return @truncate(lo);
}

fn nthPrime(n: usize) u64 {
    var count: usize = 0;
    var cand: u64 = 2;
    while (true) : (cand += 1) {
        var is_prime = true;
        var d: u64 = 2;
        while (d * d <= cand) : (d += 1) {
            if (cand % d == 0) {
                is_prime = false;
                break;
            }
        }
        if (!is_prime) continue;
        if (count == n) return cand;
        count += 1;
    }
}

fn pair(words: *const [16]u32, k: usize) u64 {
    return @as(u64, words[2 * k]) << 32 | words[2 * k + 1];
}

test "K is the first 64 bits of the cube roots of the first 80 primes" {
    for (0..80) |i| try testing.expectEqual(rootFrac(nthPrime(i), 3), K[i]);
}

test "IVs: SHA-512 from sqrt of primes 1..8, SHA-384 from primes 9..16" {
    for (0..8) |k| {
        try testing.expectEqual(rootFrac(nthPrime(k), 2), pair(&iv512, k));
        try testing.expectEqual(rootFrac(nthPrime(8 + k), 2), pair(&iv384, k));
    }
}

test "IVs of SHA-512/224 and /256 come from the SHA-512/t generation function" {
    const cases = [_]struct { length: u32, iv: [16]u32, text: []const u8 }{
        .{ .length = 224, .iv = iv512_224, .text = "SHA-512/224" },
        .{ .length = 256, .iv = iv512_256, .text = "SHA-512/256" },
    };
    for (cases) |c| {
        var st: State = undefined;
        init(&st, 512, 160);
        for (&st.hash) |*x| x.* ^= 0xa5a5a5a5;
        update(&st, c.text);
        var out: [digest_len]u8 = undefined;
        final(&st, &out);
        var words: [16]u32 = undefined;
        for (&words, 0..) |*x, i| x.* = std.mem.readInt(u32, out[i * 4 ..][0..4], .big);
        try testing.expectEqualSlices(u32, &c.iv, &words);
        try testing.expectEqualSlices(u32, &c.iv, &initialHash(c.length));
    }
}

test "reduced rounds: values captured from crypto-api 0.8.5" {
    const cases = [_]struct { length: u32, rounds: u32, hex: []const u8 }{
        .{ .length = 512, .rounds = 1, .hex = "60b9b520b0b9a6fd257194ed78877043f7d6a1f8835f9f66e1bee8ad5db22f1ca9d954b4289ba262ec13bb0bd924eef0ba8942382680298a7b64a6c50ebfdee4" },
        .{ .length = 512, .rounds = 2, .hex = "60b9b520b0b9a6fd257194ed78877043f7d6a1f8835f9f66e1bee8ad5db22f1ca9d954b4289ba262ec13bb0bd924eef0ba8942382680298a7b64a6c50ebfdee4" },
        .{ .length = 512, .rounds = 3, .hex = "7d2adf31ef43f5c8b2177d3e41c78530a678d9daf251c13360b7a3bfe3e7de2c14e33e7cf64b92cbf3d06ac0a5f38bb070922c2ba928403cf6e635a53ebc8d98" },
        .{ .length = 512, .rounds = 17, .hex = "5bf68bbc40755b2d3bfb801b64cff6de00f64e7f7950ff9654a7303c9f5bc0be214e8eb93daa82d321fbdaefcc2f582979f051cb501e7d77f2d6cf22ca5a5733" },
        .{ .length = 512, .rounds = 33, .hex = "350200aa513cce3fc6482b0c35e2c3b03705726084357853e9748b6b847a63917efd1eeae7bcd0494280e48f89132d80a6cfd80b65f05c9ae1eb9cb8133890da" },
        .{ .length = 512, .rounds = 100, .hex = "34a5becab8c1d2201286e0c31b7e4782a7d8ef8eb317f6d79b6e5c60f3fb645830eee45a5f696916c21ae979977cc26f54aa1ce0bb7c8618229d028d210bcc13" },
        .{ .length = 512, .rounds = 159, .hex = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        .{ .length = 384, .rounds = 3, .hex = "fa4cc060c7a6c9b8a9a3bdd76704148f5d149eb7f1767bef77ca16032d8b2e40c54e747e94f736cf4bb841ac26b88b0a" },
        .{ .length = 384, .rounds = 64, .hex = "175ff449e545d2c5aef66209b5458ffb4d4655748198e5a3f958a81ca6f22f77e4272ebf052d91e1d0e139278866b3f5" },
        .{ .length = 224, .rounds = 16, .hex = "f63f2cad8ee1a7b6872ee73f9dc8febdb66eaa4d9b30c54aebe3b067" },
        .{ .length = 256, .rounds = 100, .hex = "f5ab04092434e96b43e953337109803cba8acdcfeb88b25cf0cc6355b07b9d37" },
    };
    for (cases) |c| {
        var expected: [digest_len]u8 = undefined;
        const exp = try std.fmt.hexToBytes(&expected, c.hex);
        try testing.expectEqualSlices(u8, exp, digest(c.length, c.rounds, "abc")[0..exp.len]);
    }
}

test "state after final matches the original (second final)" {
    var st: State = undefined;
    init(&st, 512, 160);
    update(&st, "abc");
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    final(&st, &out);
    try testing.expectEqualStrings("e7d716ecf244306d154a4f106efb7455539659529b73511be92399d9419a7982d218b6473ccde0a6a5ea80b1bb4bb5c1b206b5b0e2a7c9c88fd834ac99ddcf6f", &std.fmt.bytesToHex(out, .lower));
}

test "the 32-bit length field bug is kept: values captured from 0.8.5 with setState lengths" {
    const cases = [_]struct { len: u64, hex: []const u8 }{
        .{ .len = 1 << 31, .hex = "8c10f8843dfedc4321bf1edc708a08a1ec70f775e654e138c8829b2949fcb11f1de229ae0de51469d73edf2255429027295a3eea35e43a515b747aadc059956e" },
        .{ .len = (1 << 31) + 5, .hex = "12584ed1a96aadddde1f897dc2cf030f485780d18236b1f302029f41c51617eab3d32bff86b1c98769ff799a753980adc9e62fbf2c0ef6df0d14e6d16e41c5de" },
        // Bits above 2^32 are dropped (JS ToInt32): same field as length 7.
        .{ .len = (1 << 32) + 7, .hex = "2c91534291c75eea96922422a703594898a47236f42627a837efc291388880bad050be3f91c7b9df08a2ed74755fb3540c214ab490262ecca553d326431d23be" },
    };
    for (cases) |c| {
        var st: State = undefined;
        init(&st, 512, 160);
        @memcpy(st.buf[0..3], "abc");
        st.buffered = 3;
        st.length = c.len;
        var out: [digest_len]u8 = undefined;
        final(&st, &out);
        try testing.expectEqualStrings(c.hex, &std.fmt.bytesToHex(out, .lower));
    }
}

test "finalTail switches to two blocks at 112 bytes" {
    var buf: [2 * block_len]u8 = undefined;
    const zeros: [127]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 128), finalTail(zeros[0..111], 111, &buf).len);
    try testing.expectEqual(@as(usize, 256), finalTail(zeros[0..112], 112, &buf).len);
    try testing.expectEqual(@as(usize, 256), finalTail(zeros[0..127], 127, &buf).len);
    try testing.expectEqual(@as(usize, 128), finalTail("", 0, &buf).len);
    // 128-bit length field: the top eight bytes are always zero.
    const t = finalTail("abc", 3, &buf);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24 }, t[112..128]);
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 216), @sizeOf(State));
    try testing.expectEqual(@as(usize, 64), @offsetOf(State, "rounds"));
    try testing.expectEqual(@as(usize, 72), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 80), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 88), @offsetOf(State, "buf"));
}
