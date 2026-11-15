//! SHA-224 / SHA-256, a faithful port of crypto-api 0.8.5 `src/hasher/sha256.mjs`,
//! including the `rounds` option.
//!
//! The JS facade normalizes options (`length || 256`, `rounds || 64`) and only
//! uses wasm for `length` 224 or 256 and `rounds` 1..64. Everything else (for
//! example `length: 160`, which the original runs with the SHA-256 IV and cuts
//! to five words, or `rounds: 80`, which reads undefined constants) stays on
//! the original JS code.
//!
//! `State` holds all eight words for both lengths; SHA-224 is SHA-256 with a
//! different IV and a 28-byte prefix of the digest, and the facade takes the
//! prefix, so `final` always writes 32 bytes.

const std = @import("std");
const be32 = @import("be32.zig");

pub const block_len = be32.block_size;
pub const digest_len = 32;
pub const max_rounds = 64;

pub const iv256 = [8]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};
pub const iv224 = [8]u32{
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

/// Layout is part of the wasm ABI (JS writes these offsets, see
/// packages/crypto-api/src/hasher/sha256.mjs); a change bumps `runtime.abi_version`.
pub const State = extern struct {
    /// a..h, stored as u32; JS exposes int32 like the original's JSON.
    hash: [8]u32,
    /// Steps per block, 1..64.
    rounds: u32,
    /// Total bytes passed to `update` (`be32.lengthField`).
    length: u64,
    /// Bytes currently buffered in `buf` (0..63).
    buffered: u32,
    _reserved: u32,
    buf: [block_len]u8,

    comptime {
        std.debug.assert(@sizeOf(State) == 120);
        std.debug.assert(@offsetOf(State, "hash") == 0);
        std.debug.assert(@offsetOf(State, "rounds") == 32);
        std.debug.assert(@offsetOf(State, "length") == 40);
        std.debug.assert(@offsetOf(State, "buffered") == 48);
        std.debug.assert(@offsetOf(State, "buf") == 56);
    }
};

/// Initial hash words for `length` (224 selects SHA-224, anything else SHA-256,
/// like the `switch` in the original `reset()`).
pub fn initialHash(length: u32) [8]u32 {
    return if (length == 224) iv224 else iv256;
}

pub const K = [64]u32{
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
pub fn compress(h: *[8]u32, block: *const [block_len]u8, rounds: u32) void {
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

pub fn init(st: *State, length: u32, rounds: u32) void {
    st.* = .{ .hash = initialHash(length), .rounds = rounds, .length = 0, .buffered = 0, ._reserved = 0, .buf = @splat(0) };
}

/// Compress whole blocks (`data.len % 64 == 0`) into `st.hash`, touching nothing
/// else. This is what the JS facade calls: buffering and counting stay in JS.
pub fn blocks(st: *State, data: []const u8) void {
    std.debug.assert(data.len % block_len == 0);
    var rest = data;
    while (rest.len >= block_len) : (rest = rest[block_len..]) {
        compress(&st.hash, rest[0..block_len], st.rounds);
    }
}

/// Absorb `data`, equivalent to the original `update()` for a binary string
/// whose code units are all <= 0xFF.
pub fn update(st: *State, data: []const u8) void {
    be32.update(State, blocks, st, data);
}

/// Pad, process the final block(s) and write all 32 digest bytes (SHA-224
/// callers use the first 28). Mutates `st` the way the original `finalize()`
/// mutates `this.state`.
pub fn final(st: *State, out: *[digest_len]u8) void {
    be32.finish(State, blocks, st);
    be32.wordsToBytes(&st.hash, out);
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

fn expectHex(length: u32, input: []const u8, hex: []const u8) !void {
    var expected: [digest_len]u8 = undefined;
    const exp = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, exp, digest(length, max_rounds, input)[0..exp.len]);
}

test "SHA-256 known answers (FIPS 180-4)" {
    try expectHex(256, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    try expectHex(256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try expectHex(256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

test "SHA-224 known answers (FIPS 180-4)" {
    try expectHex(224, "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    try expectHex(224, "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    try expectHex(224, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
}

test "SHA-224/256 match std.crypto at every length 0..300, one shot and split" {
    var prng = std.Random.DefaultPrng.init(0x256);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);
    for (0..data.len + 1) |len| {
        var w256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data[0..len], &w256, .{});
        var w224: [28]u8 = undefined;
        std.crypto.hash.sha2.Sha224.hash(data[0..len], &w224, .{});
        try testing.expectEqualSlices(u8, &w256, &digest(256, 64, data[0..len]));
        try testing.expectEqualSlices(u8, &w224, digest(224, 64, data[0..len])[0..28]);

        var st: State = undefined;
        init(&st, 256, 64);
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 70));
            update(&st, data[pos..][0..n]);
            pos += n;
        }
        var got: [digest_len]u8 = undefined;
        final(&st, &got);
        try testing.expectEqualSlices(u8, &w256, &got);
        try testing.expectEqual(@as(u64, len), st.length);
    }
}

test "K table equals the first 32 bits of the cube roots of the first 64 primes" {
    var count: usize = 0;
    var n: u64 = 2;
    while (count < 64) : (n += 1) {
        var is_prime = true;
        var d: u64 = 2;
        while (d * d <= n) : (d += 1) {
            if (n % d == 0) {
                is_prime = false;
                break;
            }
        }
        if (!is_prime) continue;
        // floor(frac(cbrt(n)) * 2^32) by integer search, no float error: the
        // largest x with x^3 <= n * 2^96 is floor(cbrt(n) * 2^32).
        const target: u128 = @as(u128, n) << 96;
        var lo: u128 = 0;
        var hi: u128 = (@as(u128, 1) << 32) * 9; // cbrt(311) < 7
        while (lo < hi) {
            const mid = lo + (hi - lo + 1) / 2;
            if (mid * mid * mid <= target) lo = mid else hi = mid - 1;
        }
        try testing.expectEqual(@as(u32, @truncate(lo)), K[count]);
        count += 1;
    }
}

test "reduced rounds: values captured from crypto-api 0.8.5" {
    const cases = [_]struct { length: u32, rounds: u32, hex: []const u8 }{
        .{ .length = 256, .rounds = 1, .hex = "c774d234257194ecf7d6a1f7e1bee8ac4b3898a1ec13bb0bba8942377b64a6c4" },
        .{ .length = 256, .rounds = 16, .hex = "1b0409f57bcc0e6315a1de882ce11eca5867604ca6985a9893de22897a384f31" },
        .{ .length = 256, .rounds = 33, .hex = "02eb0b6e2f1aea7a27081d944556006aede84875555e799e208d84e509c86150" },
        .{ .length = 256, .rounds = 63, .hex = "3da407ccc039fbf1f4cd205b5bfe85394c20648f2f928e42b5a3223f0dfc7a56" },
        .{ .length = 224, .rounds = 1, .hex = "cf9c51b2f78273df66edb21e277f365003f42d8f68182042cd51a4b8" },
        .{ .length = 224, .rounds = 40, .hex = "b4cda160af7f0ba33d9839bf213c8c2d00a3b2ec4250d7f15bbd2329" },
        .{ .length = 224, .rounds = 63, .hex = "be8ea1f38c4e9c67f704d991593bb7945508aa17e6cb231178d94830" },
    };
    for (cases) |c| {
        var expected: [digest_len]u8 = undefined;
        const exp = try std.fmt.hexToBytes(&expected, c.hex);
        try testing.expectEqualSlices(u8, exp, digest(c.length, c.rounds, "abc")[0..exp.len]);
    }
}

test "state after final matches the original (second final)" {
    var st: State = undefined;
    init(&st, 256, 64);
    update(&st, "abc");
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    final(&st, &out);
    try testing.expectEqualStrings("dc48a13efdba56ebe8244376313d20b0190adb650caf8846d981c06ab89be0d2", &std.fmt.bytesToHex(out, .lower));
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 120), @sizeOf(State));
    try testing.expectEqual(@as(usize, 32), @offsetOf(State, "rounds"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 48), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 56), @offsetOf(State, "buf"));
}
