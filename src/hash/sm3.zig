//! SM3, a faithful port of crypto-api 0.8.5 `src/hasher/sm3.mjs`, including the
//! `rounds` option (1..64; the original runs `i < options.rounds` over the
//! 64-step round function, so larger values read past the expanded message).
//!
//! The message expansion always runs in full (68 + 64 words) whatever `rounds`
//! is, as in the original. The `length` option only truncates the output
//! (`(length / 32) | 0` words, taken by the JS facade for length 256 only) and
//! never touches the state, so `final` writes all 32 bytes.

const std = @import("std");
const be32 = @import("be32.zig");

pub const block_len = be32.block_size;
pub const digest_len = 32;
pub const max_rounds = 64;

/// Layout is part of the wasm ABI (JS writes these offsets, see
/// packages/crypto-api/src/hasher/sm3.mjs); a change bumps `runtime.abi_version`.
pub const State = extern struct {
    /// a..h, stored as u32; JS exposes int32 like the original's JSON.
    hash: [8]u32,
    /// Steps per block, 1..64.
    rounds: u32,
    /// Total bytes passed to `update`. Only the low 32 bits matter (`be32.lengthField`).
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

pub const iv = [8]u32{
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
};

pub fn init(st: *State, rounds: u32) void {
    st.* = .{ .hash = iv, .rounds = rounds, .length = 0, .buffered = 0, ._reserved = 0, .buf = @splat(0) };
}

inline fn rotl(x: u32, n: u5) u32 {
    return std.math.rotl(u32, x, n);
}

inline fn p0(x: u32) u32 {
    return x ^ rotl(x, 9) ^ rotl(x, 17);
}

inline fn p1(x: u32) u32 {
    return x ^ rotl(x, 15) ^ rotl(x, 23);
}

/// Compress one block into `h`, running `rounds` steps (1..64, caller checks).
pub fn compress(h: *[8]u32, block: *const [block_len]u8, rounds: u32) void {
    std.debug.assert(rounds >= 1 and rounds <= max_rounds);
    var w: [132]u32 = undefined;
    w[0..16].* = be32.loadBlock(block);
    for (16..68) |i| {
        w[i] = p1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^ rotl(w[i - 13], 7) ^ w[i - 6];
    }
    for (68..132) |i| {
        w[i] = w[i - 68] ^ w[i - 64];
    }

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
        const t: u32 = if (i < 16) 0x79cc4519 else 0x7a879d8a;
        const ss1 = rotl(rotl(a, 12) +% e +% rotl(t, @intCast(i % 32)), 7);
        const ss2 = ss1 ^ rotl(a, 12);
        const ff = if (i < 16) a ^ b ^ c else (a & b) | (a & c) | (b & c);
        const gg = if (i < 16) e ^ f ^ g else (e & f) | (~e & g);
        const tt1 = ff +% d +% ss2 +% w[i + 68];
        const tt2 = gg +% hh +% ss1 +% w[i];
        d = c;
        c = rotl(b, 9);
        b = a;
        a = tt1;
        hh = g;
        g = rotl(f, 19);
        f = e;
        e = p0(tt2);
    }

    h[0] ^= a;
    h[1] ^= b;
    h[2] ^= c;
    h[3] ^= d;
    h[4] ^= e;
    h[5] ^= f;
    h[6] ^= g;
    h[7] ^= hh;
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

/// Pad, process the final block(s) and write the 32-byte digest. Mutates `st`
/// the way the original `finalize()` mutates `this.state`.
pub fn final(st: *State, out: *[digest_len]u8) void {
    be32.finish(State, blocks, st);
    be32.wordsToBytes(&st.hash, out);
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn digest(rounds: u32, data: []const u8) [digest_len]u8 {
    var st: State = undefined;
    init(&st, rounds);
    update(&st, data);
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    return out;
}

fn expectHex(input: []const u8, hex: []const u8) !void {
    var expected: [digest_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, &expected, &digest(max_rounds, input));
}

test "SM3 known answers (GB/T 32905-2016 appendix A)" {
    try expectHex("abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    try expectHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
}

test "SM3 of the empty message" {
    try expectHex("", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
}

test "streaming splits give the same digest" {
    var prng = std.Random.DefaultPrng.init(0x53);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);
    for (0..data.len + 1) |len| {
        const want = digest(64, data[0..len]);
        var st: State = undefined;
        init(&st, 64);
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

test "reduced rounds: values captured from crypto-api 0.8.5" {
    const cases = [_]struct { rounds: u32, hex: []const u8 }{
        .{ .rounds = 1, .hex = "ca6dd7443a94a4d63e413045cdae44d71bc21948bf5e081626dd5fc45376e003" },
        .{ .rounds = 16, .hex = "47517f71354625c185913a9e4d10b713c896a6fa28d86199c92d3c1c6be815c8" },
        .{ .rounds = 17, .hex = "0aeaecde7dc5dba7b20ab22f483f7e49af1a604977c8aeec2a1419079a5bdc1f" },
        .{ .rounds = 33, .hex = "44a0ab21c0b58ce05e61259cedd33dff6612263f1c2ecdd844daa7221397cec3" },
        .{ .rounds = 63, .hex = "587a490f1777d9f211bea035bbced3bbe3acffb41ffde1f4dc3d48e35a19cab5" },
    };
    for (cases) |c| {
        var expected: [digest_len]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, c.hex);
        try testing.expectEqualSlices(u8, &expected, &digest(c.rounds, "abc"));
    }
}

test "state after final matches the original (second final)" {
    var st: State = undefined;
    init(&st, 64);
    update(&st, "abc");
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    final(&st, &out);
    try testing.expectEqualStrings("f07085a2bd19ce21abbbf55e45e3f49ebbc09113867a36c817b4262168b672a6", &std.fmt.bytesToHex(out, .lower));
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 120), @sizeOf(State));
    try testing.expectEqual(@as(usize, 32), @offsetOf(State, "rounds"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 48), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 56), @offsetOf(State, "buf"));
}
