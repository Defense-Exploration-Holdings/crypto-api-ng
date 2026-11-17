//! Keccak-f[1600] and the sponge construction on top of it: SHA-3 and SHAKE
//! (FIPS 202) and the original Keccak padding (Ethereum's Keccak-256).
//!
//! The three families differ only in the rate (block size) and in the
//! domain-separation suffix byte that is appended to the message before the
//! final `10*1` padding:
//!
//!     SHA-3     0x06   (message bits 01, then pad)
//!     SHAKE     0x1f   (message bits 1111, then pad)
//!     Keccak    0x01   (no domain bits, the submission's padding)
//!
//! `State` carries no variant: the rate is set by `init`, the suffix is passed
//! to `final`. There is no buffer in it either. The JS facade keeps the unabsorbed
//! tail of the message in its own state, hands whole blocks to `blocks` and the
//! last partial block (shorter than the rate) to `final`, which pads, permutes
//! and squeezes. `final` is meant to run on a scratch copy of the State, so the
//! facade can finalize repeatedly and keep absorbing afterwards.
//!
//! The 25 lanes are 64-bit little-endian integers, which is how wasm memory
//! stores them, so JS can read and write them as 50 int32 words (low word of
//! lane `i` at index `2 * i`).

const std = @import("std");

pub const lane_count = 25;
pub const rounds = 24;

/// Domain-separation suffix bytes.
pub const suffix_sha3: u8 = 0x06;
pub const suffix_shake: u8 = 0x1f;
pub const suffix_keccak: u8 = 0x01;

/// Layout is part of the wasm ABI (JS writes these offsets, see
/// packages/crypto-api/src/wasm/keccak.mjs); a change bumps `runtime.abi_version`.
/// At 208 bytes it is larger than the 128-byte state slot of the scratch region, so
/// the facade puts the tail and the output above the input offset.
pub const State = extern struct {
    /// The sponge state, 1600 bits.
    lanes: [lane_count]u64 align(8),
    /// Block size in bytes: 200 minus twice the security level. A multiple of 8.
    rate: u32,
    /// Bytes of the current block already squeezed (0..rate); only used after `final`.
    pos: u32,

    comptime {
        std.debug.assert(@sizeOf(State) == 208);
        std.debug.assert(@offsetOf(State, "lanes") == 0);
        std.debug.assert(@offsetOf(State, "rate") == 200);
        std.debug.assert(@offsetOf(State, "pos") == 204);
    }
};

/// Rates the sponge accepts: whole lanes, and at least 8 bytes of capacity left.
pub fn validRate(rate: u32) bool {
    return rate >= 8 and rate <= 192 and rate % 8 == 0;
}

/// Round constants (FIPS 202, 3.2.5). A test derives them from the LFSR.
const RC = [rounds]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

/// Rotation offsets (rho), indexed `x + 5 * y`.
const rho = [lane_count]u6{
    0,  1,  62, 28, 27,
    36, 44, 6,  55, 20,
    3,  10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2,  61, 56, 14,
};

fn round(a: *[lane_count]u64, rc: u64) void {
    var c: [5]u64 = undefined;
    inline for (0..5) |x| c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    inline for (0..5) |x| {
        const d = c[(x + 4) % 5] ^ std.math.rotl(u64, c[(x + 1) % 5], 1);
        inline for (0..5) |y| a[x + 5 * y] ^= d;
    }
    // rho and pi: lane (x, y) moves to (y, 2x + 3y).
    var b: [lane_count]u64 = undefined;
    inline for (0..5) |x| {
        inline for (0..5) |y| {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = std.math.rotl(u64, a[x + 5 * y], rho[x + 5 * y]);
        }
    }
    // chi
    inline for (0..5) |y| {
        inline for (0..5) |x| {
            a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }
    }
    // iota
    a[0] ^= rc;
}

/// Keccak-f[1600].
pub fn permute(a: *[lane_count]u64) void {
    for (RC) |rc| round(a, rc);
}

/// Start a sponge with the given block size (`validRate`, caller checks).
pub fn init(st: *State, rate: u32) void {
    std.debug.assert(validRate(rate));
    st.* = .{ .lanes = @splat(0), .rate = rate, .pos = 0 };
}

/// Absorb whole blocks: `data.len` is a multiple of `st.rate`.
pub fn blocks(st: *State, data: []const u8) void {
    std.debug.assert(data.len % st.rate == 0);
    const rate: usize = st.rate;
    var off: usize = 0;
    while (off < data.len) : (off += rate) {
        var i: usize = 0;
        while (i < rate / 8) : (i += 1) {
            st.lanes[i] ^= std.mem.readInt(u64, data[off + i * 8 ..][0..8], .little);
        }
        permute(&st.lanes);
    }
}

fn xorByte(lanes: *[lane_count]u64, index: usize, value: u8) void {
    lanes[index / 8] ^= @as(u64, value) << @intCast(8 * (index % 8));
}

/// Absorb the last, partial block (`tail.len < st.rate`), apply the domain
/// suffix and the `10*1` padding, permute, and squeeze `out.len` bytes.
/// `suffix` is one of the `suffix_*` bytes (1..127).
pub fn final(st: *State, tail: []const u8, suffix: u8, out: []u8) void {
    std.debug.assert(tail.len < st.rate and suffix >= 1 and suffix < 0x80);
    for (tail, 0..) |byte, i| xorByte(&st.lanes, i, byte);
    xorByte(&st.lanes, tail.len, suffix);
    xorByte(&st.lanes, st.rate - 1, 0x80);
    permute(&st.lanes);
    st.pos = 0;
    squeeze(st, out);
}

/// Squeeze `out.len` more bytes. Callable repeatedly after `final`; the stream
/// continues where the last call stopped.
pub fn squeeze(st: *State, out: []u8) void {
    std.debug.assert(st.pos <= st.rate);
    var n: usize = 0;
    while (n < out.len) {
        if (st.pos == st.rate) {
            permute(&st.lanes);
            st.pos = 0;
        }
        const take = @min(st.rate - st.pos, out.len - n);
        for (0..take) |k| {
            const at = st.pos + k;
            out[n + k] = @truncate(st.lanes[at / 8] >> @intCast(8 * (at % 8)));
        }
        st.pos += @intCast(take);
        n += take;
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// One-shot digest: whole blocks through `blocks`, the rest through `final`.
fn sponge(rate: u32, suffix: u8, input: []const u8, out: []u8) void {
    var st: State = undefined;
    init(&st, rate);
    const whole = input.len - input.len % rate;
    blocks(&st, input[0..whole]);
    final(&st, input[whole..], suffix, out);
}

fn expectHex(rate: u32, suffix: u8, input: []const u8, hex: []const u8) !void {
    var expected: [512]u8 = undefined;
    const exp = try std.fmt.hexToBytes(&expected, hex);
    var got: [512]u8 = undefined;
    sponge(rate, suffix, input, got[0..exp.len]);
    try testing.expectEqualSlices(u8, exp, got[0..exp.len]);
}

test "SHA-3 known answers (FIPS 202 examples, NIST CSRC)" {
    try expectHex(144, suffix_sha3, "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    try expectHex(136, suffix_sha3, "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    try expectHex(104, suffix_sha3, "", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    try expectHex(72, suffix_sha3, "", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    try expectHex(144, suffix_sha3, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    try expectHex(136, suffix_sha3, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    try expectHex(104, suffix_sha3, "abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    try expectHex(72, suffix_sha3, "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
}

test "SHAKE and Keccak known answers" {
    // SHAKE128("") first 32 bytes, SHAKE256("") first 64 bytes (FIPS 202 examples).
    try expectHex(168, suffix_shake, "", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    try expectHex(136, suffix_shake, "", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    // Keccak-256("") and Keccak-256("abc") as used by Ethereum.
    try expectHex(136, suffix_keccak, "", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    try expectHex(136, suffix_keccak, "abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

test "round constants are the LFSR output of FIPS 202 algorithm 5" {
    const lfsr = struct {
        fn bit(t: usize) u64 {
            var r: u16 = 1;
            var i: usize = 0;
            while (i < t % 255) : (i += 1) {
                r <<= 1;
                if (r & 0x100 != 0) r ^= 0x171;
            }
            return r & 1;
        }
    };
    for (RC, 0..) |rc, ir| {
        var want: u64 = 0;
        for (0..7) |j| want |= lfsr.bit(j + 7 * ir) << @intCast((@as(u7, 1) << @intCast(j)) - 1);
        try testing.expectEqual(want, rc);
    }
}

test "rotation offsets follow the (t+1)(t+2)/2 walk of FIPS 202 algorithm 2" {
    var x: usize = 1;
    var y: usize = 0;
    var want: [lane_count]u6 = @splat(0);
    for (0..24) |t| {
        want[x + 5 * y] = @intCast(((t + 1) * (t + 2) / 2) % 64);
        const nx = y;
        const ny = (2 * x + 3 * y) % 5;
        x = nx;
        y = ny;
    }
    try testing.expectEqualSlices(u6, &want, &rho);
}

test "matches std.crypto at every length 0..450, one shot and split into blocks" {
    const sha3 = std.crypto.hash.sha3;
    var prng = std.Random.DefaultPrng.init(0x5ba3);
    const rnd = prng.random();
    var data: [450]u8 = undefined;
    rnd.bytes(&data);
    for (0..data.len + 1) |len| {
        const msg = data[0..len];
        var w224: [28]u8 = undefined;
        var w256: [32]u8 = undefined;
        var w384: [48]u8 = undefined;
        var w512: [64]u8 = undefined;
        var g: [64]u8 = undefined;
        sha3.Sha3_224.hash(msg, &w224, .{});
        sha3.Sha3_256.hash(msg, &w256, .{});
        sha3.Sha3_384.hash(msg, &w384, .{});
        sha3.Sha3_512.hash(msg, &w512, .{});
        sponge(144, suffix_sha3, msg, g[0..28]);
        try testing.expectEqualSlices(u8, &w224, g[0..28]);
        sponge(136, suffix_sha3, msg, g[0..32]);
        try testing.expectEqualSlices(u8, &w256, g[0..32]);
        sponge(104, suffix_sha3, msg, g[0..48]);
        try testing.expectEqualSlices(u8, &w384, g[0..48]);
        sponge(72, suffix_sha3, msg, g[0..64]);
        try testing.expectEqualSlices(u8, &w512, g[0..64]);

        // Original Keccak padding: std has 256 and 512, and a `delim` option for the rest.
        sha3.Sha3_224.hash(msg, &w224, .{ .delim = 0x01 });
        sha3.Sha3_384.hash(msg, &w384, .{ .delim = 0x01 });
        sha3.Keccak256.hash(msg, &w256, .{});
        sha3.Keccak512.hash(msg, &w512, .{});
        sponge(144, suffix_keccak, msg, g[0..28]);
        try testing.expectEqualSlices(u8, &w224, g[0..28]);
        sponge(136, suffix_keccak, msg, g[0..32]);
        try testing.expectEqualSlices(u8, &w256, g[0..32]);
        sponge(104, suffix_keccak, msg, g[0..48]);
        try testing.expectEqualSlices(u8, &w384, g[0..48]);
        sponge(72, suffix_keccak, msg, g[0..64]);
        try testing.expectEqualSlices(u8, &w512, g[0..64]);

        // SHAKE with outputs shorter than, equal to and longer than one rate.
        const out_len = rnd.intRangeAtMost(usize, 0, 400);
        var want: [400]u8 = undefined;
        var got: [400]u8 = undefined;
        sha3.Shake128.hash(msg, want[0..out_len], .{});
        sponge(168, suffix_shake, msg, got[0..out_len]);
        try testing.expectEqualSlices(u8, want[0..out_len], got[0..out_len]);
        sha3.Shake256.hash(msg, want[0..out_len], .{});
        sponge(136, suffix_shake, msg, got[0..out_len]);
        try testing.expectEqualSlices(u8, want[0..out_len], got[0..out_len]);
    }
}

test "squeezing in pieces gives the same stream as one call" {
    var prng = std.Random.DefaultPrng.init(0x5a9e);
    const rnd = prng.random();
    var whole: [1000]u8 = undefined;
    sponge(168, suffix_shake, "squeeze", &whole);
    for (0..50) |_| {
        var st: State = undefined;
        init(&st, 168);
        var got: [1000]u8 = undefined;
        const first = rnd.intRangeAtMost(usize, 0, 300);
        final(&st, "squeeze", suffix_shake, got[0..first]);
        var pos = first;
        while (pos < got.len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(got.len - pos, 400));
            squeeze(&st, got[pos..][0..n]);
            pos += n;
        }
        try testing.expectEqualSlices(u8, &whole, &got);
    }
}

test "final on a copy leaves the absorbed state reusable" {
    var st: State = undefined;
    init(&st, 136);
    blocks(&st, &@as([136]u8, @splat(7)));
    const before = st;
    var copy = st;
    var a: [32]u8 = undefined;
    final(&copy, "tail", suffix_sha3, &a);
    try testing.expectEqualSlices(u64, &before.lanes, &st.lanes);
    var again = st;
    var b: [32]u8 = undefined;
    final(&again, "tail", suffix_sha3, &b);
    try testing.expectEqualSlices(u8, &a, &b);
}

test "the empty-state permutation matches the Keccak-f[1600] test vector" {
    // First two permutations of the all-zero state (keccak team, KeccakF-1600-IntermediateValues).
    var a: [lane_count]u64 = @splat(0);
    permute(&a);
    try testing.expectEqual(@as(u64, 0xF1258F7940E1DDE7), a[0]);
    try testing.expectEqual(@as(u64, 0x84D5CCF933C0478A), a[1]);
    permute(&a);
    try testing.expectEqual(@as(u64, 0x2D5C954DF96ECB3C), a[0]);
    try testing.expectEqual(@as(u64, 0x6A332CD07057B56D), a[1]);
}

test "validRate" {
    for ([_]u32{ 72, 104, 136, 144, 168 }) |r| try testing.expect(validRate(r));
    for ([_]u32{ 0, 4, 7, 73, 200, 208 }) |r| try testing.expect(!validRate(r));
}
