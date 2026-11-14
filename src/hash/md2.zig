//! MD2 (RFC 1319), a faithful port of crypto-api 0.8.5 `src/hasher/md2.mjs`,
//! including the `rounds` option.
//!
//! MD2 is byte oriented: a 16-byte block, a 48-byte hash state and a 16-byte
//! checksum. Unlike every other hasher of the library it never looks at
//! `state.length`, so `State` has no length field and there is no 32-bit
//! length-field quirk to keep. `rounds` (default 18) is read by the original on
//! every block; the JS facade serves integers 1..2^32-1 and leaves the rest to
//! the original code.

const std = @import("std");

pub const block_len = 16;
pub const digest_len = 16;
pub const default_rounds = 18;

/// Layout is part of the wasm ABI (JS writes these offsets, see
/// packages/crypto-api/src/hasher/md2.mjs); a change bumps `runtime.abi_version`.
pub const State = extern struct {
    /// The 48-byte state `X`. JS mirrors it as `state.hash`, 48 numbers 0..255.
    hash: [48]u8,
    /// The 16-byte checksum `C`, `state.checksum` in JS.
    checksum: [16]u8,
    /// Rounds per block, 1..2^32-1 (the original runs 18 by default).
    rounds: u32,
    /// Bytes currently buffered in `buf` (0..15).
    buffered: u32,
    buf: [block_len]u8,

    comptime {
        std.debug.assert(@sizeOf(State) == 88);
        std.debug.assert(@offsetOf(State, "hash") == 0);
        std.debug.assert(@offsetOf(State, "checksum") == 48);
        std.debug.assert(@offsetOf(State, "rounds") == 64);
        std.debug.assert(@offsetOf(State, "buffered") == 68);
        std.debug.assert(@offsetOf(State, "buf") == 72);
    }
};

/// The S-box, "constants from Pi" (a permutation of 0..255).
pub const sbox = [256]u8{
    0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01, 0x3d, 0x36, 0x54, 0xa1, 0xec, 0xf0, 0x06, 0x13,
    0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7, 0x73, 0x8c, 0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c, 0x82, 0xca,
    0x1e, 0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16, 0x67, 0x42, 0x6f, 0x18, 0x8a, 0x17, 0xe5, 0x12,
    0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde, 0x49, 0xa0, 0xfb, 0xf5, 0x8e, 0xbb, 0x2f, 0xee, 0x7a,
    0xa9, 0x68, 0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f, 0x94, 0xc2, 0x10, 0x89, 0x0b, 0x22, 0x5f, 0x21,
    0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27, 0x35, 0x3e, 0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03,
    0xff, 0x19, 0x30, 0xb3, 0x48, 0xa5, 0xb5, 0xd1, 0xd7, 0x5e, 0x92, 0x2a, 0xac, 0x56, 0xaa, 0xc6,
    0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6, 0x76, 0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1,
    0x45, 0x9d, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8, 0x02,
    0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0, 0xb9, 0xf6, 0x1c, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f,
    0x55, 0x47, 0xa3, 0x23, 0xdd, 0x51, 0xaf, 0x3a, 0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26,
    0x2c, 0x53, 0x0d, 0x6e, 0x85, 0x28, 0x84, 0x09, 0xd3, 0xdf, 0xcd, 0xf4, 0x41, 0x81, 0x4d, 0x52,
    0x6a, 0xdc, 0x37, 0xc8, 0x6c, 0xc1, 0xab, 0xfa, 0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a,
    0x78, 0x88, 0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d, 0xe9, 0xcb, 0xd5, 0xfe, 0x3b, 0x00, 0x1d, 0x39,
    0xf2, 0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0, 0xe4, 0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a,
    0x31, 0x44, 0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a, 0xdb, 0x99, 0x8d, 0x33, 0x9f, 0x11, 0x83, 0x14,
};

pub fn init(st: *State, rounds: u32) void {
    st.* = .{ .hash = @splat(0), .checksum = @splat(0), .rounds = rounds, .buffered = 0, .buf = @splat(0) };
}

/// Compress one block into `hash` and `checksum`, like the original
/// `processBlock()`: `rounds` passes over the 48 bytes, then the checksum.
pub fn compress(hash: *[48]u8, checksum: *[16]u8, block: *const [block_len]u8, rounds: u32) void {
    for (0..16) |i| {
        hash[16 + i] = block[i];
        hash[32 + i] = block[i] ^ hash[i];
    }

    var t: u8 = 0;
    var r: u32 = 0;
    while (r < rounds) : (r += 1) {
        for (hash) |*x| {
            x.* ^= sbox[t];
            t = x.*;
        }
        // `(t + i) & 0xff` in the original; only the low byte of i matters.
        t +%= @truncate(r);
    }

    t = checksum[15];
    for (checksum, 0..) |*c, i| {
        c.* ^= sbox[block[i] ^ t];
        t = c.*;
    }
}

/// Compress whole blocks (`data.len % 16 == 0`) into `st.hash` and `st.checksum`,
/// touching nothing else. This is what the JS facade calls: buffering stays in JS.
pub fn blocks(st: *State, data: []const u8) void {
    std.debug.assert(data.len % block_len == 0);
    var rest = data;
    while (rest.len >= block_len) : (rest = rest[block_len..]) {
        compress(&st.hash, &st.checksum, rest[0..block_len], st.rounds);
    }
}

/// Absorb `data`, equivalent to the original `update()` for a binary string
/// whose code units are all <= 0xFF.
pub fn update(st: *State, data: []const u8) void {
    var rest = data;
    if (st.buffered != 0) {
        const n = @min(block_len - st.buffered, rest.len);
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

/// Pad (PKCS#7, 1..16 bytes), process the block, then process the checksum as
/// one more block and write the first 16 hash bytes to `out`. Mutates `st` the
/// way the original `finalize()` mutates `this.state`: the buffer is drained and
/// `hash` and `checksum` are advanced (the checksum block updates the checksum
/// again), so a second `final()` gives what 0.8.5 gives.
pub fn final(st: *State, out: *[digest_len]u8) void {
    std.debug.assert(st.buffered < block_len);
    const pad: u8 = @intCast(block_len - st.buffered);
    @memset(st.buf[st.buffered..], pad);
    compress(&st.hash, &st.checksum, &st.buf, st.rounds);

    const sum = st.checksum;
    compress(&st.hash, &st.checksum, &sum, st.rounds);

    st.buffered = 0;
    @memset(&st.buf, 0);
    out.* = st.hash[0..digest_len].*;
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

fn expectHex(rounds: u32, input: []const u8, hex: []const u8) !void {
    var expected: [digest_len]u8 = undefined;
    const exp = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, exp, &digest(rounds, input));
}

test "RFC 1319 test suite" {
    try expectHex(default_rounds, "", "8350e5a3e24c153df2275c9f80692773");
    try expectHex(default_rounds, "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1");
    try expectHex(default_rounds, "abc", "da853b0d3f88d99b30283a69e6ded6bb");
    try expectHex(default_rounds, "message digest", "ab4f496bfb2a530b219ff33031fe06b0");
    try expectHex(default_rounds, "abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b");
    try expectHex(default_rounds, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "da33def2a42df13975352846c30338cd");
    try expectHex(default_rounds, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "d5976f79d83d3a0dc9806c3c66f3efd8");
}

test "the S-box is a permutation of 0..255" {
    var seen: [256]bool = @splat(false);
    for (sbox) |x| seen[x] = true;
    for (seen) |s| try testing.expect(s);
}

test "streaming with random splits equals one shot, at every length 0..300" {
    var prng = std.Random.DefaultPrng.init(0x2d2);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);
    for (0..data.len + 1) |len| {
        const want = digest(default_rounds, data[0..len]);
        var st: State = undefined;
        init(&st, default_rounds);
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 40));
            update(&st, data[pos..][0..n]);
            pos += n;
        }
        var got: [digest_len]u8 = undefined;
        final(&st, &got);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 88), @sizeOf(State));
    try testing.expectEqual(@as(usize, 48), @offsetOf(State, "checksum"));
    try testing.expectEqual(@as(usize, 64), @offsetOf(State, "rounds"));
    try testing.expectEqual(@as(usize, 68), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 72), @offsetOf(State, "buf"));
}
