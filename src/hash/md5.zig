//! MD5 core, a faithful port of crypto-api 0.8.5 `src/hasher/md5.mjs`.
//!
//! Target-agnostic (no wasm/OS code), so it is unit-tested natively. The wasm
//! export wrapper is `src/wasm/md.zig`.
//!
//! Where the original differs from RFC 1321 the port follows the original,
//! with one exception fixed in 1.1:
//!   * the bit-length field is the 64-bit bit count (`lengthField`). 0.8.5 and
//!     v1 built it from the 32-bit byte count with signed shifts, so messages
//!     of 2^31 bytes or more got a wrong field.
//!   * `final` leaves the state exactly as the original `finalize()` does
//!     (buffer drained, hash words advanced, `length` unchanged), so a second
//!     `final` call, or `update` after `final`, behaves like the original.
//!
//! `State` is a plain `extern struct` with a fixed layout. The JS facade does
//! not keep one per hasher: it fills the single scratch copy in wasm memory
//! from the hasher's original-format state for each call (docs/abi.md).

const std = @import("std");

pub const block_len = 64;
pub const digest_len = 16;

/// Layout is part of the wasm ABI: JS writes these offsets directly, so a
/// change here must bump `runtime.abi_version` and the offsets in
/// packages/crypto-api/src/hasher/md5.mjs.
pub const State = extern struct {
    /// a, b, c, d. Stored as u32; JS exposes them as int32 (the original's JSON).
    hash: [4]u32,
    /// Total bytes passed to `update`. The original keeps a JS Number (exact
    /// below 2^53), see `lengthField`.
    length: u64 align(8),
    /// Bytes currently buffered in `buf` (0..63).
    buffered: u32,
    _reserved: u32,
    buf: [block_len]u8,

    comptime {
        std.debug.assert(@sizeOf(State) == 96);
        std.debug.assert(@offsetOf(State, "hash") == 0);
        std.debug.assert(@offsetOf(State, "length") == 16);
        std.debug.assert(@offsetOf(State, "buffered") == 24);
        std.debug.assert(@offsetOf(State, "buf") == 32);
    }
};

pub const iv = [4]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

/// T[i] = floor(abs(sin(i + 1)) * 2^32). The original computes this with
/// `Math.sin` at load time; literals are used here so no float math is needed,
/// and a test pins them against `std.math.sin` for sanity.
const T = [64]u32{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

/// Per-round shift amounts, repeated every four steps.
const S = [4][4]u5{
    .{ 7, 12, 17, 22 },
    .{ 5, 9, 14, 20 },
    .{ 4, 11, 16, 23 },
    .{ 6, 10, 15, 21 },
};

pub fn init(st: *State) void {
    st.* = .{
        .hash = iv,
        .length = 0,
        .buffered = 0,
        ._reserved = 0,
        .buf = @splat(0),
    };
}

/// Absorb `data`. Equivalent to the original `update()` for a binary string
/// whose code units are all <= 0xFF.
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
        compress(&st.hash, &st.buf);
        st.buffered = 0;
    }

    const whole = rest.len - rest.len % block_len;
    blocks(&st.hash, rest[0..whole]);
    rest = rest[whole..];

    @memcpy(st.buf[0..rest.len], rest);
    st.buffered = @intCast(rest.len);
}

/// Process whole 64-byte blocks only, leaving `length` and the buffer alone.
/// This is what the JS facade calls: the facade keeps the original state
/// object (`{message, length, hash}`) and only borrows the compression
/// function, so buffering and counting stay in JS exactly as in 0.8.5.
pub fn blocks(hash: *[4]u32, data: []const u8) void {
    std.debug.assert(data.len % block_len == 0);
    var rest = data;
    while (rest.len >= block_len) : (rest = rest[block_len..]) {
        compress(hash, rest[0..block_len]);
    }
}

/// The 8 length bytes `Hasher32le.addLengthBits` appends after the padding:
/// the message length in bits as a 64-bit little-endian integer. `length` is
/// the byte count, exact below 2^53, so the multiplication cannot overflow.
/// (crypto-api 0.8.5 and v1 used 32-bit signed shifts here, which corrupted the
/// field for messages of 2 GiB or more.)
pub fn lengthField(length: u64) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, length *% 8, .little);
    return out;
}

/// Pad, process the final block(s) and write the 16-byte digest. Mutates `st`
/// the way the original `finalize()` mutates `this.state`.
pub fn final(st: *State, out: *[digest_len]u8) void {
    const n = st.buffered;
    // Original: ISO7816 padding of (56 - n) bytes if n < 56, else (120 - n),
    // i.e. 0x80 then zeros up to 56 mod 64, then the 8 length bytes.
    var tail: [2 * block_len]u8 = @splat(0);
    // The padded last block holds the message tail: do not leave it on the stack.
    defer std.crypto.secureZero(u8, &tail);
    @memcpy(tail[0..n], st.buf[0..n]);
    tail[n] = 0x80;
    const total: usize = if (n < 56) block_len else 2 * block_len;
    @memcpy(tail[total - 8 ..][0..8], &lengthField(st.length));

    compress(&st.hash, tail[0..block_len]);
    if (total == 2 * block_len) compress(&st.hash, tail[block_len..][0..block_len]);

    st.buffered = 0;
    @memset(&st.buf, 0);

    for (st.hash, 0..) |w, i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], w, .little);
    }
}

fn compress(hash: *[4]u32, block: *const [block_len]u8) void {
    var m: [16]u32 = undefined;
    for (&m, 0..) |*w, i| w.* = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);

    var a = hash[0];
    var b = hash[1];
    var c = hash[2];
    var d = hash[3];

    inline for (0..64) |i| {
        const round = i / 16;
        const f: u32 = switch (round) {
            0 => (b & c) | (~b & d),
            1 => (b & d) | (c & ~d),
            2 => b ^ c ^ d,
            else => c ^ (b | ~d),
        };
        const k: usize = switch (round) {
            0 => i,
            1 => (5 * i + 1) % 16,
            2 => (3 * i + 5) % 16,
            else => (7 * i) % 16,
        };
        const tmp = d;
        d = c;
        c = b;
        b = b +% std.math.rotl(u32, a +% f +% m[k] +% T[i], @as(u5, S[round][i % 4]));
        a = tmp;
    }

    hash[0] +%= a;
    hash[1] +%= b;
    hash[2] +%= c;
    hash[3] +%= d;
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn hexDigest(data: []const u8) [32]u8 {
    var st: State = undefined;
    init(&st);
    update(&st, data);
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    return std.fmt.bytesToHex(out, .lower);
}

test "RFC 1321 vectors" {
    const cases = [_]struct { in: []const u8, hex: []const u8 }{
        .{ .in = "", .hex = "d41d8cd98f00b204e9800998ecf8427e" },
        .{ .in = "a", .hex = "0cc175b9c0f1b6a831c399e269772661" },
        .{ .in = "abc", .hex = "900150983cd24fb0d6963f7d28e17f72" },
        .{ .in = "message digest", .hex = "f96b697d7cb7938d525a2f31aaf161d0" },
        .{ .in = "abcdefghijklmnopqrstuvwxyz", .hex = "c3fcd3d76192e4007dfb496cca67e13b" },
        .{ .in = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", .hex = "d174ab98d277d9f5a5611c2c9f419d9f" },
        .{ .in = "12345678901234567890123456789012345678901234567890123456789012345678901234567890", .hex = "57edf4a22be3c955ac49da2e2107b67a" },
    };
    for (cases) |c| try testing.expectEqualStrings(c.hex, &hexDigest(c.in));
}

test "T table matches floor(abs(sin(i + 1)) * 2^32)" {
    for (T, 0..) |t, i| {
        const x: f64 = @floatFromInt(i + 1);
        const want: u32 = @intFromFloat(@abs(std.math.sin(x)) * 4294967296.0);
        try testing.expectEqual(want, t);
    }
}

test "matches std.crypto Md5 at every length 0..300, one shot and split" {
    var prng = std.Random.DefaultPrng.init(0x4d44_35);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);

    for (0..data.len + 1) |len| {
        var want: [digest_len]u8 = undefined;
        std.crypto.hash.Md5.hash(data[0..len], &want, .{});

        // one shot
        var st: State = undefined;
        init(&st);
        update(&st, data[0..len]);
        var got: [digest_len]u8 = undefined;
        final(&st, &got);
        try testing.expectEqualSlices(u8, &want, &got);

        // random splits
        init(&st);
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 70));
            update(&st, data[pos..][0..n]);
            pos += n;
        }
        final(&st, &got);
        try testing.expectEqualSlices(u8, &want, &got);
        try testing.expectEqual(@as(u64, len), st.length);
    }
}

test "length field is the 64-bit little-endian bit count, also at and above 2 GiB" {
    const cases = [_]struct { len: u64, bytes: [8]u8 }{
        .{ .len = 0, .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 1, .bytes = .{ 8, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 55, .bytes = .{ 184, 1, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 64, .bytes = .{ 0, 2, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 1 << 29, .bytes = .{ 0, 0, 0, 0, 1, 0, 0, 0 } },
        .{ .len = (1 << 31) - 1, .bytes = .{ 248, 255, 255, 255, 3, 0, 0, 0 } },
        .{ .len = 1 << 31, .bytes = .{ 0, 0, 0, 0, 4, 0, 0, 0 } },
        .{ .len = (1 << 31) + 5, .bytes = .{ 40, 0, 0, 0, 4, 0, 0, 0 } },
        .{ .len = (1 << 32) - 1, .bytes = .{ 248, 255, 255, 255, 7, 0, 0, 0 } },
        .{ .len = 1 << 32, .bytes = .{ 0, 0, 0, 0, 8, 0, 0, 0 } },
        .{ .len = (1 << 32) + 7, .bytes = .{ 56, 0, 0, 0, 8, 0, 0, 0 } },
        .{ .len = 3 * (1 << 31) + 9, .bytes = .{ 72, 0, 0, 0, 12, 0, 0, 0 } },
        .{ .len = (1 << 40) + 3, .bytes = .{ 24, 0, 0, 0, 0, 8, 0, 0 } },
        .{ .len = (1 << 53) - 1, .bytes = .{ 248, 255, 255, 255, 255, 255, 255, 0 } },
    };
    for (cases) |c| try testing.expectEqualSlices(u8, &c.bytes, &lengthField(c.len));
}

test "length field equals the RFC 64-bit bit count for random lengths below 2^53" {
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    for (0..1000) |_| {
        const len = rnd.intRangeLessThan(u64, 0, 1 << 53);
        var want: [8]u8 = undefined;
        std.mem.writeInt(u64, &want, len * 8, .little);
        try testing.expectEqualSlices(u8, &want, &lengthField(len));
    }
}

test "state after final matches the original (second final, update after final)" {
    // Values captured from crypto-api 0.8.5.
    var st: State = undefined;
    init(&st);
    update(&st, "abc");
    var out: [digest_len]u8 = undefined;
    final(&st, &out);
    try testing.expectEqualStrings("900150983cd24fb0d6963f7d28e17f72", &std.fmt.bytesToHex(out, .lower));
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    const hash_after: [4]i32 = .{ -1739587184, -1336946116, 2101319382, 1920983336 };
    for (st.hash, hash_after) |w, want| try testing.expectEqual(want, @as(i32, @bitCast(w)));

    // Calling final again runs another padded block on the advanced state.
    final(&st, &out);
    try testing.expectEqualStrings("837ba8647cbc62e653ca9d33f21d90ab", &std.fmt.bytesToHex(out, .lower));

    // update after final keeps going from the advanced hash and the old length.
    init(&st);
    update(&st, "abc");
    final(&st, &out);
    update(&st, "abc");
    try testing.expectEqual(@as(u64, 6), st.length);
    try testing.expectEqual(@as(u32, 3), st.buffered);
    final(&st, &out);
    try testing.expectEqualStrings("6b63e5263cbc27fcfc216e60a1ee9519", &std.fmt.bytesToHex(out, .lower));
}

test "blocks() matches update() on whole blocks and leaves length alone" {
    var data: [256]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    var a: State = undefined;
    init(&a);
    update(&a, &data);
    var h = iv;
    blocks(&h, &data);
    try testing.expectEqualSlices(u32, &a.hash, &h);
    try testing.expectEqual(@as(u64, 256), a.length);
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 96), @sizeOf(State));
    try testing.expectEqual(@as(usize, 0), @offsetOf(State, "hash"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(State, "buf"));
}
