//! Snefru (Merkle, 1990) as crypto-api 0.8.5 implements it: Snefru v2.0
//! (2 rounds for 128 bits, 4 rounds for 256 bits) and v2.5 (8 rounds), with
//! any digest length of 32..480 bits in steps of 32 and `rounds` 1..8.
//!
//! What the original does, and this file reproduces bit for bit:
//!
//!   * 16 S-boxes of 256 words, generated when the module loads by shuffling
//!     the four byte columns with digits taken from the RAND table (see
//!     `sbox`, built at comptime from `snefru_rand.zig`).
//!   * The block is `16 - words` big-endian words (`words` = digest words
//!     = `length / 32`), so the block size shrinks as the digest grows.
//!   * `finalize()`: zero-pad a non-empty tail to a full block, then one more
//!     block of zeros that ends in the 8 length bytes of `Hasher32be.addLengthBits`
//!     (the 64-bit bit count, see `lengthField`).
//!
//! `State` layout (a wasm ABI contract with packages/crypto-api/src/hasher/snefru.mjs):
//!
//!     hash: [15]u32     at 0     (only the first `words` are used)
//!     words: u8         at 60    digest words, 1..15
//!     rounds: u8        at 61    1..8
//!     buffered: u8      at 62    bytes in `buf`
//!     _pad: u8          at 63
//!     length: u32       at 64    ToInt32 of the JS length (all the original ever reads)
//!     buf: [60]u8       at 68    block size is at most 60 bytes (words = 1)
//!
//! 128 bytes, exactly the size of the scratch State area.

const std = @import("std");
const rand = @import("snefru_rand.zig");

pub const max_words = 15;
pub const max_block = 60;
pub const max_rounds = 8;

// ---- S-boxes -----------------------------------------------------------------

/// The generator state of the original: `randomIndex` / `count5` walk the RAND
/// table five decimal digits per entry.
const Digits = struct {
    index: usize = 0,
    count5: i32 = 4,

    /// `getRandomDigit()`
    fn digit(self: *Digits) u32 {
        if (self.count5 < 0) {
            self.count5 = 4;
            self.index += 1;
        }
        const pow10 = [_]u32{ 1, 10, 100, 1000, 10000, 100000 };
        const c: usize = @intCast(self.count5);
        self.count5 -= 1;
        return (rand.table[self.index] % pow10[c + 1]) / pow10[c];
    }

    /// `getRandomNumber(low, high)`: uniform in low..=high by rejection sampling on decimal digits.
    fn number(self: *Digits, low: u32, high: u32) u32 {
        const range = high - low + 1;
        var r: u32 = 0;
        while (true) {
            r = 0;
            var max: u32 = 1;
            while (max < range) : (max *= 10) {
                r = r * 10 + self.digit();
            }
            if (r < (max / range) * range) break;
        }
        return low + r % range;
    }
};

/// `generateSbox(16)` of the original: `sbox[i][row]` packs one byte of each of
/// four permutations of 0..255, one per byte column.
pub const sbox: [16][256]u32 = blk: {
    @setEvalBranchQuota(2_000_000_000);
    var digits = Digits{};
    var boxes: [16][256]u32 = undefined;
    for (&boxes) |*box| {
        for (box, 0..) |*cell, row| cell.* = @as(u32, @intCast(row)) * 0x01010101;
        var col: i32 = 3;
        while (col >= 0) : (col -= 1) {
            const mask: u32 = @as(u32, 0xff) << @intCast(col * 8);
            for (0..255) |row| {
                const temp = box[row];
                const row2 = digits.number(@intCast(row), 255);
                box[row] = (box[row] & ~mask) | (box[row2] & mask);
                box[row2] = (box[row2] & ~mask) | (temp & mask);
            }
        }
    }
    break :blk boxes;
};

// ---- compression -------------------------------------------------------------

const shift_table = [4]u5{ 16, 8, 16, 24 };

/// `Snefru.processBlock`: `hash` (the first `words` entries) and `block`
/// (`16 - words` big-endian words) fill the 16-word working array, `rounds`
/// rounds mix it, and the last `words` words are folded back into `hash`.
pub fn compress(hash: *[max_words]u32, words: usize, block: []const u8, rounds: usize) void {
    var w: [16]u32 = undefined;
    for (0..words) |i| w[i] = hash[i];
    for (words..16) |i| w[i] = std.mem.readInt(u32, block[(i - words) * 4 ..][0..4], .big);

    for (0..rounds) |r| {
        const i = 2 * r;
        inline for (shift_table) |shift| {
            // Unrolled with comptime indices so the 16 words live in registers.
            inline for (0..16) |n| {
                const sbe = sbox[i + (n / 2) % 2][w[n] & 0xff];
                w[(n + 15) & 15] ^= sbe;
                w[(n + 1) & 15] ^= sbe;
            }
            inline for (0..16) |n| w[n] = std.math.rotr(u32, w[n], shift);
        }
    }

    for (0..words) |i| hash[i] ^= w[15 - i];
}

// ---- hasher ------------------------------------------------------------------

pub const State = extern struct {
    hash: [max_words]u32,
    words: u8,
    rounds: u8,
    buffered: u8,
    _pad: u8 = 0,
    /// Total bytes passed to `update`, modulo 2^32. The JS facade only uses
    /// the wasm `final` for lengths below 2^32, see `lengthField`.
    length: u32,
    buf: [max_block]u8,

    comptime {
        std.debug.assert(@offsetOf(State, "hash") == 0);
        std.debug.assert(@offsetOf(State, "words") == 60);
        std.debug.assert(@offsetOf(State, "rounds") == 61);
        std.debug.assert(@offsetOf(State, "buffered") == 62);
        std.debug.assert(@offsetOf(State, "length") == 64);
        std.debug.assert(@offsetOf(State, "buf") == 68);
        std.debug.assert(@sizeOf(State) == 128); // exactly the scratch State area
    }

    /// Block size in bytes: `(16 - words) * 4`.
    pub fn blockLen(st: *const State) usize {
        return (16 - @as(usize, st.words)) * 4;
    }

    /// True when the fields a caller may have written are in the range the
    /// functions below are defined for. Exports check this so that a bad State
    /// returns a `Status` instead of reading out of bounds in `small` builds.
    pub fn valid(st: *const State) bool {
        return st.words >= 1 and st.words <= max_words and st.rounds >= 1 and st.rounds <= max_rounds and
            st.buffered < st.blockLen();
    }
};

/// The 8 length bytes `Hasher32be.addLengthBits` appends: the bit count as a
/// 64-bit big-endian integer. `State.length` is 32 bits wide, so longer
/// messages are finalized by the JS code (crypto-api 0.8.5 and v1 used 32-bit
/// signed shifts here, which corrupted the field from 2 GiB up).
pub fn lengthField(length: u32) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, @as(u64, length) * 8, .big);
    return out;
}

/// A fresh hasher: what `reset()` leaves (all hash words zero).
pub fn init(st: *State, words: u8, rounds: u8) void {
    st.* = .{
        .hash = @splat(0),
        .words = words,
        .rounds = rounds,
        .buffered = 0,
        .length = 0,
        .buf = @splat(0),
    };
}

/// Absorb `data`. Equivalent to the original `update()` for a binary string
/// whose code units are all <= 0xFF.
pub fn update(st: *State, data: []const u8) void {
    const bl = st.blockLen();
    st.length +%= @truncate(data.len);
    var rest = data;

    if (st.buffered != 0) {
        const room = bl - st.buffered;
        const n = @min(room, rest.len);
        @memcpy(st.buf[st.buffered..][0..n], rest[0..n]);
        st.buffered += @intCast(n);
        rest = rest[n..];
        if (st.buffered < bl) return;
        compress(&st.hash, st.words, st.buf[0..bl], st.rounds);
        st.buffered = 0;
    }

    const whole = rest.len - rest.len % bl;
    blocks(st, rest[0..whole]);
    rest = rest[whole..];

    @memcpy(st.buf[0..rest.len], rest);
    st.buffered = @intCast(rest.len);
}

/// Process whole blocks only, touching nothing but `st.hash` (and reading
/// `words` and `rounds`). This is what the JS facade calls: it keeps the
/// original state object and only borrows the compression function.
pub fn blocks(st: *State, data: []const u8) void {
    const bl = st.blockLen();
    std.debug.assert(data.len % bl == 0);
    var rest = data;
    while (rest.len >= bl) : (rest = rest[bl..]) {
        compress(&st.hash, st.words, rest[0..bl], st.rounds);
    }
}

/// Pad, process the final block(s) and write the `4 * words` digest bytes.
/// Mutates `st` the way the original `finalize()` mutates `this.state`.
///
/// The original cannot finalize when the block is smaller than the 8 length
/// bytes (`words` = 15: `addPaddingZero(-4)` throws RangeError), so this
/// requires `words <= 14`; the facade leaves that case to the original code.
pub fn final(st: *State, out: []u8) void {
    std.debug.assert(st.words <= 14);
    const bl = st.blockLen();
    const n: usize = st.buffered;
    var tail: [max_block]u8 = @splat(0);

    if (n > 0) {
        // The tail, zero-padded to a full block.
        @memcpy(tail[0..n], st.buf[0..n]);
        compress(&st.hash, st.words, tail[0..bl], st.rounds);
        @memset(tail[0..n], 0);
    }
    // One block of zeros ending in the length field.
    @memcpy(tail[bl - 8 ..][0..8], &lengthField(st.length));
    compress(&st.hash, st.words, tail[0..bl], st.rounds);

    st.buffered = 0;
    @memset(&st.buf, 0);

    for (0..st.words) |i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], st.hash[i], .big);
    }
}

// ---- tests -------------------------------------------------------------------

const testing = std.testing;

/// FNV-1a over the four bytes of each word of a table, least significant byte
/// first. The expected values below come from running `generateSbox()` of the
/// original (`node scripts/gen-snefru-rand.mjs --dump`).
fn fnv(table: *const [256]u32) u32 {
    var h: u32 = 0x811c9dc5;
    for (table) |v| {
        inline for (.{ 0, 8, 16, 24 }) |sh| {
            h = (h ^ ((v >> sh) & 0xff)) *% 0x01000193;
        }
    }
    return h;
}

test "S-boxes equal the ones the original generates at load time" {
    const expected = [16]struct { fnv: u32, first: [4]u32, last: u32 }{
        .{ .fnv = 0xa7fe8cd5, .first = .{ 0x64f9001b, 0xfeddcdf6, 0x7c8ff1e2, 0x11d71514 }, .last = 0x8211cefd },
        .{ .fnv = 0x5bd56bed, .first = .{ 0x074a1d09, 0x52a10e5a, 0x9275a3f8, 0x4b82506c }, .last = 0xff1a3a96 },
        .{ .fnv = 0x4df3c821, .first = .{ 0x4a8fe4e3, 0xf27d99cd, 0xd04a40ca, 0xcb5ff194 }, .last = 0x2eef261a },
        .{ .fnv = 0x7332c4c1, .first = .{ 0x5a79392b, 0xb8af32c2, 0x41f7720a, 0x833a61ec }, .last = 0xff64dfd6 },
        .{ .fnv = 0x8eb3e941, .first = .{ 0xcb2297cb, 0xdb48a144, 0xa16cbe4b, 0xbbea1d6c }, .last = 0x4d673c1d },
        .{ .fnv = 0x7d0dbd81, .first = .{ 0x4b4f1121, 0xba183081, 0xc784f41f, 0xd17d0bac }, .last = 0x5471d8a2 },
        .{ .fnv = 0xa3779dd1, .first = .{ 0x83a327a1, 0x9f379f51, 0x40a7d007, 0x11307423 }, .last = 0xea5a54f1 },
        .{ .fnv = 0x25382e09, .first = .{ 0x7e672590, 0xbea513bb, 0x2c906fe6, 0x86029c2b }, .last = 0x1e56a1f6 },
        .{ .fnv = 0x0310fbc1, .first = .{ 0xbaa20b6c, 0x9ffbad26, 0xe1f7d738, 0x794aec8d }, .last = 0x8456fb65 },
        .{ .fnv = 0x29c65a1d, .first = .{ 0xb29bea74, 0xc35da605, 0x305c1ca3, 0xd2e9f5bc }, .last = 0x6d2ebdf0 },
        .{ .fnv = 0x6133eb79, .first = .{ 0x0d188a6d, 0x12cea0db, 0x7e63740e, 0x6a444821 }, .last = 0x7c1ff8d9 },
        .{ .fnv = 0xad4da665, .first = .{ 0x12113f2e, 0xbfbd0785, 0xf11793fb, 0xa5bff566 }, .last = 0x954ddb44 },
        .{ .fnv = 0xec6415f1, .first = .{ 0x7b0bdffe, 0x865d16b1, 0x49a058c0, 0x97abaa3f }, .last = 0x936993ef },
        .{ .fnv = 0x865628f1, .first = .{ 0x472e91cb, 0x5444b5b6, 0x62be5861, 0x1be102c7 }, .last = 0x0d688ced },
        .{ .fnv = 0x25c680b5, .first = .{ 0xabc59484, 0x4107778a, 0x8ad94c6f, 0xfe83df90 }, .last = 0xaf6f5afc },
        .{ .fnv = 0x24b92ce5, .first = .{ 0x519aa8b5, 0xbb303da9, 0xe00e2b10, 0xdfa6c1db }, .last = 0x4d87253c },
    };
    for (expected, 0..) |e, i| {
        try testing.expectEqual(e.fnv, fnv(&sbox[i]));
        try testing.expectEqualSlices(u32, &e.first, sbox[i][0..4]);
        try testing.expectEqual(e.last, sbox[i][255]);
    }
}

test "every S-box byte column is a permutation of 0..255" {
    for (sbox) |box| {
        for (0..4) |col| {
            var seen: [256]bool = @splat(false);
            for (box) |v| seen[(v >> @intCast(col * 8)) & 0xff] = true;
            for (seen) |s| try testing.expect(s);
        }
    }
}

test "layout" {
    try testing.expectEqual(@as(usize, 128), @sizeOf(State));
}

test "length field is the 64-bit big-endian bit count, also at and above 2 GiB" {
    const cases = [_]struct { len: u32, bytes: [8]u8 }{
        .{ .len = 0, .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 1, .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 8 } },
        .{ .len = 55, .bytes = .{ 0, 0, 0, 0, 0, 0, 1, 184 } },
        .{ .len = 1 << 29, .bytes = .{ 0, 0, 0, 1, 0, 0, 0, 0 } },
        .{ .len = (1 << 31) - 1, .bytes = .{ 0, 0, 0, 3, 255, 255, 255, 248 } },
        .{ .len = 1 << 31, .bytes = .{ 0, 0, 0, 4, 0, 0, 0, 0 } },
        .{ .len = (1 << 31) + 5, .bytes = .{ 0, 0, 0, 4, 0, 0, 0, 40 } },
        .{ .len = 0xffff_ffff, .bytes = .{ 0, 0, 0, 7, 255, 255, 255, 248 } },
    };
    for (cases) |c| try testing.expectEqualSlices(u8, &c.bytes, &lengthField(c.len));
}

test "length field equals the 64-bit bit count for random 32-bit lengths" {
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    for (0..1000) |_| {
        const len = rnd.int(u32);
        var want: [8]u8 = undefined;
        std.mem.writeInt(u64, &want, @as(u64, len) * 8, .big);
        try testing.expectEqualSlices(u8, &want, &lengthField(len));
    }
}

fn hexDigest(words: u8, rounds: u8, data: []const u8, buf: []u8) []const u8 {
    var st: State = undefined;
    init(&st, words, rounds);
    update(&st, data);
    final(&st, buf);
    return buf[0 .. 4 * @as(usize, words)];
}

fn expectDigest(words: u8, rounds: u8, data: []const u8, want_hex: []const u8) !void {
    var buf: [60]u8 = undefined;
    const got = hexDigest(words, rounds, data, &buf);
    var want: [60]u8 = undefined;
    const w = try std.fmt.hexToBytes(&want, want_hex);
    try testing.expectEqualSlices(u8, w, got);
}

test "vectors of the original test suite (snefru128/2, 128/8, 256/4, 256/8)" {
    try expectDigest(4, 8, "", "8617f366566a011837f4fb4ba5bedea2");
    try expectDigest(4, 8, "\n", "d9fcb3171c097fbba8c8f12aa0906bad");
    try expectDigest(4, 8, "1\n", "44ec420ce99c1f62feb66c53c24ae453");
    try expectDigest(4, 8, "12\n", "7182051aa852ef6fba4b6c9c9b79b317");
    try expectDigest(4, 8, "123\n", "bc3a50af82bf56d6a64732bc7b050a93");
}

test "reduced rounds, other lengths and a second final() equal the original (values from crypto-api 0.8.5)" {
    const abc_rounds = [8][]const u8{
        "8f42e84a53e92a05b83a27a315faddd8", "9b0ed11e1b9843ac5bad06117c9d68a1", "ddc40591b204f57b16fee8a1f5cc8acd",
        "b6029a546373f33217be9515800c5e15", "72d702bd5a7dbaf8824b760aa7e1cba4", "ff50f3b43a82d042853ba39781871561",
        "13bae89986271463cfdf386080c3ea7a", "553d0648928299a0f22a275a02c83b10",
    };
    for (abc_rounds, 1..) |want, r| try expectDigest(4, @intCast(r), "abc", want);
    try expectDigest(8, 4, &@as([100]u8, @splat('x')), "e69389cc28ef4bf3809c89a7e1d023e0c73cd0bf52e121e329dfe1a6313c362b");
    try expectDigest(14, 8, "xxxxx", "b301a009b9b49375856f48dfc254a0e6bb9ba3abb29ac86ef4ef10449ece6c644dff3e131100f4af2b642597cf065e739fda1b7cbf1754b1");
    try expectDigest(1, 3, "xxxxx", "5cbc489f");

    // `final` drains the buffer and leaves `length`: the second final() hashes
    // an empty tail with length 3, and update() afterwards carries on from there.
    var st: State = undefined;
    init(&st, 4, 8);
    update(&st, "abc");
    var out: [16]u8 = undefined;
    final(&st, &out);
    try testing.expectEqual(@as(u8, 0), st.buffered);
    try testing.expectEqual(@as(u32, 3), st.length);
    var want: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "553d0648928299a0f22a275a02c83b10");
    try testing.expectEqualSlices(u8, &want, &out);
    final(&st, &out);
    _ = try std.fmt.hexToBytes(&want, "e806bf2adc84f8d7c6e4519175698448");
    try testing.expectEqualSlices(u8, &want, &out);
    try testing.expectEqualSlices(i32, &.{ -402211030, -595265321, -958115439, 1969849416 }, &@as([4]i32, @bitCast(st.hash[0..4].*)));
    update(&st, "de");
    final(&st, &out);
    _ = try std.fmt.hexToBytes(&want, "abb063f01513e0c9567b336e41835f86");
    try testing.expectEqualSlices(u8, &want, &out);
}

test "digests of 0..300 byte messages equal the original (folded FNV)" {
    // Captured by running packages/crypto-api/legacy/hasher/snefru.mjs: for each
    // (words, rounds), the digests of the messages [(i*7 + j) & 0xff for j in 0..i)]
    // for i = 0..300, concatenated and folded with FNV-1a.
    const cases = [_]struct { words: u8, rounds: u8, folded: u32 }{
        .{ .words = 4, .rounds = 2, .folded = 0x03547971 },
        .{ .words = 4, .rounds = 8, .folded = 0x51e96fd4 },
        .{ .words = 8, .rounds = 4, .folded = 0x5287f0af },
        .{ .words = 8, .rounds = 8, .folded = 0xb9300ee7 },
        .{ .words = 1, .rounds = 8, .folded = 0x39e12a86 },
        .{ .words = 14, .rounds = 8, .folded = 0xe1f7e81f },
        .{ .words = 14, .rounds = 1, .folded = 0x63c47612 },
        .{ .words = 7, .rounds = 5, .folded = 0xa7679f94 },
        .{ .words = 2, .rounds = 3, .folded = 0xc0696361 },
        .{ .words = 13, .rounds = 6, .folded = 0xe349c77e },
        .{ .words = 11, .rounds = 7, .folded = 0x5e2341af },
    };
    for (cases) |c| {
        var h: u32 = 0x811c9dc5;
        for (0..301) |i| {
            var msg: [300]u8 = undefined;
            for (0..i) |j| msg[j] = @truncate(i * 7 + j);
            var buf: [60]u8 = undefined;
            for (hexDigest(c.words, c.rounds, msg[0..i], &buf)) |byte| h = (h ^ byte) *% 0x01000193;
        }
        try testing.expectEqual(c.folded, h);
    }
}

test "random splits of update() give the same digest as one update()" {
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    var msg: [400]u8 = undefined;
    for (1..15) |words| {
        for ([_]u8{ 1, 2, 4, 8 }) |rounds| {
            if (words == 15) continue;
            for (0..40) |_| {
                const len = rnd.uintLessThan(usize, msg.len);
                rnd.bytes(msg[0..len]);
                var a: State = undefined;
                init(&a, @intCast(words), rounds);
                update(&a, msg[0..len]);
                var out_a: [60]u8 = undefined;
                final(&a, &out_a);

                var b: State = undefined;
                init(&b, @intCast(words), rounds);
                var pos: usize = 0;
                while (pos < len) {
                    const step = rnd.intRangeAtMost(usize, 1, 70);
                    const end = @min(pos + step, len);
                    update(&b, msg[pos..end]);
                    pos = end;
                }
                var out_b: [60]u8 = undefined;
                final(&b, &out_b);
                try testing.expectEqualSlices(u8, out_a[0 .. words * 4], out_b[0 .. words * 4]);
                try testing.expectEqual(a.hash, b.hash);
            }
        }
    }
}
