//! xxHash, the XXH32 and XXH64 variants (Yann Collet): fast non-cryptographic hashes with a
//! seed. Not for security; for hash tables, deduplication and checksums.
//!
//! These are new algorithms (crypto-api 0.8.5 has no xxHash). The state JS keeps between
//! calls is the byte counter and the four accumulators plus the seed; buffering stays in
//! the JS hasher and wasm runs `blocks` (whole stripes: 16 bytes for XXH32, 32 for XXH64)
//! and `final`, like for the other hashers that have no original. `final` does not modify
//! the state. The digest is the canonical representation of the specification: the hash as
//! a big-endian number, so its hex form is the number everyone prints.

const std = @import("std");

pub const Xxh32 = struct {
    pub const block_len = 16;
    pub const digest_len = 4;

    const p1: u32 = 2654435761;
    const p2: u32 = 2246822519;
    const p3: u32 = 3266489917;
    const p4: u32 = 668265263;
    const p5: u32 = 374761393;

    /// Layout is part of the wasm ABI (packages/crypto-api/src/wasm/blocks.mjs writes these
    /// offsets); a change bumps `runtime.abi_version`.
    pub const State = extern struct {
        /// Bytes processed so far (whole stripes).
        t: u64 align(8),
        /// The four accumulators.
        v: [4]u32,
        /// The seed, kept for messages shorter than one stripe.
        seed: u32,

        comptime {
            std.debug.assert(@sizeOf(State) == 32);
            std.debug.assert(@offsetOf(State, "seed") == 24);
        }
    };

    pub fn init(st: *State, seed: u32) void {
        st.t = 0;
        st.seed = seed;
        st.v = .{ seed +% p1 +% p2, seed +% p2, seed, seed -% p1 };
    }

    fn round(acc: u32, lane: u32) u32 {
        return std.math.rotl(u32, acc +% lane *% p2, 13) *% p1;
    }

    fn stripe(v: *[4]u32, data: *const [16]u8) void {
        inline for (0..4) |i| v[i] = round(v[i], std.mem.readInt(u32, data[4 * i ..][0..4], .little));
    }

    /// Process whole stripes (`data.len % 16 == 0`), advancing `st.t`.
    pub fn blocks(st: *State, data: []const u8) void {
        std.debug.assert(data.len % block_len == 0);
        var i: usize = 0;
        while (i < data.len) : (i += block_len) stripe(&st.v, data[i..][0..block_len]);
        st.t += data.len;
    }

    /// Finish: `tail` (0..16 bytes) is the end of the message. Writes the hash, most significant
    /// byte first; `st` is not modified.
    pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
        std.debug.assert(tail.len <= block_len);
        var v = st.v;
        var rest = tail;
        if (rest.len == block_len) {
            stripe(&v, rest[0..block_len]);
            rest = rest[block_len..];
        }
        const total = st.t + tail.len;
        var h: u32 = if (total >= block_len)
            std.math.rotl(u32, v[0], 1) +% std.math.rotl(u32, v[1], 7) +% std.math.rotl(u32, v[2], 12) +% std.math.rotl(u32, v[3], 18)
        else
            st.seed +% p5;
        h +%= @as(u32, @truncate(total));
        while (rest.len >= 4) : (rest = rest[4..]) {
            h = std.math.rotl(u32, h +% std.mem.readInt(u32, rest[0..4], .little) *% p3, 17) *% p4;
        }
        for (rest) |b| h = std.math.rotl(u32, h +% @as(u32, b) *% p5, 11) *% p1;
        h ^= h >> 15;
        h *%= p2;
        h ^= h >> 13;
        h *%= p3;
        h ^= h >> 16;
        std.mem.writeInt(u32, out, h, .big);
    }
};

pub const Xxh64 = struct {
    pub const block_len = 32;
    pub const digest_len = 8;

    const p1: u64 = 11400714785074694791;
    const p2: u64 = 14029467366897019727;
    const p3: u64 = 1609587929392839161;
    const p4: u64 = 9650029242287828579;
    const p5: u64 = 2870177450012600261;

    /// Layout is part of the wasm ABI; a change bumps `runtime.abi_version`.
    pub const State = extern struct {
        /// Bytes processed so far (whole stripes).
        t: u64 align(8),
        /// The four accumulators.
        v: [4]u64 align(8),
        /// The seed, kept for messages shorter than one stripe.
        seed: u64 align(8),

        comptime {
            std.debug.assert(@sizeOf(State) == 48);
            std.debug.assert(@offsetOf(State, "seed") == 40);
        }
    };

    pub fn init(st: *State, seed: u64) void {
        st.t = 0;
        st.seed = seed;
        st.v = .{ seed +% p1 +% p2, seed +% p2, seed, seed -% p1 };
    }

    fn round(acc: u64, lane: u64) u64 {
        return std.math.rotl(u64, acc +% lane *% p2, 31) *% p1;
    }

    fn merge(h: u64, v: u64) u64 {
        return (h ^ round(0, v)) *% p1 +% p4;
    }

    fn stripe(v: *[4]u64, data: *const [32]u8) void {
        inline for (0..4) |i| v[i] = round(v[i], std.mem.readInt(u64, data[8 * i ..][0..8], .little));
    }

    /// Process whole stripes (`data.len % 32 == 0`), advancing `st.t`.
    pub fn blocks(st: *State, data: []const u8) void {
        std.debug.assert(data.len % block_len == 0);
        var i: usize = 0;
        while (i < data.len) : (i += block_len) stripe(&st.v, data[i..][0..block_len]);
        st.t += data.len;
    }

    /// Finish: `tail` (0..32 bytes) is the end of the message. Writes the hash, most significant
    /// byte first; `st` is not modified.
    pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
        std.debug.assert(tail.len <= block_len);
        var v = st.v;
        var rest = tail;
        if (rest.len == block_len) {
            stripe(&v, rest[0..block_len]);
            rest = rest[block_len..];
        }
        const total = st.t + tail.len;
        var h: u64 = undefined;
        if (total >= block_len) {
            h = std.math.rotl(u64, v[0], 1) +% std.math.rotl(u64, v[1], 7) +% std.math.rotl(u64, v[2], 12) +% std.math.rotl(u64, v[3], 18);
            inline for (0..4) |i| h = merge(h, v[i]);
        } else {
            h = st.seed +% p5;
        }
        h +%= total;
        while (rest.len >= 8) : (rest = rest[8..]) {
            h ^= round(0, std.mem.readInt(u64, rest[0..8], .little));
            h = std.math.rotl(u64, h, 27) *% p1 +% p4;
        }
        if (rest.len >= 4) {
            h ^= @as(u64, std.mem.readInt(u32, rest[0..4], .little)) *% p1;
            h = std.math.rotl(u64, h, 23) *% p2 +% p3;
            rest = rest[4..];
        }
        for (rest) |b| {
            h ^= @as(u64, b) *% p5;
            h = std.math.rotl(u64, h, 11) *% p1;
        }
        h ^= h >> 33;
        h *%= p2;
        h ^= h >> 29;
        h *%= p3;
        h ^= h >> 32;
        std.mem.writeInt(u64, out, h, .big);
    }
};

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

/// Whole-message hash over `blocks`/`final`, holding back the last 1..block bytes like the JS hasher.
fn run(comptime T: type, message: []const u8, seed: u64) @TypeOf(if (T == Xxh32) @as(u32, 0) else @as(u64, 0)) {
    var st: T.State = undefined;
    T.init(&st, @truncate(seed));
    const whole = message.len - message.len % T.block_len;
    const keep = if (whole == message.len and message.len > 0) message.len - T.block_len else whole;
    T.blocks(&st, message[0..keep]);
    var out: [T.digest_len]u8 = undefined;
    T.final(&st, message[keep..], &out);
    return std.mem.readInt(@TypeOf(if (T == Xxh32) @as(u32, 0) else @as(u64, 0)), &out, .big);
}

test "published values: empty message and 'abc', with and without a seed" {
    try testing.expectEqual(@as(u32, 0x02cc5d05), run(Xxh32, "", 0));
    try testing.expectEqual(@as(u32, 0x32d153ff), run(Xxh32, "abc", 0));
    try testing.expectEqual(@as(u32, 0x36b78ae7), run(Xxh32, "", 0x9E3779B1));
    try testing.expectEqual(@as(u64, 0xef46db3751d8e999), run(Xxh64, "", 0));
    try testing.expectEqual(@as(u64, 0x44bc2cf5ad770999), run(Xxh64, "abc", 0));
    try testing.expectEqual(@as(u64, 0xac75fda2929b17ef), run(Xxh64, "", 0x9E3779B1));
}

test "published values: a message long enough for the stripe loop" {
    const msg = "Nobody inspects the spammish repetition";
    try testing.expectEqual(@as(u32, 0xe2293b2f), run(Xxh32, msg, 0));
    try testing.expectEqual(@as(u64, 0xfbcea83c8a378bf1), run(Xxh64, msg, 0));
}

test "every split of one message gives the one-shot value" {
    var msg: [200]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    for (0..msg.len + 1) |len| {
        // Feed `blocks` in two parts: the whole stripes of the first `len / 2` bytes, then the rest.
        for ([_]u64{ 0, 0x12345678, 0xdeadbeefcafef00d }) |seed| {
            var st: Xxh64.State = undefined;
            Xxh64.init(&st, seed);
            const cut = (len / 2) / 32 * 32;
            Xxh64.blocks(&st, msg[0..cut]);
            const rest = msg[cut..len];
            const keep = if (rest.len > 0) (rest.len - 1) / 32 * 32 else 0;
            Xxh64.blocks(&st, rest[0..keep]);
            var out: [8]u8 = undefined;
            Xxh64.final(&st, rest[keep..], &out);
            try testing.expectEqual(run(Xxh64, msg[0..len], seed), std.mem.readInt(u64, &out, .big));
        }
    }
}

test "agrees with std.hash.XxHash32 and XxHash64 at every length and seed" {
    var msg: [300]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for ([_]u64{ 0, 1, 0x9E3779B1, 0xFFFFFFFF, 0x9E3779B185EBCA8D }) |seed| {
        for (0..msg.len + 1) |len| {
            try testing.expectEqual(std.hash.XxHash64.hash(seed, msg[0..len]), run(Xxh64, msg[0..len], seed));
            try testing.expectEqual(std.hash.XxHash32.hash(@truncate(seed), msg[0..len]), run(Xxh32, msg[0..len], seed));
        }
    }
}

test "final does not change the state" {
    var st: Xxh32.State = undefined;
    Xxh32.init(&st, 7);
    const before = st;
    var out: [4]u8 = undefined;
    Xxh32.final(&st, "abc", &out);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
