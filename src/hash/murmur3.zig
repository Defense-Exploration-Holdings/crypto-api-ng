//! MurmurHash3 (Austin Appleby, SMHasher), the x86_32 and x64_128 variants: fast
//! non-cryptographic hashes with a 32-bit seed. Not for security; for hash tables, Bloom filters
//! and sharding.
//!
//! These are new algorithms (crypto-api 0.8.5 has no MurmurHash). The state JS keeps between
//! calls is the byte counter and the running hash words. Buffering stays in the JS hasher and
//! wasm runs `blocks` (whole 4-byte or 16-byte blocks) and `final`, which does not modify the
//! state.
//!
//! Output: x86_32 writes the 32-bit hash most significant byte first, so its hex form is the
//! number other libraries print. x64_128 writes the 16 bytes of the reference implementation
//! (h1 then h2, each least significant byte first), the bytes `mmh3.hash_bytes` and Guava return.

const std = @import("std");

pub const X86_32 = struct {
    pub const block_len = 4;
    pub const digest_len = 4;

    const c1: u32 = 0xcc9e2d51;
    const c2: u32 = 0x1b873593;

    /// Layout is part of the wasm ABI (packages/crypto-api/src/wasm/blocks.mjs writes these
    /// offsets); a change bumps `runtime.abi_version`.
    pub const State = extern struct {
        /// Bytes processed so far (whole blocks).
        t: u64 align(8),
        h1: u32,
        _pad: u32 = 0,

        comptime {
            std.debug.assert(@sizeOf(State) == 16);
            std.debug.assert(@offsetOf(State, "h1") == 8);
        }
    };

    pub fn init(st: *State, seed: u32) void {
        st.* = .{ .t = 0, .h1 = seed };
    }

    inline fn mixK(k: u32) u32 {
        return std.math.rotl(u32, k *% c1, 15) *% c2;
    }

    /// Process whole blocks (`data.len % 4 == 0`), advancing `st.t`.
    pub fn blocks(st: *State, data: []const u8) void {
        std.debug.assert(data.len % block_len == 0);
        var h = st.h1;
        var i: usize = 0;
        while (i < data.len) : (i += 4) {
            h ^= mixK(std.mem.readInt(u32, data[i..][0..4], .little));
            h = std.math.rotl(u32, h, 13) *% 5 +% 0xe6546b64;
        }
        st.h1 = h;
        st.t += data.len;
    }

    /// Finish: `tail` (0..4 bytes) is the end of the message. Writes the hash, most significant
    /// byte first; `st` is not modified.
    pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
        std.debug.assert(tail.len <= block_len);
        var s = st.*;
        var rest = tail;
        if (rest.len == block_len) {
            blocks(&s, rest);
            rest = rest[4..];
        }
        var h = s.h1;
        var k: u32 = 0;
        for (rest, 0..) |b, i| k |= @as(u32, b) << @intCast(8 * i);
        if (rest.len > 0) h ^= mixK(k);
        h ^= @as(u32, @truncate(st.t + tail.len));
        h ^= h >> 16;
        h *%= 0x85ebca6b;
        h ^= h >> 13;
        h *%= 0xc2b2ae35;
        h ^= h >> 16;
        std.mem.writeInt(u32, out, h, .big);
    }
};

pub const X64_128 = struct {
    pub const block_len = 16;
    pub const digest_len = 16;

    const c1: u64 = 0x87c37b91114253d5;
    const c2: u64 = 0x4cf5ad432745937f;

    /// Layout is part of the wasm ABI; a change bumps `runtime.abi_version`.
    pub const State = extern struct {
        /// Bytes processed so far (whole blocks).
        t: u64 align(8),
        h1: u64 align(8),
        h2: u64 align(8),

        comptime {
            std.debug.assert(@sizeOf(State) == 24);
            std.debug.assert(@offsetOf(State, "h2") == 16);
        }
    };

    pub fn init(st: *State, seed: u32) void {
        st.* = .{ .t = 0, .h1 = seed, .h2 = seed };
    }

    inline fn mix1(k: u64) u64 {
        return std.math.rotl(u64, k *% c1, 31) *% c2;
    }

    inline fn mix2(k: u64) u64 {
        return std.math.rotl(u64, k *% c2, 33) *% c1;
    }

    fn fmix(k0: u64) u64 {
        var k = k0;
        k ^= k >> 33;
        k *%= 0xff51afd7ed558ccd;
        k ^= k >> 33;
        k *%= 0xc4ceb9fe1a85ec53;
        return k ^ (k >> 33);
    }

    /// Process whole blocks (`data.len % 16 == 0`), advancing `st.t`.
    pub fn blocks(st: *State, data: []const u8) void {
        std.debug.assert(data.len % block_len == 0);
        var h1 = st.h1;
        var h2 = st.h2;
        var i: usize = 0;
        while (i < data.len) : (i += 16) {
            h1 ^= mix1(std.mem.readInt(u64, data[i..][0..8], .little));
            h1 = std.math.rotl(u64, h1, 27) +% h2;
            h1 = h1 *% 5 +% 0x52dce729;
            h2 ^= mix2(std.mem.readInt(u64, data[i + 8 ..][0..8], .little));
            h2 = std.math.rotl(u64, h2, 31) +% h1;
            h2 = h2 *% 5 +% 0x38495ab5;
        }
        st.h1 = h1;
        st.h2 = h2;
        st.t += data.len;
    }

    /// Finish: `tail` (0..16 bytes) is the end of the message. Writes h1 then h2, each least
    /// significant byte first; `st` is not modified.
    pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
        std.debug.assert(tail.len <= block_len);
        var s = st.*;
        var rest = tail;
        if (rest.len == block_len) {
            blocks(&s, rest);
            rest = rest[16..];
        }
        var h1 = s.h1;
        var h2 = s.h2;
        var k1: u64 = 0;
        var k2: u64 = 0;
        for (rest, 0..) |b, i| {
            if (i < 8) k1 |= @as(u64, b) << @intCast(8 * i) else k2 |= @as(u64, b) << @intCast(8 * (i - 8));
        }
        if (rest.len > 8) h2 ^= mix2(k2);
        if (rest.len > 0) h1 ^= mix1(k1);
        const len = st.t + tail.len;
        h1 ^= len;
        h2 ^= len;
        h1 +%= h2;
        h2 +%= h1;
        h1 = fmix(h1);
        h2 = fmix(h2);
        h1 +%= h2;
        h2 +%= h1;
        std.mem.writeInt(u64, out[0..8], h1, .little);
        std.mem.writeInt(u64, out[8..16], h2, .little);
    }
};

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

/// Whole-message hash over `blocks`/`final`, holding back the last 1..block bytes like the JS hasher.
pub fn oneShot(comptime T: type, message: []const u8, seed: u32, out: *[T.digest_len]u8) void {
    var st: T.State = undefined;
    T.init(&st, seed);
    const keep = if (message.len == 0) 0 else (message.len - 1) / T.block_len * T.block_len;
    T.blocks(&st, message[0..keep]);
    T.final(&st, message[keep..], out);
}

/// The verification value of SMHasher: hash the keys {}, {0}, {0, 1}, .. {0, .., 254} with the
/// seeds 256, 255, .., 1, then hash the concatenated results with seed 0; the first four bytes
/// of that, as the reference writes them, read as a little-endian number.
fn verification(comptime T: type) u32 {
    var key: [256]u8 = undefined;
    var all: [256 * T.digest_len]u8 = undefined;
    for (0..256) |i| {
        key[i] = @truncate(i);
        var out: [T.digest_len]u8 = undefined;
        oneShot(T, key[0..i], @intCast(256 - i), &out);
        // x86_32 is written most significant byte first here; the reference writes it the other way.
        if (T == X86_32) std.mem.reverse(u8, &out);
        all[i * T.digest_len ..][0..T.digest_len].* = out;
    }
    var final: [T.digest_len]u8 = undefined;
    oneShot(T, &all, 0, &final);
    if (T == X86_32) std.mem.reverse(u8, &final);
    return std.mem.readInt(u32, final[0..4], .little);
}

test "the SMHasher verification values" {
    try testing.expectEqual(@as(u32, 0xB0F57EE3), verification(X86_32));
    try testing.expectEqual(@as(u32, 0x6384BA69), verification(X64_128));
}

test "x86_32 agrees with std.hash.Murmur3_32 at every length and seed" {
    var msg: [200]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    for ([_]u32{ 0, 1, 0x9747b28c, 0xffffffff }) |seed| {
        for (0..msg.len + 1) |len| {
            var out: [4]u8 = undefined;
            oneShot(X86_32, msg[0..len], seed, &out);
            try testing.expectEqual(std.hash.Murmur3_32.hashWithSeed(msg[0..len], seed), std.mem.readInt(u32, &out, .big));
        }
    }
}

test "published values" {
    var o4: [4]u8 = undefined;
    oneShot(X86_32, "", 0, &o4);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, &o4, .big));
    oneShot(X86_32, "", 1, &o4);
    try testing.expectEqual(@as(u32, 0x514E28B7), std.mem.readInt(u32, &o4, .big));
    oneShot(X86_32, "Hello, world!", 0x9747b28c, &o4);
    try testing.expectEqual(@as(u32, 0x24884CBA), std.mem.readInt(u32, &o4, .big));
    var o16: [16]u8 = undefined;
    oneShot(X64_128, "", 0, &o16);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &o16);
}

test "final does not change the state" {
    var st: X64_128.State = undefined;
    X64_128.init(&st, 5);
    X64_128.blocks(&st, "0123456789abcdef");
    const before = st;
    var out: [16]u8 = undefined;
    X64_128.final(&st, "0123456789abcdef", &out);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
