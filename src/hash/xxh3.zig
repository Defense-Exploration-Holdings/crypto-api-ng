//! XXH3, the 64-bit and 128-bit variants (Yann Collet, xxHash 0.8): fast non-cryptographic
//! hashes with a seed. Not for security; for hash tables, deduplication and checksums.
//!
//! These are new algorithms (crypto-api 0.8.5 has no xxHash). The state JS keeps between calls
//! is the byte counter, the eight accumulators and the seed. Buffering stays in the JS hasher
//! and wasm runs `blocks` (whole 1024-byte blocks, each followed by the scramble step) and
//! `final`. Because the last stripe of a long message is its last 64 bytes, the hasher keeps
//! back at least `keep_len` bytes once a block has been compressed, so `final` gets
//! `keep_len` to `block_len + keep_len - 1` bytes (`tail_max`). `final` does not modify the
//! state. The digest is the canonical representation of the specification: the hash as a
//! big-endian number (XXH128: the high 64 bits first).
//!
//! The derived secret of a seeded long hash is recomputed from the seed on every call, so the
//! state holds no secret.

const std = @import("std");

const p32_1: u64 = 0x9E3779B1;
const p32_2: u64 = 0x85EBCA77;
const p32_3: u64 = 0xC2B2AE3D;
const p64_1: u64 = 0x9E3779B185EBCA87;
const p64_2: u64 = 0xC2B2AE3D27D4EB4F;
const p64_3: u64 = 0x165667B19E3779F9;
const p64_4: u64 = 0x85EBCA77C2B2AE63;
const p64_5: u64 = 0x27D4EB2F165667C5;
const prime_mx1: u64 = 0x165667919E3779F9;
const prime_mx2: u64 = 0x9FB21C651E98DF25;

/// The default secret of the specification (192 bytes).
pub const default_secret: [192]u8 = .{
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

const secret_len = default_secret.len;
const stripe_len = 64;
const stripes_per_block = (secret_len - stripe_len) / 8;
/// Bytes of one block: 16 stripes, then a scramble.
pub const block_len = stripe_len * stripes_per_block;
/// Bytes the hasher keeps back once a block has been compressed: the last stripe.
pub const keep_len = stripe_len;
/// The longest tail `final` accepts.
pub const tail_max = block_len + keep_len - 1;
/// Messages up to this length are hashed without the accumulators.
const short_max = 240;

const init_acc = [8]u64{ p32_3, p64_1, p64_2, p64_3, p64_4, p32_2, p64_5, p32_1 };

/// Layout is part of the wasm ABI (packages/crypto-api/src/wasm/blocks.mjs writes these
/// offsets); a change bumps `runtime.abi_version`.
pub const State = extern struct {
    /// Bytes compressed so far (whole blocks).
    t: u64 align(8),
    /// The eight accumulators.
    acc: [8]u64 align(8),
    /// The seed.
    seed: u64 align(8),

    comptime {
        std.debug.assert(@sizeOf(State) == 80);
        std.debug.assert(@offsetOf(State, "seed") == 72);
    }
};

pub fn init(st: *State, seed: u64) void {
    st.t = 0;
    st.acc = init_acc;
    st.seed = seed;
}

inline fn r64(p: []const u8, at: usize) u64 {
    return std.mem.readInt(u64, p[at..][0..8], .little);
}

inline fn r32(p: []const u8, at: usize) u64 {
    return std.mem.readInt(u32, p[at..][0..4], .little);
}

inline fn mul128(a: u64, b: u64) u128 {
    return @as(u128, a) * @as(u128, b);
}

inline fn fold64(a: u64, b: u64) u64 {
    const m = mul128(a, b);
    return @as(u64, @truncate(m)) ^ @as(u64, @truncate(m >> 64));
}

fn avalanche64(h0: u64) u64 {
    var h = h0;
    h ^= h >> 33;
    h *%= p64_2;
    h ^= h >> 29;
    h *%= p64_3;
    return h ^ (h >> 32);
}

fn avalanche3(h0: u64) u64 {
    const h = (h0 ^ (h0 >> 37)) *% prime_mx1;
    return h ^ (h >> 32);
}

fn rrmxmx(h0: u64, len: u64) u64 {
    var h = h0 ^ std.math.rotl(u64, h0, 49) ^ std.math.rotl(u64, h0, 24);
    h *%= prime_mx2;
    h ^= (h >> 35) +% len;
    h *%= prime_mx2;
    return h ^ (h >> 28);
}

fn mix16(in: []const u8, at: usize, sec: []const u8, s: usize, seed: u64) u64 {
    return fold64(r64(in, at) ^ (r64(sec, s) +% seed), r64(in, at + 8) ^ (r64(sec, s + 8) -% seed));
}

// ---- the long-message loop --------------------------------------------------

fn accumulate512(acc: *[8]u64, in: []const u8, at: usize, sec: []const u8, s: usize) void {
    inline for (0..8) |i| {
        const v = r64(in, at + 8 * i);
        const k = v ^ r64(sec, s + 8 * i);
        acc[i ^ 1] +%= v;
        acc[i] +%= (k & 0xffffffff) *% (k >> 32);
    }
}

fn scramble(acc: *[8]u64, sec: []const u8) void {
    inline for (0..8) |i| {
        var a = acc[i];
        a ^= a >> 47;
        a ^= r64(sec, secret_len - stripe_len + 8 * i);
        acc[i] = a *% p32_1;
    }
}

fn block(acc: *[8]u64, in: []const u8, at: usize, sec: []const u8) void {
    for (0..stripes_per_block) |n| accumulate512(acc, in, at + n * stripe_len, sec, n * 8);
    scramble(acc, sec);
}

/// The secret of `seed`: the default secret with the seed added to its even and subtracted
/// from its odd 64-bit words. Seed 0 gives the default secret.
pub fn deriveSecret(seed: u64, out: *[secret_len]u8) void {
    var i: usize = 0;
    while (i < secret_len) : (i += 16) {
        std.mem.writeInt(u64, out[i..][0..8], r64(&default_secret, i) +% seed, .little);
        std.mem.writeInt(u64, out[i + 8 ..][0..8], r64(&default_secret, i + 8) -% seed, .little);
    }
}

/// Process whole blocks (`data.len % 1024 == 0`), advancing `st.t`. None may hold the last
/// byte of the message.
pub fn blocks(st: *State, data: []const u8) void {
    std.debug.assert(data.len % block_len == 0);
    var sec: [secret_len]u8 = undefined;
    deriveSecret(st.seed, &sec);
    var i: usize = 0;
    while (i < data.len) : (i += block_len) block(&st.acc, data, i, &sec);
    st.t += data.len;
    std.crypto.secureZero(u8, &sec);
}

/// The accumulators after the whole message, for a message longer than 240 bytes: `st` plus
/// `tail`, which holds at least the last stripe.
fn finishAcc(st: *const State, tail: []const u8, sec: []const u8) [8]u64 {
    var acc = st.acc;
    const len = tail.len;
    // Blocks of the tail that are not the last one, then the stripes of the last block but
    // its last stripe, then the last 64 bytes of the message.
    const whole = (len - 1) / block_len;
    for (0..whole) |n| block(&acc, tail, n * block_len, sec);
    const start = whole * block_len;
    const stripes = (len - 1 - start) / stripe_len;
    for (0..stripes) |n| accumulate512(&acc, tail, start + n * stripe_len, sec, n * 8);
    accumulate512(&acc, tail, len - stripe_len, sec, secret_len - stripe_len - 7);
    return acc;
}

fn mergeAccs(acc: *const [8]u64, sec: []const u8, s: usize, start: u64) u64 {
    var r = start;
    inline for (0..4) |i| r +%= fold64(acc[2 * i] ^ r64(sec, s + 16 * i), acc[2 * i + 1] ^ r64(sec, s + 16 * i + 8));
    return avalanche3(r);
}

fn checkTail(st: *const State, tail: []const u8) void {
    std.debug.assert(tail.len <= tail_max);
    std.debug.assert(st.t == 0 or tail.len >= keep_len);
}

// ---- XXH3-64 ----------------------------------------------------------------

fn short64(in: []const u8, seed: u64) u64 {
    const sec: []const u8 = &default_secret;
    const len: u64 = in.len;
    if (in.len == 0) return avalanche64(seed ^ (r64(sec, 56) ^ r64(sec, 64)));
    if (in.len <= 3) {
        const c: u64 = (@as(u64, in[0]) << 16) | (@as(u64, in[in.len >> 1]) << 24) | in[in.len - 1] | (len << 8);
        return avalanche64(c ^ ((r32(sec, 0) ^ r32(sec, 4)) +% seed));
    }
    if (in.len <= 8) {
        const s = seed ^ (@as(u64, @byteSwap(@as(u32, @truncate(seed)))) << 32);
        const v = r32(in, in.len - 4) +% (r32(in, 0) << 32);
        return rrmxmx(v ^ ((r64(sec, 8) ^ r64(sec, 16)) -% s), len);
    }
    if (in.len <= 16) {
        const lo = r64(in, 0) ^ ((r64(sec, 24) ^ r64(sec, 32)) +% seed);
        const hi = r64(in, in.len - 8) ^ ((r64(sec, 40) ^ r64(sec, 48)) -% seed);
        return avalanche3(len +% @byteSwap(lo) +% hi +% fold64(lo, hi));
    }
    var acc = len *% p64_1;
    if (in.len <= 128) {
        if (in.len > 32) {
            if (in.len > 64) {
                if (in.len > 96) {
                    acc +%= mix16(in, 48, sec, 96, seed);
                    acc +%= mix16(in, in.len - 64, sec, 112, seed);
                }
                acc +%= mix16(in, 32, sec, 64, seed);
                acc +%= mix16(in, in.len - 48, sec, 80, seed);
            }
            acc +%= mix16(in, 16, sec, 32, seed);
            acc +%= mix16(in, in.len - 32, sec, 48, seed);
        }
        acc +%= mix16(in, 0, sec, 0, seed);
        acc +%= mix16(in, in.len - 16, sec, 16, seed);
        return avalanche3(acc);
    }
    for (0..8) |i| acc +%= mix16(in, 16 * i, sec, 16 * i, seed);
    acc = avalanche3(acc);
    for (8..in.len / 16) |i| acc +%= mix16(in, 16 * i, sec, 16 * (i - 8) + 3, seed);
    acc +%= mix16(in, in.len - 16, sec, 136 - 17, seed);
    return avalanche3(acc);
}

pub const Xxh3_64 = struct {
    pub const State = xxh3State;
    pub const block_len = xxh3Block;
    pub const keep_len = xxh3Keep;
    pub const tail_max = xxh3TailMax;
    pub const digest_len = 8;

    pub const init = xxh3Init;
    pub const blocks = xxh3Blocks;

    /// Finish: `tail` is the end of the message (see `tail_max`). Writes the hash, most
    /// significant byte first; `st` is not modified.
    pub fn final(st: *const xxh3State, tail: []const u8, out: *[digest_len]u8) void {
        checkTail(st, tail);
        const total = st.t + tail.len;
        var h: u64 = undefined;
        if (total <= short_max) {
            h = short64(tail, st.seed);
        } else {
            var sec: [secret_len]u8 = undefined;
            deriveSecret(st.seed, &sec);
            var acc = finishAcc(st, tail, &sec);
            h = mergeAccs(&acc, &sec, 11, total *% p64_1);
            std.crypto.secureZero(u8, &sec);
            std.crypto.secureZero(u64, &acc);
        }
        std.mem.writeInt(u64, out, h, .big);
    }
};

// ---- XXH3-128 ---------------------------------------------------------------

const U128 = struct { lo: u64, hi: u64 };

fn mix32(acc: *U128, in: []const u8, a: usize, b: usize, sec: []const u8, s: usize, seed: u64) void {
    acc.lo +%= mix16(in, a, sec, s, seed);
    acc.lo ^= r64(in, b) +% r64(in, b + 8);
    acc.hi +%= mix16(in, b, sec, s + 16, seed);
    acc.hi ^= r64(in, a) +% r64(in, a + 8);
}

fn short128(in: []const u8, seed: u64) U128 {
    const sec: []const u8 = &default_secret;
    const len: u64 = in.len;
    if (in.len == 0) return .{
        .lo = avalanche64(seed ^ r64(sec, 64) ^ r64(sec, 72)),
        .hi = avalanche64(seed ^ r64(sec, 80) ^ r64(sec, 88)),
    };
    if (in.len <= 3) {
        const cl: u32 = (@as(u32, in[0]) << 16) | (@as(u32, in[in.len >> 1]) << 24) | in[in.len - 1] | (@as(u32, @truncate(len)) << 8);
        const ch: u32 = std.math.rotl(u32, @byteSwap(cl), 13);
        return .{
            .lo = avalanche64(@as(u64, cl) ^ ((r32(sec, 0) ^ r32(sec, 4)) +% seed)),
            .hi = avalanche64(@as(u64, ch) ^ ((r32(sec, 8) ^ r32(sec, 12)) -% seed)),
        };
    }
    if (in.len <= 8) {
        const s = seed ^ (@as(u64, @byteSwap(@as(u32, @truncate(seed)))) << 32);
        const v = r32(in, 0) +% (r32(in, in.len - 4) << 32);
        const keyed = v ^ ((r64(sec, 16) ^ r64(sec, 24)) +% s);
        const m = mul128(keyed, p64_1 +% (len << 2));
        var lo: u64 = @truncate(m);
        var hi: u64 = @truncate(m >> 64);
        hi +%= lo << 1;
        lo ^= hi >> 3;
        lo ^= lo >> 35;
        lo *%= prime_mx2;
        lo ^= lo >> 28;
        return .{ .lo = lo, .hi = avalanche3(hi) };
    }
    if (in.len <= 16) {
        const flip_lo = (r64(sec, 32) ^ r64(sec, 40)) -% seed;
        const flip_hi = (r64(sec, 48) ^ r64(sec, 56)) +% seed;
        const in_lo = r64(in, 0);
        var in_hi = r64(in, in.len - 8);
        const m = mul128(in_lo ^ in_hi ^ flip_lo, p64_1);
        var lo: u64 = @truncate(m);
        var hi: u64 = @truncate(m >> 64);
        lo +%= (len - 1) << 54;
        in_hi ^= flip_hi;
        hi +%= in_hi +% (in_hi & 0xffffffff) *% (p32_2 - 1);
        lo ^= @byteSwap(hi);
        const h = mul128(lo, p64_2);
        const hlo: u64 = @truncate(h);
        const hhi: u64 = @as(u64, @truncate(h >> 64)) +% hi *% p64_2;
        return .{ .lo = avalanche3(hlo), .hi = avalanche3(hhi) };
    }
    var acc: U128 = .{ .lo = len *% p64_1, .hi = 0 };
    if (in.len <= 128) {
        if (in.len > 32) {
            if (in.len > 64) {
                if (in.len > 96) mix32(&acc, in, 48, in.len - 64, sec, 96, seed);
                mix32(&acc, in, 32, in.len - 48, sec, 64, seed);
            }
            mix32(&acc, in, 16, in.len - 32, sec, 32, seed);
        }
        mix32(&acc, in, 0, in.len - 16, sec, 0, seed);
    } else {
        for (0..4) |i| mix32(&acc, in, 32 * i, 32 * i + 16, sec, 32 * i, seed);
        acc.lo = avalanche3(acc.lo);
        acc.hi = avalanche3(acc.hi);
        for (4..in.len / 32) |i| mix32(&acc, in, 32 * i, 32 * i + 16, sec, 3 + 32 * (i - 4), seed);
        mix32(&acc, in, in.len - 16, in.len - 32, sec, 136 - 17 - 16, 0 -% seed);
    }
    const lo = acc.lo +% acc.hi;
    const hi = acc.lo *% p64_1 +% acc.hi *% p64_4 +% (len -% seed) *% p64_2;
    return .{ .lo = avalanche3(lo), .hi = 0 -% avalanche3(hi) };
}

pub const Xxh3_128 = struct {
    pub const State = xxh3State;
    pub const block_len = xxh3Block;
    pub const keep_len = xxh3Keep;
    pub const tail_max = xxh3TailMax;
    pub const digest_len = 16;

    pub const init = xxh3Init;
    pub const blocks = xxh3Blocks;

    /// Finish: `tail` is the end of the message (see `tail_max`). Writes the high 64 bits then
    /// the low 64 bits, each most significant byte first; `st` is not modified.
    pub fn final(st: *const xxh3State, tail: []const u8, out: *[digest_len]u8) void {
        checkTail(st, tail);
        const total = st.t + tail.len;
        var h: U128 = undefined;
        if (total <= short_max) {
            h = short128(tail, st.seed);
        } else {
            var sec: [secret_len]u8 = undefined;
            deriveSecret(st.seed, &sec);
            var acc = finishAcc(st, tail, &sec);
            h = .{
                .lo = mergeAccs(&acc, &sec, 11, total *% p64_1),
                .hi = mergeAccs(&acc, &sec, secret_len - stripe_len - 11, ~(total *% p64_2)),
            };
            std.crypto.secureZero(u8, &sec);
            std.crypto.secureZero(u64, &acc);
        }
        std.mem.writeInt(u64, out[0..8], h.hi, .big);
        std.mem.writeInt(u64, out[8..16], h.lo, .big);
    }
};

const xxh3State = State;
const xxh3Block = block_len;
const xxh3Keep = keep_len;
const xxh3TailMax = tail_max;
const xxh3Init = init;
const xxh3Blocks = blocks;

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

/// Whole-message hash over `blocks`/`final`, holding back what the JS hasher holds back.
pub fn oneShot(comptime T: type, message: []const u8, seed: u64, out: *[T.digest_len]u8) void {
    var st: State = undefined;
    T.init(&st, seed);
    const keep = if (message.len < block_len + keep_len) 0 else (message.len - keep_len) / block_len * block_len;
    T.blocks(&st, message[0..keep]);
    T.final(&st, message[keep..], out);
}

fn h64(message: []const u8, seed: u64) u64 {
    var out: [8]u8 = undefined;
    oneShot(Xxh3_64, message, seed, &out);
    return std.mem.readInt(u64, &out, .big);
}

fn h128(message: []const u8, seed: u64) u128 {
    var out: [16]u8 = undefined;
    oneShot(Xxh3_128, message, seed, &out);
    return std.mem.readInt(u128, &out, .big);
}

/// The sanity buffer of the xxHash test suite (tests/sanity_test.c).
fn sanityBuffer(comptime n: usize) [n]u8 {
    var out: [n]u8 = undefined;
    var gen: u64 = 2654435761;
    for (&out) |*b| {
        b.* = @truncate(gen >> 56);
        gen *%= 11400714785074694797;
    }
    return out;
}

test "published values: empty message and 'abc'" {
    try testing.expectEqual(@as(u64, 0x2d06800538d394c2), h64("", 0));
    try testing.expectEqual(@as(u64, 0x78af5f94892f3950), h64("abc", 0));
    try testing.expectEqual(@as(u128, 0x99aa06d3014798d86001c324468d497f), h128("", 0));
    try testing.expectEqual(@as(u128, 0x06b05ab6733a618578af5f94892f3950), h128("abc", 0));
}

test "values of the xxHash sanity suite, every code path" {
    const buf = sanityBuffer(4096 + 64 + 1);
    // From tests/sanity_test_vectors.h of xxHash 0.8.3.
    const v64 = [_]struct { usize, u64, u64 }{
        .{ 0, 0, 0x2D06800538D394C2 }, .{ 0, 0x9E3779B185EBCA8D, 0xA8A6B918B2F0364A },
        .{ 1, 0, 0xC44BDFF4074EECDB }, .{ 1, 0x9E3779B185EBCA8D, 0x032BE332DD766EF8 },
        .{ 4, 0, 0xE5DC74BC51848A51 }, .{ 4, 0x9E3779B185EBCA8D, 0xAA2E7ECCB0C8F747 },
    };
    for (v64) |v| try testing.expectEqual(v[2], h64(buf[0..v[0]], v[1]));
    const v128 = [_]struct { usize, u64, u64, u64 }{
        .{ 0, 0, 0x6001C324468D497F, 0x99AA06D3014798D8 },
        .{ 0, 0x9E3779B1, 0x5444F7869C671AB0, 0x92220AE55E14AB50 },
        .{ 1, 0x9E3779B185EBCA8D, 0x032BE332DD766EF8, 0x20E49ABCC53B3842 },
        .{ 2, 0x9E3779B1, 0x8295910C7638B180, 0x8B75A791EC034873 },
    };
    for (v128) |v| try testing.expectEqual((@as(u128, v[3]) << 64) | v[2], h128(buf[0..v[0]], v[1]));
}

test "agrees with std.hash.XxHash3 at every length up to 3000, seeded and not" {
    var msg: [3000]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7 +% (i >> 5));
    for ([_]u64{ 0, 1, 0x9E3779B1, 0x9E3779B185EBCA8D, 0xffffffffffffffff }) |seed| {
        for (0..msg.len + 1) |len| {
            try testing.expectEqual(std.hash.XxHash3.hash(seed, msg[0..len]), h64(msg[0..len], seed));
        }
    }
}

test "the low half of XXH128 of 1 to 3 bytes is XXH3-64 (as in the reference)" {
    for ([_][]const u8{ "a", "ab", "abc" }) |m| {
        try testing.expectEqual(h64(m, 7), @as(u64, @truncate(h128(m, 7))));
    }
}

test "every split into blocks gives the one-shot value" {
    var msg: [5000]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    for ([_]usize{ 1024 + 64, 1024 + 65, 2047, 2048, 2048 + 63, 2048 + 64, 3100, 5000 }) |len| {
        // Compress as few blocks as possible before `final`: the tail is then up to 1087 bytes.
        var st: State = undefined;
        init(&st, 99);
        Xxh3_128.blocks(&st, msg[0..block_len]);
        const rest = msg[block_len..len];
        const more = if (rest.len < block_len + keep_len) 0 else (rest.len - keep_len) / block_len * block_len;
        Xxh3_128.blocks(&st, rest[0..more]);
        var a: [16]u8 = undefined;
        Xxh3_128.final(&st, rest[more..], &a);
        try testing.expectEqual(h128(msg[0..len], 99), std.mem.readInt(u128, &a, .big));
    }
}

test "final does not change the state" {
    var st: State = undefined;
    init(&st, 7);
    var msg: [1500]u8 = @splat(3);
    Xxh3_64.blocks(&st, msg[0..1024]);
    const before = st;
    var out: [16]u8 = undefined;
    Xxh3_128.final(&st, msg[1024..], &out);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
