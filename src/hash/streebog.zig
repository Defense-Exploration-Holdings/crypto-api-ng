//! Streebog, the GOST R 34.11-2012 hash function (RFC 6986): 512-bit blocks, 256- and
//! 512-bit digests.
//!
//! These are new algorithms (crypto-api 0.8.5 has no Streebog), so there is no original to
//! stay compatible with. As for BLAKE2, the state JS keeps between calls is just the
//! algorithm's words and the byte counter; buffering stays in the JS hasher and wasm
//! compresses (`blocks`) and finishes (`final`). `blocks` never pads, so the caller keeps
//! the last 1..64 bytes of a message for `final`. `final` does not modify the state.
//!
//! The digest is the bytes of the final value `h` in memory order (little-endian words), as
//! printed by OpenSSL's gost engine, rhash and the Linux kernel: the empty message gives
//! `3f539a21...` (256 bits, the last 32 bytes of `h`) and `8e945da2...` (512 bits). RFC 6986
//! prints test vectors as big-endian integers, which is the same digest byte-reversed.
//!
//! What is typed in: the S-box `pi`, the 64 rows of the linear transformation `a` and the
//! twelve iteration constants `c`, as published in RFC 6986. The 16 KiB of combined tables
//! (S-box, permutation and linear step in one lookup) are derived from them at compile time.

const std = @import("std");

/// Streebog-256: IV of 0x01 bytes, the upper half of the final value.
pub const Streebog256 = StreebogImpl(32);
/// Streebog-512: IV of zeros, the whole final value.
pub const Streebog512 = StreebogImpl(64);

/// The nonlinear bijection (S-box) applied to every byte.
pub const pi = [256]u8{
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6,
};

/// The linear transformation: bit `i` of an input word (byte 0 is the low byte) contributes
/// `a[i]` to the output word.
pub const a = [64]u64{
    0x641c314b2b8ee083, 0xc83862965601dd1b, 0x8d70c431ac02a736, 0x07e095624504536c,
    0x0edd37c48a08a6d8, 0x1ca76e95091051ad, 0x3853dc371220a247, 0x70a6a56e2440598e,
    0xa48b474f9ef5dc18, 0x550b8e9e21f7a530, 0xaa16012142f35760, 0x492c024284fbaec0,
    0x9258048415eb419d, 0x39b008152acb8227, 0x727d102a548b194e, 0xe4fa2054a80b329c,
    0xf97d86d98a327728, 0xeffa11af0964ee50, 0xc3e9224312c8c1a0, 0x9bcf4486248d9f5d,
    0x2b838811480723ba, 0x561b0d22900e4669, 0xac361a443d1c8cd2, 0x456c34887a3805b9,
    0x5b068c651810a89e, 0xb60c05ca30204d21, 0x71180a8960409a42, 0xe230140fc0802984,
    0xd960281e9d1d5215, 0xafc0503c273aa42a, 0x439da0784e745554, 0x86275df09ce8aaa8,
    0x0321658cba93c138, 0x0642ca05693b9f70, 0x0c84890ad27623e0, 0x18150f14b9ec46dd,
    0x302a1e286fc58ca7, 0x60543c50de970553, 0xc0a878a0a1330aa6, 0x9d4df05d5f661451,
    0xaccc9ca9328a8950, 0x4585254f64090fa0, 0x8a174a9ec8121e5d, 0x092e94218d243cba,
    0x125c354207487869, 0x24b86a840e90f0d2, 0x486dd4151c3dfdb9, 0x90dab52a387ae76f,
    0x46b60f011a83988e, 0x8c711e02341b2d01, 0x05e23c0468365a02, 0x0ad97808d06cb404,
    0x14aff010bdd87508, 0x2843fd2067adea10, 0x5086e740ce47c920, 0xa011d380818e8f40,
    0x83478b07b2468764, 0x1b8e0b0e798c13c8, 0x3601161cf205268d, 0x6c022c38f90a4c07,
    0xd8045870ef14980e, 0xad08b0e0c3282d1c, 0x47107ddd9b505a38, 0x8e20faa72ba0b470,
};

/// The iteration constants, 8 little-endian words each.
pub const c: [12][8]u64 = @bitCast([96]u64{
    0xdd806559f2a64507, 0x05767436cc744d23, 0xa2422a08a460d315, 0x4b7ce09192676901,
    0x714eb88d7585c4fc, 0x2f6a76432e45d016, 0xebcb2f81c0657c1f, 0xb1085bda1ecadae9,
    0xe679047021b19bb7, 0x55dda21bd7cbcd56, 0x5cb561c2db0aa7ca, 0x9ab5176b12d69958,
    0x61d55e0f16b50131, 0xf3feea720a232b98, 0x4fe39d460f70b5d7, 0x6fa3b58aa99d2f1a,
    0x991e96f50aba0ab2, 0xc2b6f443867adb31, 0xc1c93a376062db09, 0xd3e20fe490359eb1,
    0xf2ea7514b1297b7b, 0x06f15e5f529c1f8b, 0x0a39fc286a3d8435, 0xf574dcac2bce2fc7,
    0x220cbebc84e3d12e, 0x3453eaa193e837f1, 0xd8b71333935203be, 0xa9d72c82ed03d675,
    0x9d721cad685e353f, 0x488e857e335c3c7d, 0xf948e1a05d71e4dd, 0xef1fdfb3e81566d2,
    0x601758fd7c6cfe57, 0x7a56a27ea9ea63f5, 0xdfff00b723271a16, 0xbfcd1747253af5a3,
    0x359e35d7800fffbd, 0x7f151c1f1686104a, 0x9a3f410c6ca92363, 0x4bea6bacad474799,
    0xfa68407a46647d6e, 0xbf71c57236904f35, 0x0af21f66c2bec6b6, 0xcffaa6b71c9ab7b4,
    0x187f9ab49af08ec6, 0x2d66c4f95142a46c, 0x6fa4c33b7a3039c0, 0xae4faeae1d3ad3d9,
    0x8886564d3a14d493, 0x3517454ca23c4af3, 0x06476983284a0504, 0x0992abc52d822c37,
    0xd3473e33197a93c9, 0x399ec6c7e6bf87c9, 0x51ac86febf240954, 0xf4c70e16eeaac5ec,
    0xa47f0dd4bf02e71e, 0x36acc2355951a8d9, 0x69d18d2bd1a5c42f, 0xf4892bcb929b0690,
    0x89b4443b4ddbc49a, 0x4eb7f8719c36de1e, 0x03e7aa020c6e4141, 0x9b1f5b424d93c9a7,
    0x7261445183235adb, 0x0e38dc92cb1f2a60, 0x7b2b8a9aa6079c54, 0x800a440bdbb2ceb1,
    0x3cd955b7e00d0984, 0x3a7d3a1b25894224, 0x944c9ad8ec165fde, 0x378f5a541631229b,
    0x74b4c7fb98459ced, 0x3698fad1153bb6c3, 0x7a1e6c303b7652f4, 0x9fe76702af69334b,
    0x1fffe18a1b336103, 0x8941e71cff8a78db, 0x382ae548b2e4f3f3, 0xabbedea680056f52,
    0x6bcaa4cd81f32d1b, 0xdea2594ac06fd85d, 0xefbacd1d7d476e98, 0x8a1d71efea48b9ca,
    0x2001802114846679, 0xd8fa6bbbebab0761, 0x3002c6cd635afe94, 0x7bcd9ed0efc889fb,
    0x48bc924af11bd720, 0xfaf417d5d9b21b99, 0xe71da4aa88e12852, 0x5d80ef9d1891cc86,
    0xf82012d430219f9b, 0xcda43c32bcdf1d77, 0xd21380b00449b17a, 0x378ee767f11631ba,
});

/// S, P and L together: `tables[j][b]` is the transformed value of the byte `b` found in word `j`.
pub const tables: [8][256]u64 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [8][256]u64 = undefined;
    for (0..8) |j| {
        for (0..256) |b| {
            var w: u64 = 0;
            for (0..8) |k| {
                if ((pi[b] >> @intCast(k)) & 1 == 1) w ^= a[8 * j + k];
            }
            t[j][b] = w;
        }
    }
    break :blk t;
};

const Words = [8]u64;

/// LPS: the S-box on every byte, the transposition P, the linear map L. Output word `i`
/// collects byte `i` of every input word.
fn lps(x: *const Words) Words {
    var out: Words = undefined;
    inline for (0..8) |i| {
        var w: u64 = 0;
        inline for (0..8) |j| w ^= tables[j][@as(u8, @truncate(x[j] >> (8 * i)))];
        out[i] = w;
    }
    return out;
}

fn xor(x: *const Words, y: *const Words) Words {
    var out: Words = undefined;
    for (&out, 0..) |*w, i| w.* = x[i] ^ y[i];
    return out;
}

/// The compression function g_N(h, m); `n` is the number of message bits hashed before this block.
fn g(h: *Words, n: u64, m: *const Words) void {
    var nn = @as(Words, @splat(0));
    nn[0] = n;
    var k = xor(h, &nn);
    k = lps(&k);
    var s = xor(m, &k);
    inline for (0..12) |i| {
        s = lps(&s);
        const kc = xor(&k, &c[i]);
        k = lps(&kc);
        s = xor(&s, &k);
    }
    // h' = E(k, m) ^ h ^ m
    const hm = xor(h, m);
    h.* = xor(&s, &hm);
}

/// `sigma += m` modulo 2^512.
fn addSum(sigma: *Words, m: *const Words) void {
    var carry: u64 = 0;
    for (sigma, 0..) |*w, i| {
        const r1 = @addWithOverflow(w.*, m[i]);
        const r2 = @addWithOverflow(r1[0], carry);
        w.* = r2[0];
        carry = @as(u64, r1[1]) | @as(u64, r2[1]);
    }
}

fn StreebogImpl(comptime digest_bytes: usize) type {
    return struct {
        pub const block_len = 64;
        pub const digest_len = digest_bytes;

        /// Layout is part of the wasm ABI (packages/crypto-api/src/wasm/blocks.mjs writes
        /// these offsets); a change bumps `runtime.abi_version`. Words are little-endian in
        /// memory. 136 bytes: more than the 128-byte state slot, so the JS side puts the
        /// digest behind the input chunk instead of in the output slot.
        pub const State = extern struct {
            /// Bytes compressed so far (the counter N of the specification is `8 * t`).
            t: u64,
            /// The chaining value.
            h: Words,
            /// The checksum: the sum of all blocks, modulo 2^512.
            sigma: Words,

            comptime {
                std.debug.assert(@sizeOf(State) == 136);
                std.debug.assert(@offsetOf(State, "h") == 8);
                std.debug.assert(@offsetOf(State, "sigma") == 72);
            }
        };

        pub fn init(st: *State) void {
            st.t = 0;
            st.h = @splat(if (digest_bytes == 32) 0x0101010101010101 else 0);
            st.sigma = @splat(0);
        }

        /// `block` (up to 64 bytes, zero padded here) as eight little-endian words.
        fn load(block: []const u8) Words {
            var buf = @as([block_len]u8, @splat(0));
            defer std.crypto.secureZero(u8, &buf);
            @memcpy(buf[0..block.len], block);
            var m: Words = undefined;
            for (&m, 0..) |*w, i| w.* = std.mem.readInt(u64, buf[8 * i ..][0..8], .little);
            return m;
        }

        /// One block: hash it with the current counter, then count it (`bytes` of it are
        /// message) and add it to the checksum.
        fn step(h: *Words, sigma: *Words, t: *u64, m: *const Words, bytes: u64) void {
            g(h, t.* *% 8, m);
            t.* +%= bytes;
            addSum(sigma, m);
        }

        /// Compress whole blocks (`data.len % 64 == 0`), advancing `st.t`.
        pub fn blocks(st: *State, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            var i: usize = 0;
            while (i < data.len) : (i += block_len) {
                var m = load(data[i..][0..block_len]);
                step(&st.h, &st.sigma, &st.t, &m, block_len);
                std.crypto.secureZero(u64, &m);
            }
        }

        /// Finish: `tail` (0..64 bytes) is the end of the message. Writes the digest; `st` is
        /// not modified.
        pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
            std.debug.assert(tail.len <= block_len);
            var h = st.h;
            var sigma = st.sigma;
            var t = st.t;
            defer std.crypto.secureZero(u64, &h);
            defer std.crypto.secureZero(u64, &sigma);
            var rest = tail;
            if (rest.len == block_len) {
                var full = load(rest);
                step(&h, &sigma, &t, &full, block_len);
                std.crypto.secureZero(u64, &full);
                rest = rest[block_len..];
            }
            var last = @as([block_len]u8, @splat(0));
            defer std.crypto.secureZero(u8, &last);
            @memcpy(last[0..rest.len], rest);
            last[rest.len] = 0x01;
            var m = load(&last);
            defer std.crypto.secureZero(u64, &m);
            step(&h, &sigma, &t, &m, rest.len);
            // `t` is now the whole length in bytes. The two last steps use N = 0.
            var len_bits = @as(Words, @splat(0));
            len_bits[0] = t *% 8;
            g(&h, 0, &len_bits);
            g(&h, 0, &sigma);
            var bytes: [64]u8 = undefined;
            defer std.crypto.secureZero(u8, &bytes);
            for (h, 0..) |w, i| std.mem.writeInt(u64, bytes[8 * i ..][0..8], w, .little);
            @memcpy(out, bytes[64 - digest_len ..]);
        }
    };
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

fn hexTo(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// Whole-message hash over `blocks`/`final`, buffering like the JS hasher does (the last
/// 1..64 bytes are held back), with the data fed in `piece`-byte updates.
fn oneShot(comptime T: type, message: []const u8, piece: usize, out: *[T.digest_len]u8) void {
    var st: T.State = undefined;
    T.init(&st);
    var buf: [T.block_len]u8 = undefined;
    var n: usize = 0;
    var rest = message;
    while (rest.len > 0) {
        var data = rest[0..@min(piece, rest.len)];
        rest = rest[data.len..];
        while (data.len > 0) {
            if (n == T.block_len) {
                T.blocks(&st, buf[0..T.block_len]);
                n = 0;
            }
            const take = @min(data.len, T.block_len - n);
            @memcpy(buf[n..][0..take], data[0..take]);
            n += take;
            data = data[take..];
        }
    }
    T.final(&st, buf[0..n], out);
}

test "typed-in tables: the S-box is a permutation, spot values of the derived tables" {
    var seen = @as([256]bool, @splat(false));
    for (pi) |b| {
        try testing.expect(!seen[b]);
        seen[b] = true;
    }
    // First and last words of the combined tables, from the published reference tables.
    try testing.expectEqual(@as(u64, 0xd01f715b5c7ef8e6), tables[0][0]);
    try testing.expectEqual(@as(u64, 0x16fa240980778325), tables[0][1]);
    try testing.expectEqual(@as(u64, 0x72d14d3493b2e388), tables[7][254]);
    try testing.expectEqual(@as(u64, 0xd6a30f258c153427), tables[7][255]);
    // The rows of the linear map are independent, so L is a bijection: no two table entries
    // of one byte position collide.
    for (tables) |t| {
        for (0..256) |i| for (i + 1..256) |j| try testing.expect(t[i] != t[j]);
    }
}

test "RFC 6986 and published vectors, at every update size" {
    const m1 = "012345678901234567890123456789012345678901234567890123456789012";
    const cases = [_]struct { msg: []const u8, h256: []const u8, h512: []const u8 }{
        .{
            .msg = "",
            .h256 = "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
            .h512 = "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
        },
        .{
            .msg = m1,
            .h256 = "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
            .h512 = "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
        },
    };
    for (cases) |v| {
        for ([_]usize{ 1, 7, 63, 64, 65, 1000 }) |piece| {
            var d256: [32]u8 = undefined;
            oneShot(Streebog256, v.msg, piece, &d256);
            try testing.expectEqualSlices(u8, &hexTo(32, v.h256), &d256);
            var d512: [64]u8 = undefined;
            oneShot(Streebog512, v.msg, piece, &d512);
            try testing.expectEqualSlices(u8, &hexTo(64, v.h512), &d512);
        }
    }
}

test "padding boundaries: every length up to 200 agrees between update splits" {
    var msg: [200]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    for (0..msg.len + 1) |len| {
        var one: [64]u8 = undefined;
        oneShot(Streebog512, msg[0..len], 1000, &one);
        var split: [64]u8 = undefined;
        oneShot(Streebog512, msg[0..len], 5, &split);
        try testing.expectEqualSlices(u8, &one, &split);
    }
}

test "final does not change the state" {
    var st: Streebog256.State = undefined;
    Streebog256.init(&st);
    const before = st;
    var out: [32]u8 = undefined;
    Streebog256.final(&st, "abc", &out);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
