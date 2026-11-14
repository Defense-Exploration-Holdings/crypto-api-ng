//! Whirlpool, a faithful port of crypto-api 0.8.5 `src/hasher/whirlpool.mjs`:
//! the final Whirlpool, Whirlpool-T (`type: 't'`) and Whirlpool-0 (`type: '0'`),
//! including the `rounds` option.
//!
//! The three variants differ only in tables. Whirlpool-0 uses the original
//! S-box `sbox0` and the circulant row `theta0`, Whirlpool-T uses the
//! generated S-box and `theta0`, and Whirlpool uses the generated S-box and
//! `theta`. All tables are derived at compile time exactly like the original's
//! `calculateSBOX()`/`calculateRC()`; only the 256-entry `C[0]` column is
//! stored, the other seven are rotations of it by whole bytes.
//!
//! The original hashes with the Hasher32be framing: 64-byte blocks, sixteen
//! int32 hash words (the eight 64-bit words as hi/lo pairs) and the 8-byte
//! 32-bit-bug length field (`be32.lengthField`) instead of the 256-bit field of
//! the specification, placed so that padding reaches offset 56 for a tail
//! shorter than 32 bytes and offset 120 otherwise. For every message shorter
//! than 2^31 bytes that is the same bytes the specification pads.

const std = @import("std");
const be32 = @import("be32.zig");

pub const block_len = be32.block_size;
pub const digest_len = 64;
pub const max_rounds = 10;

pub const Variant = enum { whirlpool, whirlpool0, whirlpool_t };

/// Layout is part of the wasm ABI (JS writes these offsets, see
/// packages/crypto-api/src/hasher/whirlpool.mjs); a change bumps `runtime.abi_version`.
/// 152 bytes, larger than the 128-byte state slot, so `final` output is
/// written at the input offset (like SHA-512).
pub const State = extern struct {
    /// Eight 64-bit words as (hi, lo) pairs of the original's int32 `state.hash`.
    hash: [16]u32,
    /// Rounds per block, 1..10.
    rounds: u32,
    _reserved0: u32,
    /// Total bytes passed to `update`. Only the low 32 bits matter (`be32.lengthField`).
    length: u64,
    /// Bytes currently buffered in `buf` (0..63).
    buffered: u32,
    _reserved1: u32,
    buf: [block_len]u8,

    comptime {
        std.debug.assert(@sizeOf(State) == 152);
        std.debug.assert(@offsetOf(State, "hash") == 0);
        std.debug.assert(@offsetOf(State, "rounds") == 64);
        std.debug.assert(@offsetOf(State, "length") == 72);
        std.debug.assert(@offsetOf(State, "buffered") == 80);
        std.debug.assert(@offsetOf(State, "buf") == 88);
    }
};

/// The S-box of Whirlpool-0.
const sbox0 = [256]u8{
    0x68, 0xd0, 0xeb, 0x2b, 0x48, 0x9d, 0x6a, 0xe4, 0xe3, 0xa3, 0x56, 0x81, 0x7d, 0xf1, 0x85, 0x9e,
    0x2c, 0x8e, 0x78, 0xca, 0x17, 0xa9, 0x61, 0xd5, 0x5d, 0x0b, 0x8c, 0x3c, 0x77, 0x51, 0x22, 0x42,
    0x3f, 0x54, 0x41, 0x80, 0xcc, 0x86, 0xb3, 0x18, 0x2e, 0x57, 0x06, 0x62, 0xf4, 0x36, 0xd1, 0x6b,
    0x1b, 0x65, 0x75, 0x10, 0xda, 0x49, 0x26, 0xf9, 0xcb, 0x66, 0xe7, 0xba, 0xae, 0x50, 0x52, 0xab,
    0x05, 0xf0, 0x0d, 0x73, 0x3b, 0x04, 0x20, 0xfe, 0xdd, 0xf5, 0xb4, 0x5f, 0x0a, 0xb5, 0xc0, 0xa0,
    0x71, 0xa5, 0x2d, 0x60, 0x72, 0x93, 0x39, 0x08, 0x83, 0x21, 0x5c, 0x87, 0xb1, 0xe0, 0x00, 0xc3,
    0x12, 0x91, 0x8a, 0x02, 0x1c, 0xe6, 0x45, 0xc2, 0xc4, 0xfd, 0xbf, 0x44, 0xa1, 0x4c, 0x33, 0xc5,
    0x84, 0x23, 0x7c, 0xb0, 0x25, 0x15, 0x35, 0x69, 0xff, 0x94, 0x4d, 0x70, 0xa2, 0xaf, 0xcd, 0xd6,
    0x6c, 0xb7, 0xf8, 0x09, 0xf3, 0x67, 0xa4, 0xea, 0xec, 0xb6, 0xd4, 0xd2, 0x14, 0x1e, 0xe1, 0x24,
    0x38, 0xc6, 0xdb, 0x4b, 0x7a, 0x3a, 0xde, 0x5e, 0xdf, 0x95, 0xfc, 0xaa, 0xd7, 0xce, 0x07, 0x0f,
    0x3d, 0x58, 0x9a, 0x98, 0x9c, 0xf2, 0xa7, 0x11, 0x7e, 0x8b, 0x43, 0x03, 0xe2, 0xdc, 0xe5, 0xb2,
    0x4e, 0xc7, 0x6d, 0xe9, 0x27, 0x40, 0xd8, 0x37, 0x92, 0x8f, 0x01, 0x1d, 0x53, 0x3e, 0x59, 0xc1,
    0x4f, 0x32, 0x16, 0xfa, 0x74, 0xfb, 0x63, 0x9f, 0x34, 0x1a, 0x2a, 0x5a, 0x8d, 0xc9, 0xcf, 0xf6,
    0x90, 0x28, 0x88, 0x9b, 0x31, 0x0e, 0xbd, 0x4a, 0xe8, 0x96, 0xa6, 0x0c, 0xc8, 0x79, 0xbc, 0xbe,
    0xef, 0x6e, 0x46, 0x97, 0x5b, 0xed, 0x19, 0xd9, 0xac, 0x99, 0xa8, 0x29, 0x64, 0x1f, 0xad, 0x55,
    0x13, 0xbb, 0xf7, 0x6f, 0xb9, 0x47, 0x2f, 0xee, 0xb8, 0x7b, 0x89, 0x30, 0xd3, 0x7f, 0x76, 0x82,
};

/// Mini-boxes of the generated S-box (`eBOX`, `rBOX` of the original).
const ebox = [16]u8{ 0x1, 0xb, 0x9, 0xc, 0xd, 0x6, 0xf, 0x3, 0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0 };
const rbox = [16]u8{ 0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0 };

/// `calculateSBOX()` of the original: the S-box of Whirlpool-T and Whirlpool.
fn generateSbox() [256]u8 {
    var ibox: [16]u8 = undefined;
    for (ebox, 0..) |e, i| ibox[e] = @intCast(i);
    var s: [256]u8 = undefined;
    for (&s, 0..) |*out, i| {
        const left = ebox[i >> 4];
        const right = ibox[i & 0xf];
        const temp = rbox[left ^ right];
        out.* = (ebox[left ^ temp] << 4) | ibox[right ^ temp];
    }
    return s;
}

/// Matrix rows (`theta` and `theta0` of the original): the circulant matrix is
/// `cir(theta)`, with the multipliers 1, 2, 3, 4, 5, 8, 9 of GF(2^8) mod 0x11d.
const theta = [8]u8{ 1, 1, 4, 1, 8, 5, 2, 9 };
const theta0 = [8]u8{ 1, 1, 3, 1, 5, 8, 9, 5 };

fn xtime(x: u16) u16 {
    const y = x << 1;
    return if (y >= 0x100) y ^ 0x11d else y;
}

const Tables = struct {
    /// `C[0]` of the original as 64-bit words (hi word first); `C[t]` is this
    /// rotated right by `8 * t` bits.
    c0: [256]u64,
    /// Round constants, `rc[0] = 0` and `rc[1..=10]`.
    rc: [max_rounds + 1]u64,
};

/// `calculateRC()` of the original.
fn buildTables(comptime sb: [256]u8, comptime th: [8]u8) Tables {
    @setEvalBranchQuota(200_000);
    var t: Tables = undefined;
    for (0..256) |i| {
        var v: [10]u16 = @splat(0);
        v[1] = sb[i];
        v[2] = xtime(v[1]);
        v[3] = v[2] ^ v[1];
        v[4] = xtime(v[2]);
        v[5] = v[4] ^ v[1];
        v[8] = xtime(v[4]);
        v[9] = v[8] ^ v[1];
        var word: u64 = 0;
        for (th) |idx| word = (word << 8) | v[idx];
        t.c0[i] = word;
    }
    t.rc[0] = 0;
    for (1..max_rounds + 1) |r| {
        var rc: u64 = 0;
        for (0..8) |j| {
            const mask = @as(u64, 0xff) << @intCast(56 - 8 * j);
            rc ^= std.math.rotr(u64, t.c0[8 * (r - 1) + j], 8 * j) & mask;
        }
        t.rc[r] = rc;
    }
    return t;
}

const sbox = generateSbox();
const tables = [3]Tables{
    buildTables(sbox, theta),
    buildTables(sbox0, theta0),
    buildTables(sbox, theta0),
};

fn tableFor(v: Variant) *const Tables {
    return &tables[@backingInt(v)];
}

/// XOR over `t` of `C[t][byte t (from the top) of x[(i - t) & 7]]`: one output
/// word of the combined substitution and diffusion layer.
inline fn lookup(c0: *const [256]u64, x: *const [8]u64, i: usize) u64 {
    var acc: u64 = 0;
    inline for (0..8) |t| {
        const b: u8 = @truncate(x[(i -% t) & 7] >> (56 - 8 * t));
        acc ^= std.math.rotr(u64, c0[b], 8 * t);
    }
    return acc;
}

/// Compress one block into `h`, running `rounds` rounds (1..10).
pub fn compress(v: Variant, h: *[16]u32, block: *const [block_len]u8, rounds: u32) void {
    std.debug.assert(rounds >= 1 and rounds <= max_rounds);
    const tb = tableFor(v);

    var key: [8]u64 = undefined;
    var state: [8]u64 = undefined;
    var m: [8]u64 = undefined;
    for (0..8) |i| {
        m[i] = std.mem.readInt(u64, block[i * 8 ..][0..8], .big);
        key[i] = (@as(u64, h[2 * i]) << 32) | h[2 * i + 1];
        state[i] = m[i] ^ key[i];
    }

    var r: usize = 1;
    while (r <= rounds) : (r += 1) {
        var next: [8]u64 = undefined;
        for (0..8) |i| next[i] = lookup(&tb.c0, &key, i);
        next[0] ^= tb.rc[r];
        key = next;
        for (0..8) |i| next[i] = key[i] ^ lookup(&tb.c0, &state, i);
        state = next;
    }

    for (0..8) |i| {
        const nh = ((@as(u64, h[2 * i]) << 32) | h[2 * i + 1]) ^ state[i] ^ m[i];
        h[2 * i] = @truncate(nh >> 32);
        h[2 * i + 1] = @truncate(nh);
    }
}

/// One algorithm: the functions of a variant, with the same names for all three.
pub fn Algo(comptime v: Variant) type {
    return struct {
        pub fn init(st: *State, rounds: u32) void {
            st.* = .{ .hash = @splat(0), .rounds = rounds, ._reserved0 = 0, .length = 0, .buffered = 0, ._reserved1 = 0, .buf = @splat(0) };
        }

        /// Compress whole blocks (`data.len % 64 == 0`) into `st.hash`, touching
        /// nothing else. This is what the JS facade calls: buffering and counting
        /// stay in JS.
        pub fn blocks(st: *State, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            var rest = data;
            while (rest.len >= block_len) : (rest = rest[block_len..]) {
                compress(v, &st.hash, rest[0..block_len], st.rounds);
            }
        }

        /// Absorb `data`, equivalent to the original `update()` for a binary
        /// string whose code units are all <= 0xFF.
        pub fn update(st: *State, data: []const u8) void {
            be32.update(State, blocks, st, data);
        }

        /// Pad, process the final block(s) and write the 64 digest bytes.
        /// Mutates `st` the way the original `finalize()` mutates `this.state`.
        pub fn final(st: *State, out: *[digest_len]u8) void {
            var buf: [2 * block_len]u8 = undefined;
            blocks(st, finalTail(st.buf[0..st.buffered], @truncate(st.length), &buf));
            st.buffered = 0;
            @memset(&st.buf, 0);
            for (st.hash, 0..) |word, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .big);
        }
    };
}

pub const whirlpool = Algo(.whirlpool);
pub const whirlpool0 = Algo(.whirlpool0);
pub const whirlpoolT = Algo(.whirlpool_t);

/// Padding done by the original `finalize()`: ISO 7816-4 (`0x80`, then zeros)
/// up to offset 56 when the buffered tail is shorter than 32 bytes, up to
/// offset 120 otherwise, then the 8-byte length field of `be32.lengthField`.
/// Returns the 64 or 128 bytes that remain to be compressed.
pub fn finalTail(tail: []const u8, len_lo: u32, out: *[2 * block_len]u8) []const u8 {
    std.debug.assert(tail.len < block_len);
    @memset(out, 0);
    @memcpy(out[0..tail.len], tail);
    out[tail.len] = 0x80;
    const total: usize = if (tail.len < 32) block_len else 2 * block_len;
    out[total - 8 ..][0..8].* = be32.lengthField(len_lo);
    return out[0..total];
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn digestOf(comptime A: type, rounds: u32, data: []const u8) [digest_len]u8 {
    var st: State = undefined;
    A.init(&st, rounds);
    A.update(&st, data);
    var out: [digest_len]u8 = undefined;
    A.final(&st, &out);
    return out;
}

fn expectHex(comptime A: type, rounds: u32, input: []const u8, hex: []const u8) !void {
    var expected: [digest_len]u8 = undefined;
    const exp = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, exp, &digestOf(A, rounds, input));
}

test "State layout is stable (JS depends on these offsets)" {
    try testing.expectEqual(@as(usize, 152), @sizeOf(State));
    try testing.expectEqual(@as(usize, 64), @offsetOf(State, "rounds"));
    try testing.expectEqual(@as(usize, 72), @offsetOf(State, "length"));
    try testing.expectEqual(@as(usize, 80), @offsetOf(State, "buffered"));
    try testing.expectEqual(@as(usize, 88), @offsetOf(State, "buf"));
}

const Case = struct { input: []const u8, hex: []const u8 };

fn xs(comptime n: usize) []const u8 {
    const bytes: [n]u8 = @splat('x');
    return &bytes;
}

const cases_whirlpool = [_]Case{
    .{ .input = "", .hex = "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3" },
    .{ .input = "abc", .hex = "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5" },
    .{ .input = xs(31), .hex = "797c14f03584a2b65a03d3f1f9a337f9c109d463c8d822723fc80e07faaae95c366035f5f5a1474813818e03c6c12d04136bc630001a465c932e99d65eae8c35" },
    .{ .input = xs(32), .hex = "c0a5e7e8964adde9b543bfab118c9d7962d70d74edd5e1e1bbfb173ac0f8c95922e65a282480fafa0fa698eeed82e5d57af2b46fa7fbb6f868d4a6fa57960ff3" },
    .{ .input = xs(63), .hex = "193c4edbb9dba0aec8d524a19287f03a10141df638a7c1a1f4495164c0d2e3de2d607160afea6ad10b410b5125ee7cf4e54d1009f580ce5321d2ae75b4dabe1e" },
    .{ .input = xs(64), .hex = "24922b3af68625c1cfff57682513b0f33d74da807fe921e7b63cfb656f1f22fdcd7f057af9a72c019d718edebabf2c82703f68c2c74ffd38e44b913260bcb7f9" },
    .{ .input = xs(100), .hex = "5a9df165a79280d6bd4ff047f621edd2ef52537b1af983d1006b9796074bb65911312e0fb4e721189423f10b19f15902ca1d21a8882cef6725237cff2ce4e5fc" },
};

const cases_whirlpool0 = [_]Case{
    .{ .input = "", .hex = "b3e1ab6eaf640a34f784593f2074416accd3b8e62c620175fca0997b1ba2347339aa0d79e754c308209ea36811dfa40c1c32f1a2b9004725d987d3635165d3c8" },
    .{ .input = "abc", .hex = "54ee18b0bbd4dd38a211699f2829793156e5842df502a2a25995c6c541f28cc050ff57d4af772dee7cedcc4c34c3b8ec06446c6657f2f36c2c06464399879b86" },
    .{ .input = xs(31), .hex = "a916e29c05c18ac9fe89e1bf2f6142e32b1b9f3ae737ec4d0ff02429e6e0af4b89b258c55b182dcca65a70882d1d63b689158124420cadfe954e8bd3e129aa4c" },
    .{ .input = xs(32), .hex = "76a5dc450ab13db25c70bf19e27810bb85c00e4052270c4ff740cc164644528d162017e877f95b4733374d31b64acb66653e7ec33ebbefc6678b387d3afb7d56" },
    .{ .input = xs(63), .hex = "26a7ba6f4789a7385b2706cdba7f9423e6a38594f09886a3b9a1cc18779cfb65b766963f544fa9e19a44e0323d845bed81bc6c84cf9dac4a727499b21450d7ba" },
    .{ .input = xs(64), .hex = "0485b69114da002a5dcde25c2f3c924acfc24bf7722ff383f4452d32ffaa0daafc053d2ed730b927a5dcc4b4ff72380a3a40a227eaa3b90b953af6974f136060" },
    .{ .input = xs(100), .hex = "048681284dac1961eedbe742e5687d242bf7fcd35b149c5201ae2ec4769ed3bc30f8891a6614793841b924fa81833822e3a498141cd10f1c8df897eeb400e952" },
};

const cases_whirlpool_t = [_]Case{
    .{ .input = "", .hex = "470f0409abaa446e49667d4ebe12a14387cedbd10dd17b8243cad550a089dc0feea7aa40f6c2aaab71c6ebd076e43c7cfca0ad32567897dcb5969861049a0f5a" },
    .{ .input = "abc", .hex = "8afc0527dcc0a19623860ef2369d0e25de8ebe2abaa40f598afaf6b07c002ed73e4fc0fc220fd4f54f74b5d6b07aa57764c3dbdcc2cdd919d89fa8155a34b841" },
    .{ .input = xs(31), .hex = "be178237fc5b6f5788f7a8227f128f74903bf0ccdc932dc7f443a7f20e52276dc88686f5e17eff3df7ada9361d32a8b1c77aafc86db14a2f0e333d42645af149" },
    .{ .input = xs(32), .hex = "1fc44e17b2353f54e907674164d004d883b9b5d133dc965b2efc38b8b2007cafb5dee1524c63818710e59a488011f6b3ab63e4e229dbb0803e43d50dc4af2c60" },
    .{ .input = xs(63), .hex = "707a1da90d8fa49bb977f8ba3421dfede0070b01139d294a2dd140c102579e1b06f15043e0d32d3b3d378983d52e7aeb80bf424d543299e2e479e8157d86e9e0" },
    .{ .input = xs(64), .hex = "f55e03fa35c9e9ef69c80c4da0e888c43902ed28fbffb52ae5c9d131b3c273783bc454dddf51519712ad980e883534f58341f761d6745e79c2bccafa5a769210" },
    .{ .input = xs(100), .hex = "55de9871642ab21851187cd695431652d533ed05a964c1ebb69c943125190a679cc3ffc939c9b2011dce9f8ab68e9d1c6905698e56ee8df8123b77acece13278" },
};

test "known answers: ISO/IEC 10118-3 and values captured from crypto-api 0.8.5, all three variants" {
    for (cases_whirlpool) |c| try expectHex(whirlpool, max_rounds, c.input, c.hex);
    for (cases_whirlpool0) |c| try expectHex(whirlpool0, max_rounds, c.input, c.hex);
    for (cases_whirlpool_t) |c| try expectHex(whirlpoolT, max_rounds, c.input, c.hex);
}

test "reduced rounds: values captured from crypto-api 0.8.5" {
    // The digest of "abc" after `rounds` rounds; rounds 1 leaves most of the padding visible.
    try expectHex(whirlpool, 1, "abc", "6e56f97f3ff32fe0ebcdcd13cd26de872d2c98985a98b4c28903838f8f068f0c0000000000000000000000000000000005140528110a2d050000000000000018");
    try expectHex(whirlpool, 5, "abc", "67c4d99805548d338455fec41fb20b1c6ea293493f1789b77d02c9a05285bbefac55d7a9444889a9cbdebe43aa4db5a060a6bac025d94f8cd7e462e5d4a8ccd8");
    try expectHex(whirlpool, 9, "abc", "2a923d1b461416d072a8c1344713172d17332a69fb34989883b1ee379347eca03b3967112335b578fc783d1f9d2fb6ae3cf93864969bde6c425ad1476c0c49b6");
    try expectHex(whirlpool0, 1, "abc", "f04b9e52720608de4de2e23be24d43a11ddf6a6abe6adf7720241404040c041400000000000000000000000000000000355f35e1b580e1350000000000000018");
    try expectHex(whirlpool0, 5, "abc", "62eea0082b662294eb6e3af45064959af987cd093d55d121b8648b1fd03457c93b34cf4a799e700296e05550248e22665f87150f9576a4fd68599c1205923ed9");
    try expectHex(whirlpool0, 9, "abc", "67843902028e2dfba05857a388fd2a112daddfc015b222c8d2793af7ba7b9b5f5eae61fb7c66a17066f5a203fa03b5562853e47efca40d3644c62cf0218ed170");
    try expectHex(whirlpoolT, 1, "abc", "6e569c7fcc00ae04decdcd4acdde26eb2cc29898b598c2b40c83898f8f8c8f8900000000000000000000000000000000050f0511282d11050000000000000018");
    try expectHex(whirlpoolT, 5, "abc", "1f60302042bbe77e0528f8ec483a2dc36a23be6ef20c6c8f73c3be249fc69b00eed10ca638937c58dfdc20d22ef87e5ac07a68496270b0b8147b9243c24222fe");
    try expectHex(whirlpoolT, 9, "abc", "400b468ea038fa83379c55ebd309a469fd71bf0e0d3e4cdbc9a5caf39b0c3dc8b9892ab49830b1ea280768c46a5b273a9a2ffafda31f6986a5c8301b5c3bda7a");
}

/// FNV-1a over the 32-bit words of `C[0..8]` and `RC` exactly as the original
/// stores them (`C[t][2i]` hi, `C[t][2i+1]` lo, `RC[2r]` hi, `RC[2r+1]` lo).
fn tableFingerprint(v: Variant) u32 {
    const tb = tableFor(v);
    var f: u32 = 0x811c9dc5;
    const mix = struct {
        fn go(acc: *u32, x: u32) void {
            for (0..4) |i| {
                acc.* ^= (x >> @intCast(8 * i)) & 0xff;
                acc.* *%= 0x01000193;
            }
        }
    }.go;
    for (0..8) |t| {
        for (0..256) |i| {
            const w = std.math.rotr(u64, tb.c0[i], 8 * t);
            mix(&f, @truncate(w >> 32));
            mix(&f, @truncate(w));
        }
    }
    for (0..max_rounds + 1) |r| {
        mix(&f, @truncate(tb.rc[r] >> 32));
        mix(&f, @truncate(tb.rc[r]));
    }
    return f;
}

test "derived tables equal the original's (fingerprints of C[0..8] and RC taken from 0.8.5)" {
    try testing.expectEqual(@as(u32, 0x214037aa), tableFingerprint(.whirlpool));
    try testing.expectEqual(@as(u32, 0x08004df0), tableFingerprint(.whirlpool0));
    try testing.expectEqual(@as(u32, 0x3a579b42), tableFingerprint(.whirlpool_t));
}

test "the generated S-box starts like the Whirlpool S-box" {
    // ISO/IEC 10118-3: S[0..4] = 0x18, 0x23, 0xc6, 0xe8.
    try testing.expectEqualSlices(u8, &.{ 0x18, 0x23, 0xc6, 0xe8 }, sbox[0..4]);
    var seen: [256]bool = @splat(false);
    for (sbox) |x| seen[x] = true;
    for (seen) |s| try testing.expect(s);
    seen = @splat(false);
    for (sbox0) |x| seen[x] = true;
    for (seen) |s| try testing.expect(s);
}

test "streaming with random splits equals one shot, at every length 0..300, all variants" {
    var prng = std.Random.DefaultPrng.init(0x5a);
    const rnd = prng.random();
    var data: [300]u8 = undefined;
    rnd.bytes(&data);
    inline for (.{ whirlpool, whirlpool0, whirlpoolT }) |A| {
        for (0..data.len + 1) |len| {
            const want = digestOf(A, max_rounds, data[0..len]);
            var st: State = undefined;
            A.init(&st, max_rounds);
            var pos: usize = 0;
            while (pos < len) {
                const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 70));
                A.update(&st, data[pos..][0..n]);
                pos += n;
            }
            var got: [digest_len]u8 = undefined;
            A.final(&st, &got);
            try testing.expectEqualSlices(u8, &want, &got);
            try testing.expectEqual(@as(u64, len), st.length);
        }
    }
}

test "padding switches to two blocks at 32 bytes" {
    var buf: [2 * block_len]u8 = undefined;
    const zeros: [63]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 64), finalTail(zeros[0..0], 0, &buf).len);
    try testing.expectEqual(@as(usize, 64), finalTail(zeros[0..31], 31, &buf).len);
    try testing.expectEqual(@as(usize, 128), finalTail(zeros[0..32], 32, &buf).len);
    try testing.expectEqual(@as(usize, 128), finalTail(zeros[0..63], 63, &buf).len);
}

test "the 2 GiB length-field bug is kept (values captured from 0.8.5)" {
    const Check = struct {
        fn run(comptime A: type, len: u64, hex: []const u8) !void {
            var st: State = undefined;
            A.init(&st, max_rounds);
            st.length = len;
            @memcpy(st.buf[0..3], "abc");
            st.buffered = 3;
            var out: [digest_len]u8 = undefined;
            A.final(&st, &out);
            var expected: [digest_len]u8 = undefined;
            try testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&expected, hex), &out);
        }
    };
    try Check.run(whirlpool, 1 << 31, "d3f1c6cd9f83b6f72f1cf4949eed54acc2b5532f2814fc22f9cfc2c45071ba0f08fa8adf171a8fa61b0f0df914170997229e8f623a99753d276a855bb70ca0a2");
    try Check.run(whirlpool, (1 << 31) + 5, "6308b95a8ff203fddf4420b4def4885b6906206ca46caf27e17381144ff34db1293d066fae1769bac38a38a036855c134272fe217ce7f377eb4ba386f544928f");
    try Check.run(whirlpool0, 1 << 31, "9c0ced2fd596b2e9346cc34f0bc99464a8b8dd647a828a7bfc98f625ccf7c0726ed34649a9d6dcc24782fca3b4ec67047344e72517b53c4025972a1cea2c010e");
    try Check.run(whirlpool0, (1 << 31) + 5, "d0170c32d2fdc1a9323cca323b0208786dc5d18111d851027a21273157fd9a8826b43e4ba194375789a12e61cb530048eff29d383a9fae4a9871b00a4585b123");
    try Check.run(whirlpoolT, 1 << 31, "177d3d87592a57118d6897df75568d93d833f64700753de9e50a0850d61b79decfd297a4aa260decd781e59e852690a1975eee1460531bbb96e30002f2ecf736");
    try Check.run(whirlpoolT, (1 << 31) + 5, "d84a8ef759267338b8742f77d4d67e586d17952f5b6fee23623c24ea35aafb23f701ce7eaa98c49eacdc4abf5e72f86898cbced0dc1e97aecc256384623ddd19");
}

test "state after final matches the original (second final)" {
    var st: State = undefined;
    whirlpool.init(&st, max_rounds);
    whirlpool.update(&st, "abc");
    var out: [digest_len]u8 = undefined;
    whirlpool.final(&st, &out);
    try testing.expectEqual(@as(u32, 0), st.buffered);
    try testing.expectEqual(@as(u64, 3), st.length);
    whirlpool.final(&st, &out);
    try testing.expectEqualStrings("b9f317fb19295286a75c9e0025192157991a342a2ba0660340f6fa33f8223f17394fb6d8e46b428f111a024542f77e1392f0a1ea7665b69efa1b542cc6fea68c", &std.fmt.bytesToHex(out, .lower));
}
