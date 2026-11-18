//! SipHash-2-4 and SipHash-1-3 (Jean-Philippe Aumasson and Daniel J. Bernstein): keyed 64-bit
//! hashes, a short-input PRF for hash tables that face untrusted keys. With a secret 128-bit key
//! the output cannot be predicted; it is not a general-purpose MAC (64-bit tags) nor a hash
//! without a key.
//!
//! These are new algorithms (crypto-api 0.8.5 has no SipHash). The state JS keeps between calls
//! is the byte counter and v0..v3; the key only sets the initial state. Buffering stays in the
//! JS hasher and wasm runs `blocks` (whole 8-byte words) and `final`, which does not modify the
//! state. The digest is the output of the reference implementation: the 64-bit result, least
//! significant byte first.

const std = @import("std");

/// Layout is part of the wasm ABI (packages/crypto-api/src/wasm/blocks.mjs writes these
/// offsets); a change bumps `runtime.abi_version`.
pub const State = extern struct {
    /// Bytes compressed so far (whole words).
    t: u64 align(8),
    /// v0, v1, v2, v3.
    v: [4]u64 align(8),

    comptime {
        std.debug.assert(@sizeOf(State) == 40);
        std.debug.assert(@offsetOf(State, "v") == 8);
    }
};

pub const key_len = 16;

pub fn init(st: *State, key: *const [key_len]u8) void {
    const k0 = std.mem.readInt(u64, key[0..8], .little);
    const k1 = std.mem.readInt(u64, key[8..16], .little);
    st.t = 0;
    st.v = .{ k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d, k0 ^ 0x6c7967656e657261, k1 ^ 0x7465646279746573 };
}

inline fn sipRound(v: *[4]u64) void {
    v[0] +%= v[1];
    v[1] = std.math.rotl(u64, v[1], 13);
    v[1] ^= v[0];
    v[0] = std.math.rotl(u64, v[0], 32);
    v[2] +%= v[3];
    v[3] = std.math.rotl(u64, v[3], 16);
    v[3] ^= v[2];
    v[0] +%= v[3];
    v[3] = std.math.rotl(u64, v[3], 21);
    v[3] ^= v[0];
    v[2] +%= v[1];
    v[1] = std.math.rotl(u64, v[1], 17);
    v[1] ^= v[2];
    v[2] = std.math.rotl(u64, v[2], 32);
}

/// SipHash-c-d: `c` rounds per message word, `d` finalization rounds.
pub fn SipHash(comptime c: usize, comptime d: usize) type {
    return struct {
        pub const block_len = 8;
        pub const digest_len = 8;
        pub const State = state;
        pub const init = initFn;

        inline fn compress(v: *[4]u64, m: u64) void {
            v[3] ^= m;
            inline for (0..c) |_| sipRound(v);
            v[0] ^= m;
        }

        /// Process whole words (`data.len % 8 == 0`), advancing `st.t`.
        pub fn blocks(st: *state, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            var i: usize = 0;
            while (i < data.len) : (i += 8) compress(&st.v, std.mem.readInt(u64, data[i..][0..8], .little));
            st.t += data.len;
        }

        /// Finish: `tail` (0..8 bytes) is the end of the message. Writes the 64-bit result,
        /// least significant byte first; `st` is not modified.
        pub fn final(st: *const state, tail: []const u8, out: *[digest_len]u8) void {
            std.debug.assert(tail.len <= block_len);
            var v = st.v;
            var rest = tail;
            if (rest.len == block_len) {
                compress(&v, std.mem.readInt(u64, rest[0..8], .little));
                rest = rest[8..];
            }
            const total = st.t + tail.len;
            var b: u64 = @as(u64, @truncate(total)) << 56;
            for (rest, 0..) |x, i| b |= @as(u64, x) << @intCast(8 * i);
            compress(&v, b);
            v[2] ^= 0xff;
            inline for (0..d) |_| sipRound(&v);
            std.mem.writeInt(u64, out, v[0] ^ v[1] ^ v[2] ^ v[3], .little);
            std.crypto.secureZero(u64, &v);
        }
    };
}

const state = State;
const initFn = init;

pub const SipHash24 = SipHash(2, 4);
pub const SipHash13 = SipHash(1, 3);

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

fn run(comptime T: type, key: *const [16]u8, message: []const u8) [8]u8 {
    var st: State = undefined;
    T.init(&st, key);
    const keep = if (message.len == 0) 0 else (message.len - 1) / 8 * 8;
    T.blocks(&st, message[0..keep]);
    var out: [8]u8 = undefined;
    T.final(&st, message[keep..], &out);
    return out;
}

const test_key: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

test "the paper's example and the first reference vectors" {
    // Appendix A of the SipHash paper: 15-byte message 00..0e, key 00..0f, result a129ca6149be45e5.
    const m15: [15]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
    try testing.expectEqual(@as(u64, 0xa129ca6149be45e5), std.mem.readInt(u64, &run(SipHash24, &test_key, &m15), .little));
    try testing.expectEqualSlices(u8, &.{ 0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72 }, &run(SipHash24, &test_key, ""));
    try testing.expectEqualSlices(u8, &.{ 0xdc, 0xc4, 0x0f, 0x05, 0x58, 0x01, 0xac, 0xab }, &run(SipHash13, &test_key, ""));
}

test "agrees with std.crypto.auth.siphash at every length and split" {
    var msg: [200]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 29 +% 3);
    var key: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @truncate(i *% 77 +% 1);
    for (0..msg.len + 1) |len| {
        var want24: [8]u8 = undefined;
        std.crypto.auth.siphash.SipHash64(2, 4).create(&want24, msg[0..len], &key);
        try testing.expectEqualSlices(u8, &want24, &run(SipHash24, &key, msg[0..len]));
        var want13: [8]u8 = undefined;
        std.crypto.auth.siphash.SipHash64(1, 3).create(&want13, msg[0..len], &key);
        try testing.expectEqualSlices(u8, &want13, &run(SipHash13, &key, msg[0..len]));
        // In two calls of `blocks`.
        var st: State = undefined;
        SipHash24.init(&st, &key);
        const whole = if (len == 0) 0 else (len - 1) / 8 * 8;
        const cut = whole / 16 * 8;
        SipHash24.blocks(&st, msg[0..cut]);
        SipHash24.blocks(&st, msg[cut..whole]);
        var out: [8]u8 = undefined;
        SipHash24.final(&st, msg[whole..len], &out);
        try testing.expectEqualSlices(u8, &want24, &out);
    }
}

test "final does not change the state" {
    var st: State = undefined;
    SipHash24.init(&st, &test_key);
    SipHash24.blocks(&st, "12345678");
    const before = st;
    var out: [8]u8 = undefined;
    SipHash13.final(&st, "abc", &out);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
