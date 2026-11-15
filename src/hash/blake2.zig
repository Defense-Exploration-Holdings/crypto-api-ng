//! BLAKE2b and BLAKE2s (RFC 7693), sequential mode, with digest length, key,
//! salt and personalization.
//!
//! These are new algorithms (crypto-api 0.8.5 has no BLAKE), so there is no
//! original to stay compatible with. The state that JS keeps between calls is
//! just the chaining value and the byte counter: buffering, key-block
//! prefixing and the parameter block are handled by the JS hasher, and wasm
//! only compresses (`blocks`) and finishes (`final`).
//!
//! `blocks` never sets the final-block flag, so the caller must keep the last
//! block of the message (1..block_len bytes, or none for an empty message) for
//! `final`. `final` does not modify the state, so a hasher can be finalized
//! more than once.

const std = @import("std");

/// BLAKE2b: 64-bit words, 128-byte blocks, 12 rounds.
pub const Blake2b = Blake2(u64);
/// BLAKE2s: 32-bit words, 64-byte blocks, 10 rounds.
pub const Blake2s = Blake2(u32);

const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

fn Blake2(comptime Word: type) type {
    const is_b = Word == u64;
    const bits = @bitSizeOf(Word);
    const RotAmt = std.math.Log2Int(Word);
    // Rotation distances of G (RFC 7693 section 3.1).
    const r1: RotAmt = if (is_b) 32 else 16;
    const r2: RotAmt = if (is_b) 24 else 12;
    const r3: RotAmt = if (is_b) 16 else 8;
    const r4: RotAmt = if (is_b) 63 else 7;

    return struct {
        pub const word_len = bits / 8;
        pub const block_len = 16 * word_len;
        /// Longest digest (and key): 64 bytes for BLAKE2b, 32 for BLAKE2s.
        pub const digest_len = 8 * word_len;
        pub const key_len_max = digest_len;
        /// Salt and personalization are each two words long.
        pub const param_len = 2 * word_len;
        pub const rounds = if (is_b) 12 else 10;

        pub const iv: [8]Word = if (is_b) .{
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
        } else .{
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        };

        /// Layout is part of the wasm ABI (the JS hasher writes these offsets,
        /// see packages/crypto-api/src/hasher/blake2*.mjs); a change bumps
        /// `runtime.abi_version`. Words are little-endian in memory.
        pub const State = extern struct {
            /// The chaining value.
            h: [8]Word,
            /// Bytes compressed so far, including the key block. BLAKE2 has a
            /// 128-bit counter; messages are limited to 2^64 bytes here, far
            /// above what JS can hold.
            t: u64,

            comptime {
                std.debug.assert(@sizeOf(State) == 8 * word_len + 8);
                std.debug.assert(@offsetOf(State, "t") == 8 * word_len);
            }
        };

        /// Start a hash: the IV XORed with the parameter block of sequential
        /// mode (fanout 1, depth 1). `digest_bytes` is 1..digest_len,
        /// `key_bytes` 0..key_len_max. `salt` and `person` are zero padded to
        /// `param_len`. The key block itself is part of the message: the
        /// caller feeds it first.
        pub fn init(st: *State, digest_bytes: u32, key_bytes: u32, salt: []const u8, person: []const u8) void {
            std.debug.assert(digest_bytes >= 1 and digest_bytes <= digest_len);
            std.debug.assert(key_bytes <= key_len_max);
            std.debug.assert(salt.len <= param_len and person.len <= param_len);
            st.h = iv;
            st.t = 0;
            st.h[0] ^= @as(Word, digest_bytes) | (@as(Word, key_bytes) << 8) | (1 << 16) | (1 << 24);
            var s = @as([param_len]u8, @splat(0));
            var p = @as([param_len]u8, @splat(0));
            @memcpy(s[0..salt.len], salt);
            @memcpy(p[0..person.len], person);
            inline for (0..2) |i| {
                st.h[4 + i] ^= std.mem.readInt(Word, s[i * word_len ..][0..word_len], .little);
                st.h[6 + i] ^= std.mem.readInt(Word, p[i * word_len ..][0..word_len], .little);
            }
        }

        inline fn g(v: *[16]Word, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize, x: Word, y: Word) void {
            v[a] = v[a] +% v[b] +% x;
            v[d] = std.math.rotr(Word, v[d] ^ v[a], r1);
            v[c] = v[c] +% v[d];
            v[b] = std.math.rotr(Word, v[b] ^ v[c], r2);
            v[a] = v[a] +% v[b] +% y;
            v[d] = std.math.rotr(Word, v[d] ^ v[a], r3);
            v[c] = v[c] +% v[d];
            v[b] = std.math.rotr(Word, v[b] ^ v[c], r4);
        }

        /// The compression function F: `h` absorbs one block, `t` is the
        /// counter after this block, `last` is the final-block flag.
        pub fn compress(h: *[8]Word, block: *const [block_len]u8, t: u64, last: bool) void {
            var m: [16]Word = undefined;
            for (&m, 0..) |*w, i| w.* = std.mem.readInt(Word, block[i * word_len ..][0..word_len], .little);

            var v: [16]Word = undefined;
            v[0..8].* = h.*;
            v[8..16].* = iv;
            v[12] ^= @truncate(t);
            if (is_b) {
                // The high half of the 128-bit counter is zero (t is a u64).
            } else {
                v[13] ^= @truncate(t >> 32);
            }
            if (last) v[14] = ~v[14];

            inline for (0..rounds) |r| {
                const s = comptime sigma[r % 10];
                g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
            }
            for (h, 0..) |*w, i| w.* ^= v[i] ^ v[i + 8];
        }

        /// Compress whole blocks (`data.len % block_len == 0`), none of them
        /// final, advancing `st.t` by `block_len` each.
        pub fn blocks(st: *State, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            var i: usize = 0;
            while (i < data.len) : (i += block_len) {
                st.t += block_len;
                compress(&st.h, data[i..][0..block_len], st.t, false);
            }
        }

        /// Finish: `tail` (0..block_len bytes, zero padded here) is the last
        /// block. Writes the whole `digest_len` bytes of the output; the
        /// caller keeps the first `digest_bytes`. `st` is not modified.
        pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
            std.debug.assert(tail.len <= block_len);
            var block = @as([block_len]u8, @splat(0));
            @memcpy(block[0..tail.len], tail);
            var h = st.h;
            compress(&h, &block, st.t + tail.len, true);
            for (h, 0..) |w, i| std.mem.writeInt(Word, out[i * word_len ..][0..word_len], w, .little);
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

/// Whole-message BLAKE2 over this module's `blocks`/`final`, buffering like the
/// JS hasher does: the key block first, the last 1..block_len bytes held back.
fn oneShot(comptime B: type, message: []const u8, digest_bytes: usize, key: []const u8, salt: []const u8, person: []const u8, out: []u8) void {
    var st: B.State = undefined;
    B.init(&st, @intCast(digest_bytes), @intCast(key.len), salt, person);
    var buf: [B.block_len]u8 = @splat(0);
    var tail_len: usize = 0;
    var feed = struct {
        st: *B.State,
        buf: *[B.block_len]u8,
        n: *usize,
        fn add(self: *@This(), data: []const u8) void {
            // Stream `data` in, compressing a full buffer only when more input follows.
            var rest = data;
            while (rest.len > 0) {
                if (self.n.* == B.block_len) {
                    B.blocks(self.st, self.buf);
                    self.n.* = 0;
                }
                const take = @min(rest.len, B.block_len - self.n.*);
                @memcpy(self.buf[self.n.*..][0..take], rest[0..take]);
                self.n.* += take;
                rest = rest[take..];
            }
        }
    }{ .st = &st, .buf = &buf, .n = &tail_len };
    if (key.len > 0) {
        var kb: [B.block_len]u8 = @splat(0);
        @memcpy(kb[0..key.len], key);
        feed.add(&kb);
    }
    feed.add(message);
    var full: [B.digest_len]u8 = undefined;
    B.final(&st, buf[0..tail_len], &full);
    @memcpy(out, full[0..digest_bytes]);
}

test "BLAKE2b-512 of abc (RFC 7693 appendix A)" {
    var out: [64]u8 = undefined;
    oneShot(Blake2b, "abc", 64, "", "", "", &out);
    const want = hexTo(64, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    try testing.expectEqualSlices(u8, &want, &out);
}

test "BLAKE2s-256 of abc (RFC 7693 appendix B)" {
    var out: [32]u8 = undefined;
    oneShot(Blake2s, "abc", 32, "", "", "", &out);
    const want = hexTo(32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    try testing.expectEqualSlices(u8, &want, &out);
}

test "empty message" {
    var b: [64]u8 = undefined;
    oneShot(Blake2b, "", 64, "", "", "", &b);
    const want_b = hexTo(64, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    try testing.expectEqualSlices(u8, &want_b, &b);
    var s: [32]u8 = undefined;
    oneShot(Blake2s, "", 32, "", "", "", &s);
    const want_s = hexTo(32, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    try testing.expectEqualSlices(u8, &want_s, &s);
}

test "state layout" {
    try testing.expectEqual(@as(usize, 72), @sizeOf(Blake2b.State));
    try testing.expectEqual(@as(usize, 40), @sizeOf(Blake2s.State));
}

/// Deterministic test message.
fn fill(buf: []u8, seed: u8) void {
    var x: u32 = @as(u32, seed) *% 2654435761 +% 12345;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        b.* = @truncate(x >> 24);
    }
}

fn crossCheck(comptime B: type, comptime StdHash: fn (comptime usize) type, comptime bits: usize) !void {
    const Std = StdHash(bits);
    var msg: [3 * B.block_len + 7]u8 = undefined;
    fill(&msg, 7);
    var key: [B.key_len_max]u8 = undefined;
    fill(&key, 9);
    var salt: [B.param_len]u8 = undefined;
    fill(&salt, 11);
    var person: [B.param_len]u8 = undefined;
    fill(&person, 13);

    var len: usize = 0;
    while (len <= msg.len) : (len += 1) {
        var want: [Std.digest_length]u8 = undefined;
        Std.hash(msg[0..len], &want, .{});
        var got: [Std.digest_length]u8 = undefined;
        oneShot(B, msg[0..len], Std.digest_length, "", "", "", &got);
        try testing.expectEqualSlices(u8, &want, &got);

        // Keyed, with salt and personalization.
        for ([_]usize{ 1, 7, B.key_len_max / 2, B.key_len_max }) |k| {
            Std.hash(msg[0..len], &want, .{ .key = key[0..k], .salt = salt, .context = person });
            oneShot(B, msg[0..len], Std.digest_length, key[0..k], &salt, &person, &got);
            try testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

test "BLAKE2b matches std.crypto at every length, keyed and unkeyed" {
    try crossCheck(Blake2b, std.crypto.hash.blake2.Blake2b, 512);
    try crossCheck(Blake2b, std.crypto.hash.blake2.Blake2b, 256);
    try crossCheck(Blake2b, std.crypto.hash.blake2.Blake2b, 160);
}

test "BLAKE2s matches std.crypto at every length, keyed and unkeyed" {
    try crossCheck(Blake2s, std.crypto.hash.blake2.Blake2s, 256);
    try crossCheck(Blake2s, std.crypto.hash.blake2.Blake2s, 224);
    try crossCheck(Blake2s, std.crypto.hash.blake2.Blake2s, 128);
}

test "final does not modify the state and can be repeated" {
    var st: Blake2s.State = undefined;
    Blake2s.init(&st, 32, 0, "", "");
    const before = st;
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    Blake2s.final(&st, "abc", &a);
    Blake2s.final(&st, "abc", &b);
    try testing.expectEqualSlices(u8, &a, &b);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
