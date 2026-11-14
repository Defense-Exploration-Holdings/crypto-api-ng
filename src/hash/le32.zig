//! Shared scaffolding for the 32-bit little-endian, 64-byte-block hashers of
//! crypto-api 0.8.5 that extend `Hasher32le` (MD4, HAS-160, RIPEMD-128/160/256/320).
//! MD5 predates this file and keeps its own copy of the same logic.
//!
//! What lives here is exactly what those classes share in the original:
//!
//!   * `finalize()`: ISO 7816 padding (0x80, zeros) up to 56 mod 64, then the
//!     8 length bytes of `Hasher32le.addLengthBits`, then the block(s).
//!   * `addLengthBits`' 32-bit quirk, see `lengthField`.
//!   * the state left behind after `finalize()` (buffer drained, hash words
//!     advanced, `length` untouched).
//!
//! An algorithm file supplies its IV and a compression function and gets a
//! `State`, `init`, `update`, `blocks` and `final` back from `Hasher(...)`.
//!
//! `State` layout (a wasm ABI contract with the JS facades; the facades compute
//! the same offsets in `packages/crypto-api/src/wasm/le32.mjs`):
//!
//!     hash: [words]u32          at 0
//!     length: u64               at align8(4 * words)
//!     buffered: u32             at length + 8
//!     param: u32                at length + 12   (HAS-160: `rounds`; unused elsewhere)
//!     buf: [64]u8               at length + 16

const std = @import("std");

pub const block_len = 64;

/// The 8 length bytes the original appends after the padding, derived from
/// `length` exactly like `Hasher32le.addLengthBits`:
///
///     (len << 3) & 0xff, (len >> 5) & 0xff, (len >> 13) & 0xff,
///     (len >> 21) & 0xff, (len >> 29) & 0xff, 0, 0, 0
///
/// where `len` is the JS Number converted with ToInt32 and `>>` is an
/// arithmetic shift. For lengths below 2^31 this equals the 64-bit
/// little-endian bit count. From 2^31 up the sign extension corrupts byte 4
/// and the high bits are lost. Kept in v1, fixed in v2.
pub fn lengthField(length: u64) [8]u8 {
    const len: i32 = @bitCast(@as(u32, @truncate(length)));
    const shl: i32 = len << 3;
    return .{
        @truncate(@as(u32, @bitCast(shl))),
        @truncate(@as(u32, @bitCast(len >> 5))),
        @truncate(@as(u32, @bitCast(len >> 13))),
        @truncate(@as(u32, @bitCast(len >> 21))),
        @truncate(@as(u32, @bitCast(len >> 29))),
        0,
        0,
        0,
    };
}

/// `compress(hash, block, param)` folds one 64-byte block into the hash words.
pub fn Hasher(
    comptime words: usize,
    comptime iv: [words]u32,
    comptime compress: fn (hash: *[words]u32, block: *const [block_len]u8, param: u32) void,
) type {
    return struct {
        pub const digest_len = words * 4;

        pub const State = extern struct {
            hash: [words]u32,
            /// Total bytes passed to `update`. The original keeps a JS Number
            /// (exact below 2^53); only the low 32 bits ever matter, see `lengthField`.
            length: u64,
            /// Bytes currently buffered in `buf` (0..63).
            buffered: u32,
            /// Algorithm parameter: HAS-160 `rounds`. Unused (0) elsewhere.
            param: u32,
            buf: [block_len]u8,

            pub const length_off = (4 * words + 7) & ~@as(usize, 7);

            comptime {
                std.debug.assert(@offsetOf(State, "hash") == 0);
                std.debug.assert(@offsetOf(State, "length") == length_off);
                std.debug.assert(@offsetOf(State, "buffered") == length_off + 8);
                std.debug.assert(@offsetOf(State, "param") == length_off + 12);
                std.debug.assert(@offsetOf(State, "buf") == length_off + 16);
                std.debug.assert(@sizeOf(State) == length_off + 16 + block_len);
                std.debug.assert(@sizeOf(State) <= 128); // fits the scratch state area
            }
        };

        pub fn init(st: *State, param: u32) void {
            st.* = .{
                .hash = iv,
                .length = 0,
                .buffered = 0,
                .param = param,
                .buf = @splat(0),
            };
        }

        /// Absorb `data`. Equivalent to the original `update()` for a binary
        /// string whose code units are all <= 0xFF.
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
                compress(&st.hash, &st.buf, st.param);
                st.buffered = 0;
            }

            const whole = rest.len - rest.len % block_len;
            blocks(st, rest[0..whole]);
            rest = rest[whole..];

            @memcpy(st.buf[0..rest.len], rest);
            st.buffered = @intCast(rest.len);
        }

        /// Process whole 64-byte blocks only, touching nothing but `st.hash`
        /// (and reading `st.param`). This is what the JS facades call: they keep
        /// the original state object and only borrow the compression function.
        pub fn blocks(st: *State, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            var rest = data;
            while (rest.len >= block_len) : (rest = rest[block_len..]) {
                compress(&st.hash, rest[0..block_len], st.param);
            }
        }

        /// Pad, process the final block(s) and write the digest. Mutates `st`
        /// the way the original `finalize()` mutates `this.state`.
        pub fn final(st: *State, out: *[digest_len]u8) void {
            const n = st.buffered;
            // Original: ISO7816 padding of (56 - n) bytes if n < 56, else
            // (120 - n), i.e. 0x80 then zeros up to 56 mod 64, then 8 length bytes.
            var tail: [2 * block_len]u8 = @splat(0);
            @memcpy(tail[0..n], st.buf[0..n]);
            tail[n] = 0x80;
            const total: usize = if (n < 56) block_len else 2 * block_len;
            @memcpy(tail[total - 8 ..][0..8], &lengthField(st.length));

            compress(&st.hash, tail[0..block_len], st.param);
            if (total == 2 * block_len) compress(&st.hash, tail[block_len..][0..block_len], st.param);

            st.buffered = 0;
            @memset(&st.buf, 0);

            for (st.hash, 0..) |w, i| {
                std.mem.writeInt(u32, out[i * 4 ..][0..4], w, .little);
            }
        }
    };
}

/// The 16 little-endian message words of a block (what `Hasher32le.process` builds).
pub inline fn loadWords(block: *const [block_len]u8) [16]u32 {
    var m: [16]u32 = undefined;
    for (&m, 0..) |*w, i| w.* = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
    return m;
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

test "length field matches the original addLengthBits (values from crypto-api 0.8.5)" {
    const cases = [_]struct { len: u64, bytes: [8]u8 }{
        .{ .len = 0, .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 1, .bytes = .{ 8, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 55, .bytes = .{ 184, 1, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 64, .bytes = .{ 0, 2, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 1 << 29, .bytes = .{ 0, 0, 0, 0, 1, 0, 0, 0 } },
        .{ .len = (1 << 31) - 1, .bytes = .{ 248, 255, 255, 255, 3, 0, 0, 0 } },
        .{ .len = 1 << 31, .bytes = .{ 0, 0, 0, 0, 252, 0, 0, 0 } },
        .{ .len = (1 << 31) + 5, .bytes = .{ 40, 0, 0, 0, 252, 0, 0, 0 } },
        .{ .len = (1 << 32) - 1, .bytes = .{ 248, 255, 255, 255, 255, 0, 0, 0 } },
        .{ .len = 1 << 32, .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .len = (1 << 32) + 7, .bytes = .{ 56, 0, 0, 0, 0, 0, 0, 0 } },
        .{ .len = 3 * (1 << 31) + 9, .bytes = .{ 72, 0, 0, 0, 252, 0, 0, 0 } },
        .{ .len = (1 << 40) + 3, .bytes = .{ 24, 0, 0, 0, 0, 0, 0, 0 } },
    };
    for (cases) |c| try testing.expectEqualSlices(u8, &c.bytes, &lengthField(c.len));
}

test "length field equals the 64-bit bit count below 2^31" {
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    for (0..1000) |_| {
        const len = rnd.intRangeLessThan(u64, 0, 1 << 31);
        var want: [8]u8 = undefined;
        std.mem.writeInt(u64, &want, len * 8, .little);
        try testing.expectEqualSlices(u8, &want, &lengthField(len));
    }
}
