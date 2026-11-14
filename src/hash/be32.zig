//! Shared helpers for the 64-byte-block, big-endian-word hashers of crypto-api
//! (SHA-0, SHA-1, SHA-224/256, SM3).
//!
//! These reproduce the original library's quirks, not the standards' ideal
//! behavior: in particular the message length field is built from the JS
//! `state.length` with 32-bit shift operators (see `lengthField`).

const std = @import("std");

pub const block_size = 64;

/// Load a 64-byte block as sixteen big-endian words.
pub inline fn loadBlock(block: *const [block_size]u8) [16]u32 {
    var w: [16]u32 = undefined;
    inline for (0..16) |i| {
        w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
    }
    return w;
}

/// The 8 length bytes the original `Hasher32be.addLengthBits()` appends:
///
///     "\x00\x00\x00" + chr(len >> 29 & 0xff) + chr(len >> 21 & 0xff)
///                    + chr(len >> 13 & 0xff) + chr(len >> 5 & 0xff)
///                    + chr(len << 3 & 0xff)
///
/// JS applies `>>` and `<<` to ToInt32(len), i.e. the low 32 bits of the byte
/// count read as a signed integer, and `>>` sign-extends. So for byte counts of
/// 2^31 and above the field is wrong; this function is wrong in exactly the
/// same way (v1 keeps the bug, v2 fixes it). `len_lo` is the byte count modulo
/// 2^32 (JS `len >>> 0`), which is all the original ever looks at.
pub fn lengthField(len_lo: u32) [8]u8 {
    const l: i32 = @bitCast(len_lo);
    return .{
        0,
        0,
        0,
        @truncate(@as(u32, @bitCast(l >> 29))),
        @truncate(@as(u32, @bitCast(l >> 21))),
        @truncate(@as(u32, @bitCast(l >> 13))),
        @truncate(@as(u32, @bitCast(l >> 5))),
        @truncate(len_lo << 3),
    };
}

/// Padding done by the original `finalize()` of these hashers: ISO 7816-4
/// (`0x80`, then zeros) up to offset 56 (or 120 when the buffered tail is 56
/// bytes or more), then the length field. `tail` is the buffered, unprocessed
/// message, shorter than one block. Returns the 64 or 128 bytes that remain to
/// be compressed.
pub fn finalTail(tail: []const u8, len_lo: u32, out: *[2 * block_size]u8) []const u8 {
    std.debug.assert(tail.len < block_size);
    @memset(out, 0);
    @memcpy(out[0..tail.len], tail);
    out[tail.len] = 0x80;
    const total: usize = if (tail.len < 56) block_size else 2 * block_size;
    out[total - 8 ..][0..8].* = lengthField(len_lo);
    return out[0..total];
}

/// Streaming over any `S` with the fields `length: u64`, `buffered: u32` and
/// `buf: [64]u8`; `blocksFn(st, data)` compresses whole blocks into `st.hash`.
/// Same buffering as the original `update()`/`process()`.
pub fn update(comptime S: type, comptime blocksFn: fn (*S, []const u8) void, st: *S, data: []const u8) void {
    st.length +%= data.len;
    var rest = data;

    if (st.buffered != 0) {
        const room = block_size - st.buffered;
        const n = @min(room, rest.len);
        @memcpy(st.buf[st.buffered..][0..n], rest[0..n]);
        st.buffered += @intCast(n);
        rest = rest[n..];
        if (st.buffered < block_size) return;
        blocksFn(st, &st.buf);
        st.buffered = 0;
    }

    const whole = rest.len - rest.len % block_size;
    blocksFn(st, rest[0..whole]);
    rest = rest[whole..];

    @memcpy(st.buf[0..rest.len], rest);
    st.buffered = @intCast(rest.len);
}

/// Pad and compress the last block(s) of `st` exactly like the original
/// `finalize()`: afterwards the buffer is drained, the hash words are advanced
/// and `length` is untouched, so a second `finish` or an `update` after it
/// gives what crypto-api 0.8.5 gives.
pub fn finish(comptime S: type, comptime blocksFn: fn (*S, []const u8) void, st: *S) void {
    var buf: [2 * block_size]u8 = undefined;
    blocksFn(st, finalTail(st.buf[0..st.buffered], @truncate(st.length), &buf));
    st.buffered = 0;
    @memset(&st.buf, 0);
}

/// Write `hash` words big-endian into `out` (the original `getStateHash()`).
pub fn wordsToBytes(hash: []const u32, out: []u8) void {
    std.debug.assert(out.len >= hash.len * 4);
    for (hash, 0..) |word, i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .big);
    }
}

test "lengthField matches the standard below 2 GiB" {
    // 3 bytes = 24 bits.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 24 }, &lengthField(3));
    // 0x12345678 bytes = 0x91A2B3C0 bits.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0x00, 0x91, 0xA2, 0xB3, 0xC0 }, &lengthField(0x12345678));
}

test "lengthField keeps the 2 GiB sign-extension bug" {
    // 2^31 bytes: the standard field is 00 00 00 04 00 00 00 00, but the
    // original's arithmetic shift of a negative int32 gives 0xfc as the top byte.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0xfc, 0, 0, 0, 0 }, &lengthField(0x8000_0000));
    // Bits above 2^32 are dropped (JS ToInt32): same as length 0.
    try std.testing.expectEqualSlices(u8, &lengthField(0), &lengthField(@truncate(@as(u64, 1) << 32)));
}

test "finalTail switches to two blocks at 56 bytes" {
    var buf: [2 * block_size]u8 = undefined;
    const zeros: [63]u8 = @splat(0);
    try std.testing.expectEqual(@as(usize, 64), finalTail(zeros[0..55], 55, &buf).len);
    try std.testing.expectEqual(@as(usize, 128), finalTail(zeros[0..56], 56, &buf).len);
    try std.testing.expectEqual(@as(usize, 128), finalTail(zeros[0..63], 63, &buf).len);
    try std.testing.expectEqual(@as(usize, 64), finalTail("", 0, &buf).len);
}
