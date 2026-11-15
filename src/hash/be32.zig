//! Shared helpers for the 64-byte-block, big-endian-word hashers of crypto-api
//! (SHA-0, SHA-1, SHA-224/256, SM3).
//!
//! The message length field is the standard 64-bit big-endian bit count
//! (see `lengthField`); crypto-api 0.8.5 and v1 built it with 32-bit shifts.

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

/// The 8 length bytes `Hasher32be.addLengthBits()` appends: the message length
/// in bits as a 64-bit big-endian integer. `length` is the byte count, which a
/// JS Number holds exactly below 2^53, so the multiplication cannot overflow.
/// (crypto-api 0.8.5 and v1 used 32-bit signed shifts here, which corrupted the
/// field for messages of 2 GiB or more.)
pub fn lengthField(length: u64) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, length *% 8, .big);
    return out;
}

/// Padding done by the original `finalize()` of these hashers: ISO 7816-4
/// (`0x80`, then zeros) up to offset 56 (or 120 when the buffered tail is 56
/// bytes or more), then the length field. `tail` is the buffered, unprocessed
/// message, shorter than one block. Returns the 64 or 128 bytes that remain to
/// be compressed.
pub fn finalTail(tail: []const u8, length: u64, out: *[2 * block_size]u8) []const u8 {
    std.debug.assert(tail.len < block_size);
    @memset(out, 0);
    @memcpy(out[0..tail.len], tail);
    out[tail.len] = 0x80;
    const total: usize = if (tail.len < 56) block_size else 2 * block_size;
    out[total - 8 ..][0..8].* = lengthField(length);
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
    blocksFn(st, finalTail(st.buf[0..st.buffered], st.length, &buf));
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

test "lengthField is the 64-bit bit count at and above 2 GiB" {
    // 2^31 bytes = 2^34 bits.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0x04, 0, 0, 0, 0 }, &lengthField(0x8000_0000));
    // 2^32 + 7 bytes: the high bits are kept.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0x08, 0, 0, 0, 0x38 }, &lengthField((1 << 32) + 7));
    // 2^53 - 1 bytes, the largest exact JS length.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8 }, &lengthField((1 << 53) - 1));
}

test "finalTail switches to two blocks at 56 bytes" {
    var buf: [2 * block_size]u8 = undefined;
    const zeros: [63]u8 = @splat(0);
    try std.testing.expectEqual(@as(usize, 64), finalTail(zeros[0..55], 55, &buf).len);
    try std.testing.expectEqual(@as(usize, 128), finalTail(zeros[0..56], 56, &buf).len);
    try std.testing.expectEqual(@as(usize, 128), finalTail(zeros[0..63], 63, &buf).len);
    try std.testing.expectEqual(@as(usize, 64), finalTail("", 0, &buf).len);
}
