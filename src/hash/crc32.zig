//! CRC-32 checksums: the IEEE 802.3 polynomial used by zlib, gzip, PNG and Ethernet
//! (`Crc32`, check value `cbf43926` for "123456789"), and the Castagnoli polynomial used by
//! iSCSI, ext4 and Btrfs (`Crc32c`, check value `e3069283`).
//!
//! These are new algorithms (crypto-api 0.8.5 has no checksums), and they are not
//! cryptographic hashes: they detect accidental changes only. The state JS keeps between
//! calls is the byte counter and the running register; buffering stays in the JS hasher and
//! wasm runs `blocks` and `final`, like for the other hashers that have no original. `final`
//! does not modify the state. The digest is the four bytes of the checksum, most
//! significant first, so its hex form is the number everyone prints.

const std = @import("std");

/// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320).
pub const Crc32 = Impl(0xEDB88320);
/// CRC-32C (Castagnoli, reflected polynomial 0x82F63B78).
pub const Crc32c = Impl(0x82F63B78);

fn table(comptime poly: u32) [256]u32 {
    @setEvalBranchQuota(10_000);
    var t: [256]u32 = undefined;
    for (&t, 0..) |*e, i| {
        var c: u32 = @intCast(i);
        for (0..8) |_| c = if (c & 1 == 1) (c >> 1) ^ poly else c >> 1;
        e.* = c;
    }
    return t;
}

fn Impl(comptime poly: u32) type {
    const t = comptime table(poly);
    return struct {
        pub const block_len = 64;
        pub const digest_len = 4;

        /// Layout is part of the wasm ABI (packages/crypto-api/src/wasm/blocks.mjs writes
        /// these offsets); a change bumps `runtime.abi_version`.
        pub const State = extern struct {
            /// Bytes processed so far.
            t: u64 align(8),
            /// The running register: starts as 0xFFFFFFFF, the checksum is its complement.
            crc: u32,

            comptime {
                std.debug.assert(@sizeOf(State) == 16);
                std.debug.assert(@offsetOf(State, "crc") == 8);
            }
        };

        pub fn init(st: *State) void {
            st.t = 0;
            st.crc = 0xFFFFFFFF;
        }

        fn run(crc: u32, data: []const u8) u32 {
            var c = crc;
            for (data) |b| c = t[@as(u8, @truncate(c)) ^ b] ^ (c >> 8);
            return c;
        }

        /// Process whole blocks (`data.len % 64 == 0`), advancing `st.t`.
        pub fn blocks(st: *State, data: []const u8) void {
            std.debug.assert(data.len % block_len == 0);
            st.crc = run(st.crc, data);
            st.t += data.len;
        }

        /// Finish: `tail` (0..64 bytes) is the end of the message. Writes the checksum, most
        /// significant byte first; `st` is not modified.
        pub fn final(st: *const State, tail: []const u8, out: *[digest_len]u8) void {
            std.debug.assert(tail.len <= block_len);
            std.mem.writeInt(u32, out, ~run(st.crc, tail), .big);
        }
    };
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

fn check(comptime T: type, message: []const u8) u32 {
    var st: T.State = undefined;
    T.init(&st);
    const whole = message.len - message.len % T.block_len;
    // Hold back the last 1..64 bytes, like the JS hasher.
    const keep = if (whole == message.len and message.len > 0) message.len - T.block_len else whole;
    T.blocks(&st, message[0..keep]);
    var out: [4]u8 = undefined;
    T.final(&st, message[keep..], &out);
    return std.mem.readInt(u32, &out, .big);
}

test "check values and the RFC 3720 (iSCSI) CRC-32C vectors" {
    try testing.expectEqual(@as(u32, 0), check(Crc32, ""));
    try testing.expectEqual(@as(u32, 0xcbf43926), check(Crc32, "123456789"));
    try testing.expectEqual(@as(u32, 0xe3069283), check(Crc32c, "123456789"));
    try testing.expectEqual(@as(u32, 0), check(Crc32c, ""));
    var buf: [32]u8 = @splat(0);
    try testing.expectEqual(@as(u32, 0x8a9136aa), check(Crc32c, &buf));
    @memset(&buf, 0xff);
    try testing.expectEqual(@as(u32, 0x62a8ab43), check(Crc32c, &buf));
    for (&buf, 0..) |*b, i| b.* = @intCast(i);
    try testing.expectEqual(@as(u32, 0x46dd794e), check(Crc32c, &buf));
    for (&buf, 0..) |*b, i| b.* = @intCast(31 - i);
    try testing.expectEqual(@as(u32, 0x113fdb5c), check(Crc32c, &buf));
}

test "CRC-32 agrees with std.hash.Crc32 at every length" {
    var msg: [300]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for (0..msg.len + 1) |len| {
        try testing.expectEqual(std.hash.Crc32.hash(msg[0..len]), check(Crc32, msg[0..len]));
    }
}

test "final does not change the state" {
    var st: Crc32.State = undefined;
    Crc32.init(&st);
    const before = st;
    var out: [4]u8 = undefined;
    Crc32.final(&st, "abc", &out);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&st));
}
