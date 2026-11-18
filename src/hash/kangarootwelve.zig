//! KangarooTwelve: KT128 and KT256 (RFC 9861), a tree hash over TurboSHAKE
//! (sp800_185.zig), computed here one chunk after another.
//!
//! The input string is `S = M || C || length_encode(|C|)` for message `M` and
//! customization `C`. Up to 8192 bytes, the output is TurboSHAKE(S, 0x07).
//! Longer, `S` is cut into 8192-byte chunks; every chunk but the first is
//! hashed to a chaining value with TurboSHAKE(chunk, 0x0B) (32 bytes for KT128,
//! 64 for KT256), and the output is TurboSHAKE over
//! `S_0 || 03 00 00 00 00 00 00 00 || CV_1 .. CV_n-1 || length_encode(n - 1) || FF FF`
//! with domain byte 0x06.
//!
//! `length_encode(x)` (RFC 9861, 3.3) is `x` in big-endian bytes without leading
//! zeros, followed by the number of those bytes; `length_encode(0)` is `00`.

const std = @import("std");
const sp = @import("sp800_185.zig");

pub const chunk_size = 8192;

/// Domain bytes of the three node kinds.
pub const domain_single: u8 = 0x07;
pub const domain_final: u8 = 0x06;
pub const domain_leaf: u8 = 0x0b;

/// `length_encode(x)`.
pub fn lengthEncode(x: u64) sp.Encoded {
    var n: usize = 0;
    var v = x;
    while (v != 0) : (v >>= 8) n += 1;
    var e: sp.Encoded = .{ .len = n + 1 };
    for (0..n) |i| e.buf[i] = @truncate(x >> @intCast(8 * (n - 1 - i)));
    e.buf[n] = @intCast(n);
    return e;
}

/// KT128 (`strength` 128) or KT256 (256).
pub fn KangarooTwelve(comptime strength: u32) type {
    const Turbo = sp.TurboShake(strength);
    const cv_len = 2 * strength / 8;
    return struct {
        const Self = @This();
        pub const block_length = Turbo.block_length;
        /// The output length `finalResult` uses: twice the strength.
        pub const digest_length = 2 * strength / 8;
        pub const Options = struct {
            /// C: the customization string.
            customization: []const u8 = "",
        };

        /// The final node: the first chunk, then the chaining values.
        final_node: Turbo,
        /// The chunk being hashed into a chaining value.
        leaf: Turbo,
        /// Bytes of `S` taken so far.
        taken: u64,
        /// Chaining values added to the final node.
        leaves: u64,
        customization: []const u8,

        pub fn init(options: Options) Self {
            return .{
                .final_node = .init(.{ .domain = domain_single }),
                .leaf = .init(.{ .domain = domain_leaf }),
                .taken = 0,
                .leaves = 0,
                .customization = options.customization,
            };
        }

        pub fn hash(data: []const u8, out: []u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        fn take(self: *Self, data: []const u8) void {
            var rest = data;
            while (rest.len > 0) {
                if (self.taken < chunk_size) {
                    const n: usize = @intCast(@min(chunk_size - self.taken, rest.len));
                    self.final_node.update(rest[0..n]);
                    self.taken += n;
                    rest = rest[n..];
                    continue;
                }
                const in_leaf = (self.taken - chunk_size) % chunk_size;
                if (self.taken == chunk_size) {
                    // More than one chunk: the final node gets the marker after S_0.
                    self.final_node.update(&.{ 3, 0, 0, 0, 0, 0, 0, 0 });
                } else if (in_leaf == 0) {
                    self.endLeaf();
                }
                const n: usize = @intCast(@min(chunk_size - in_leaf, rest.len));
                self.leaf.update(rest[0..n]);
                self.taken += n;
                rest = rest[n..];
            }
        }

        fn endLeaf(self: *Self) void {
            var cv: [cv_len]u8 = undefined;
            self.leaf.final(&cv);
            self.final_node.update(&cv);
            std.crypto.secureZero(u8, &cv);
            self.leaf = .init(.{ .domain = domain_leaf });
            self.leaves += 1;
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.take(data);
        }

        fn finish(self: *Self) void {
            self.take(self.customization);
            self.take(lengthEncode(self.customization.len).slice());
            if (self.taken > chunk_size) {
                self.endLeaf();
                self.final_node.update(lengthEncode(self.leaves).slice());
                self.final_node.update(&.{ 0xff, 0xff });
                self.final_node.domain = domain_final;
            }
        }

        /// Write `out.len` bytes of output and wipe the state.
        pub fn final(self: *Self, out: []u8) void {
            self.squeeze(out);
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }

        /// Write the next `out.len` bytes of output; may be called repeatedly.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (self.final_node.phase == .absorbing) self.finish();
            self.final_node.squeeze(out);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

pub const KT128 = KangarooTwelve(128);
pub const KT256 = KangarooTwelve(256);

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// The RFC 9861 test pattern: 00 01 .. FA repeated.
fn pattern(buf: []u8) []u8 {
    for (buf, 0..) |*b, i| b.* = @intCast(i % 251);
    return buf;
}

test "length_encode (RFC 9861, 3.3)" {
    try testing.expectEqualSlices(u8, &.{0}, lengthEncode(0).slice());
    try testing.expectEqualSlices(u8, &.{ 12, 1 }, lengthEncode(12).slice());
    try testing.expectEqualSlices(u8, &.{ 1, 0, 2, 3 }, lengthEncode(65538).slice());
}

test "KT128 and KT256 RFC 9861 vectors" {
    var buf: [17 * 17 * 17]u8 = undefined;
    var out: [64]u8 = undefined;
    KT128.hash("", out[0..32], .{});
    try testing.expectEqualSlices(u8, &hex("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"), out[0..32]);
    KT128.hash(pattern(buf[0 .. 17 * 17 * 17]), out[0..32], .{});
    try testing.expectEqualSlices(u8, &hex("cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0"), out[0..32]);
    var c: [41]u8 = undefined;
    KT128.hash(&.{0xff}, out[0..32], .{ .customization = pattern(&c) });
    try testing.expectEqualSlices(u8, &hex("d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4"), out[0..32]);
    KT256.hash("", &out, .{});
    try testing.expectEqualSlices(u8, &hex("b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9"), &out);
}

test "KT128 and KT256 match std.crypto across chunk boundaries, in any split" {
    const allocator = testing.allocator;
    const data = try allocator.alloc(u8, 5 * chunk_size + 300);
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0x4b54);
    const rnd = prng.random();
    rnd.bytes(data);
    const lengths = [_]usize{ 0, 1, 8191 - 9, 8192 - 9, 8192 - 8, 8191, 8192, 8193, 2 * 8192, 2 * 8192 + 1, 3 * 8192 - 5, data.len };
    for (0..lengths.len + 20) |iter| {
        const len = if (iter < lengths.len) lengths[iter] else rnd.intRangeAtMost(usize, 0, data.len);
        const c_len = rnd.intRangeAtMost(usize, 0, 40);
        const custom = data[data.len - c_len ..];
        inline for (.{ .{ KT128, std.crypto.hash.sha3.KT128 }, .{ KT256, std.crypto.hash.sha3.KT256 } }) |pair| {
            var want: [100]u8 = undefined;
            try pair[1].hash(data[0..len], &want, .{ .customization = custom });
            var h = pair[0].init(.{ .customization = custom });
            var pos: usize = 0;
            while (pos < len) {
                const n = rnd.intRangeAtMost(usize, 0, @min(len - pos, 3 * chunk_size));
                h.update(data[pos..][0..n]);
                pos += n;
            }
            var got: [100]u8 = undefined;
            h.squeeze(got[0..33]);
            h.squeeze(got[33..]);
            try testing.expectEqualSlices(u8, &want, &got);
        }
    }
}
