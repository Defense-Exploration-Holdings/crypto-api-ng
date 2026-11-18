//! The SHA-3 derived functions of NIST SP 800-185 on top of the Keccak sponge
//! in keccak.zig: cSHAKE, KMAC, TupleHash and ParallelHash (each with 128- and
//! 256-bit strength, and the XOF forms), plus TurboSHAKE (RFC 9861), the
//! 12-round sponge that KangarooTwelve is built from.
//!
//! The types follow the `std.crypto.hash` conventions of src/lib.zig, which
//! re-exports them: `init`, `update`, `final` (any output length, wipes the
//! state) and `squeeze` (more output: the XOF form). Copying a value forks it.
//!
//! Encodings (SP 800-185, section 2.3): `left_encode(x)` is the byte count of
//! `x` followed by `x` in big-endian bytes, `right_encode(x)` the same with the
//! count last; `encode_string(S)` is `left_encode(bit length of S) || S`;
//! `bytepad(X, w)` is `left_encode(w) || X`, zero-padded to a multiple of `w`.

const std = @import("std");
const keccak = @import("keccak.zig");

/// Domain suffix of cSHAKE with a function name or customization (bits 00).
pub const suffix_cshake: u8 = 0x04;

/// An encoded integer: at most 8 value bytes and the count.
pub const Encoded = struct {
    buf: [9]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Encoded) []const u8 {
        return self.buf[0..self.len];
    }
};

fn valueBytes(x: u64) usize {
    if (x == 0) return 1;
    return (64 - @clz(x) + 7) / 8;
}

/// `left_encode(x)`.
pub fn leftEncode(x: u64) Encoded {
    const n = valueBytes(x);
    var e: Encoded = .{ .len = n + 1 };
    e.buf[0] = @intCast(n);
    for (0..n) |i| e.buf[1 + i] = @truncate(x >> @intCast(8 * (n - 1 - i)));
    return e;
}

/// `right_encode(x)`.
pub fn rightEncode(x: u64) Encoded {
    const n = valueBytes(x);
    var e: Encoded = .{ .len = n + 1 };
    for (0..n) |i| e.buf[i] = @truncate(x >> @intCast(8 * (n - 1 - i)));
    e.buf[n] = @intCast(n);
    return e;
}

/// The bit length of `len` bytes, as SP 800-185 encodes it. Inputs of 2^61
/// bytes and more cannot be described and are not supported.
fn bits(len: usize) u64 {
    return @as(u64, len) * 8;
}

/// A sponge over keccak.zig with its own block buffer: `rate` bytes per block,
/// `nr` rounds of the permutation.
pub fn Sponge(comptime rate: u32, comptime nr: u32) type {
    comptime std.debug.assert(keccak.validRate(rate) and keccak.validRounds(nr));
    return struct {
        const Self = @This();
        pub const block_length = rate;

        st: keccak.State,
        buf: [rate]u8,
        n: usize,

        pub fn init() Self {
            var self: Self = undefined;
            keccak.init(&self.st, rate);
            self.n = 0;
            return self;
        }

        pub fn update(self: *Self, data: []const u8) void {
            var rest = data;
            if (self.n > 0) {
                const take = @min(rate - self.n, rest.len);
                @memcpy(self.buf[self.n..][0..take], rest[0..take]);
                self.n += take;
                rest = rest[take..];
                if (self.n < rate) return;
                keccak.blocksRounds(&self.st, &self.buf, nr);
                self.n = 0;
            }
            const whole = rest.len - rest.len % rate;
            keccak.blocksRounds(&self.st, rest[0..whole], nr);
            rest = rest[whole..];
            @memcpy(self.buf[0..rest.len], rest);
            self.n = rest.len;
        }

        /// Zero bytes up to the next block boundary (the end of `bytepad`).
        pub fn fillBlock(self: *Self) void {
            if (self.n == 0) return;
            @memset(self.buf[self.n..], 0);
            keccak.blocksRounds(&self.st, &self.buf, nr);
            self.n = 0;
        }

        /// Pad with `suffix`, permute and write the first `out.len` output bytes.
        pub fn final(self: *Self, suffix: u8, out: []u8) void {
            keccak.finalRounds(&self.st, self.buf[0..self.n], suffix, out, nr);
            std.crypto.secureZero(u8, &self.buf);
            self.n = 0;
        }

        /// More output after `final`.
        pub fn squeeze(self: *Self, out: []u8) void {
            keccak.squeezeRounds(&self.st, out, nr);
        }

        pub fn wipe(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }
    };
}

fn rateOf(comptime strength: u32) u32 {
    comptime std.debug.assert(strength == 128 or strength == 256);
    return 200 - strength / 4;
}

/// The state machine shared by the XOF types here: `final` or any number of
/// `squeeze` calls, never both.
const Phase = enum(u8) { absorbing, squeezing };

/// cSHAKE128 / cSHAKE256. With an empty function name and customization it is
/// SHAKE128 / SHAKE256.
pub fn CShake(comptime strength: u32) type {
    const rate = rateOf(strength);
    return struct {
        const Self = @This();
        pub const block_length = rate;
        /// The output length `finalResult` uses: twice the strength.
        pub const digest_length = 2 * strength / 8;
        pub const Options = struct {
            /// N: the function name, reserved for functions NIST defines on top of cSHAKE.
            function_name: []const u8 = "",
            /// S: the customization string.
            customization: []const u8 = "",
        };

        sponge: Sponge(rate, keccak.rounds),
        suffix: u8,
        phase: Phase,

        pub fn init(options: Options) Self {
            var self: Self = .{ .sponge = .init(), .suffix = keccak.suffix_shake, .phase = .absorbing };
            if (options.function_name.len == 0 and options.customization.len == 0) return self;
            self.suffix = suffix_cshake;
            self.sponge.update(leftEncode(rate).slice());
            self.encodeString(options.function_name);
            self.encodeString(options.customization);
            self.sponge.fillBlock();
            return self;
        }

        pub fn hash(data: []const u8, out: []u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        fn encodeString(self: *Self, s: []const u8) void {
            self.sponge.update(leftEncode(bits(s.len)).slice());
            self.sponge.update(s);
        }

        pub fn update(self: *Self, data: []const u8) void {
            std.debug.assert(self.phase == .absorbing);
            self.sponge.update(data);
        }

        /// Write `out.len` bytes of output and wipe the state.
        pub fn final(self: *Self, out: []u8) void {
            self.squeeze(out);
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }

        /// Write the next `out.len` bytes of output; may be called repeatedly.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (self.phase == .absorbing) {
                self.sponge.final(self.suffix, out);
                self.phase = .squeezing;
            } else {
                self.sponge.squeeze(out);
            }
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// KMAC128 / KMAC256: a MAC (and with `squeeze`, KMACXOF) over cSHAKE.
pub fn Kmac(comptime strength: u32) type {
    const C = CShake(strength);
    return struct {
        const Self = @This();
        pub const block_length = C.block_length;
        /// The recommended tag length: twice the strength.
        pub const mac_length = 2 * strength / 8;
        /// The recommended key length: the strength.
        pub const key_length = strength / 8;
        pub const key_length_min = 0;
        pub const Options = struct {
            /// S: the customization string.
            customization: []const u8 = "",
        };

        cshake: C,

        pub fn init(key: []const u8) Self {
            return initWithOptions(key, .{});
        }

        pub fn initWithOptions(key: []const u8, options: Options) Self {
            var self: Self = .{ .cshake = .init(.{ .function_name = "KMAC", .customization = options.customization }) };
            const sp = &self.cshake.sponge;
            sp.update(leftEncode(C.block_length).slice());
            sp.update(leftEncode(bits(key.len)).slice());
            sp.update(key);
            sp.fillBlock();
            return self;
        }

        /// The `out.len`-byte tag of `msg` under `key`.
        pub fn create(out: []u8, msg: []const u8, key: []const u8) void {
            createWithOptions(out, msg, key, .{});
        }

        pub fn createWithOptions(out: []u8, msg: []const u8, key: []const u8, options: Options) void {
            var ctx = initWithOptions(key, options);
            ctx.update(msg);
            ctx.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.cshake.update(data);
        }

        /// KMAC: the `out.len`-byte tag (the length is part of the input). Wipes the state.
        pub fn final(self: *Self, out: []u8) void {
            self.cshake.update(rightEncode(bits(out.len)).slice());
            self.cshake.final(out);
        }

        /// KMACXOF: the next `out.len` bytes of output; may be called repeatedly.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (self.cshake.phase == .absorbing) self.cshake.update(rightEncode(0).slice());
            self.cshake.squeeze(out);
        }

        pub fn finalResult(self: *Self) [mac_length]u8 {
            var out: [mac_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// TupleHash128 / TupleHash256: every `update` call is one element of the
/// tuple, so `update("ab")` differs from `update("a"); update("b")`.
pub fn TupleHash(comptime strength: u32) type {
    const C = CShake(strength);
    return struct {
        const Self = @This();
        pub const block_length = C.block_length;
        pub const digest_length = C.digest_length;
        pub const Options = struct {
            /// S: the customization string.
            customization: []const u8 = "",
        };

        cshake: C,

        pub fn init(options: Options) Self {
            return .{ .cshake = .init(.{ .function_name = "TupleHash", .customization = options.customization }) };
        }

        /// The hash of the tuple `elements`.
        pub fn hash(elements: []const []const u8, out: []u8, options: Options) void {
            var h = init(options);
            for (elements) |e| h.update(e);
            h.final(out);
        }

        /// Add one element to the tuple.
        pub fn update(self: *Self, element: []const u8) void {
            self.cshake.update(leftEncode(bits(element.len)).slice());
            self.cshake.update(element);
        }

        /// TupleHash: `out.len` bytes (the length is part of the input). Wipes the state.
        pub fn final(self: *Self, out: []u8) void {
            self.cshake.update(rightEncode(bits(out.len)).slice());
            self.cshake.final(out);
        }

        /// TupleHashXOF: the next `out.len` bytes of output; may be called repeatedly.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (self.cshake.phase == .absorbing) self.cshake.update(rightEncode(0).slice());
            self.cshake.squeeze(out);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// ParallelHash128 / ParallelHash256: the message is cut into blocks of
/// `block_size` bytes, each block is hashed with SHAKE, and the chaining
/// values are hashed with cSHAKE. The blocks are processed one after another
/// here; the result is the same as with a parallel implementation.
pub fn ParallelHash(comptime strength: u32) type {
    const C = CShake(strength);
    const cv_len = 2 * strength / 8;
    return struct {
        const Self = @This();
        pub const block_length = C.block_length;
        pub const digest_length = C.digest_length;
        /// The default block size B in bytes.
        pub const default_block_size = 8192;
        pub const Options = struct {
            /// B: the block size in bytes, at least 1.
            block_size: usize = default_block_size,
            /// S: the customization string.
            customization: []const u8 = "",
        };

        outer: C,
        inner: Sponge(C.block_length, keccak.rounds),
        block_size: usize,
        /// Bytes of the current block absorbed so far.
        filled: usize,
        /// Chaining values added to `outer`.
        count: u64,

        pub fn init(options: Options) Self {
            std.debug.assert(options.block_size >= 1);
            var self: Self = .{
                .outer = .init(.{ .function_name = "ParallelHash", .customization = options.customization }),
                .inner = .init(),
                .block_size = options.block_size,
                .filled = 0,
                .count = 0,
            };
            self.outer.update(leftEncode(options.block_size).slice());
            return self;
        }

        pub fn hash(data: []const u8, out: []u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            var rest = data;
            while (rest.len > 0) {
                const take = @min(self.block_size - self.filled, rest.len);
                self.inner.update(rest[0..take]);
                self.filled += take;
                rest = rest[take..];
                if (self.filled == self.block_size) self.endBlock();
            }
        }

        fn endBlock(self: *Self) void {
            var cv: [cv_len]u8 = undefined;
            self.inner.final(keccak.suffix_shake, &cv);
            self.outer.update(&cv);
            std.crypto.secureZero(u8, &cv);
            self.inner = .init();
            self.filled = 0;
            self.count += 1;
        }

        fn finish(self: *Self, out_bits: u64) void {
            if (self.filled > 0) self.endBlock();
            self.outer.update(rightEncode(self.count).slice());
            self.outer.update(rightEncode(out_bits).slice());
        }

        /// ParallelHash: `out.len` bytes (the length is part of the input). Wipes the state.
        pub fn final(self: *Self, out: []u8) void {
            self.finish(bits(out.len));
            self.outer.final(out);
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }

        /// ParallelHashXOF: the next `out.len` bytes of output; may be called repeatedly.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (self.outer.phase == .absorbing) self.finish(0);
            self.outer.squeeze(out);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// TurboSHAKE128 / TurboSHAKE256 (RFC 9861): SHAKE with 12 rounds and a
/// domain byte chosen by the caller.
pub fn TurboShake(comptime strength: u32) type {
    const rate = rateOf(strength);
    return struct {
        const Self = @This();
        pub const block_length = rate;
        pub const digest_length = 2 * strength / 8;
        pub const default_domain: u8 = 0x1f;
        pub const Options = struct {
            /// D: the domain separation byte, 0x01 to 0x7f.
            domain: u8 = default_domain,
        };

        sponge: Sponge(rate, keccak.turbo_rounds),
        domain: u8,
        phase: Phase,

        pub fn init(options: Options) Self {
            std.debug.assert(options.domain >= 0x01 and options.domain <= 0x7f);
            return .{ .sponge = .init(), .domain = options.domain, .phase = .absorbing };
        }

        pub fn hash(data: []const u8, out: []u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            std.debug.assert(self.phase == .absorbing);
            self.sponge.update(data);
        }

        /// Write `out.len` bytes of output and wipe the state.
        pub fn final(self: *Self, out: []u8) void {
            self.squeeze(out);
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }

        /// Write the next `out.len` bytes of output; may be called repeatedly.
        pub fn squeeze(self: *Self, out: []u8) void {
            if (self.phase == .absorbing) {
                self.sponge.final(self.domain, out);
                self.phase = .squeezing;
            } else {
                self.sponge.squeeze(out);
            }
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const sha3 = std.crypto.hash.sha3;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn range(comptime n: usize) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = @intCast(i);
    return out;
}

test "left_encode and right_encode (SP 800-185, 2.3.1)" {
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, leftEncode(0).slice());
    try testing.expectEqualSlices(u8, &.{ 0, 1 }, rightEncode(0).slice());
    try testing.expectEqualSlices(u8, &.{ 1, 168 }, leftEncode(168).slice());
    try testing.expectEqualSlices(u8, &.{ 2, 1, 0 }, leftEncode(256).slice());
    try testing.expectEqualSlices(u8, &.{ 1, 0, 2 }, rightEncode(256).slice());
    try testing.expectEqualSlices(u8, &.{ 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, leftEncode(std.math.maxInt(u64)).slice());
}

// NIST SP 800-185 samples (csrc.nist.gov, "cSHAKE_samples", "KMAC_samples",
// "TupleHash_samples", "ParallelHash_samples").
test "cSHAKE NIST samples" {
    var out: [64]u8 = undefined;
    const o: CShake(128).Options = .{ .customization = "Email Signature" };
    CShake(128).hash(&range(4), out[0..32], o);
    try testing.expectEqualSlices(u8, &hex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"), out[0..32]);
    CShake(128).hash(&range(200), out[0..32], o);
    try testing.expectEqualSlices(u8, &hex("c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b"), out[0..32]);
    CShake(256).hash(&range(4), &out, .{ .customization = "Email Signature" });
    try testing.expectEqualSlices(u8, &hex("d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c"), &out);
}

test "KMAC NIST samples" {
    const key = comptime range(96)[0x40..0x60];
    var out: [64]u8 = undefined;
    Kmac(128).create(out[0..32], &range(4), key);
    try testing.expectEqualSlices(u8, &hex("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e"), out[0..32]);
    Kmac(128).createWithOptions(out[0..32], &range(200), key, .{ .customization = "My Tagged Application" });
    try testing.expectEqualSlices(u8, &hex("1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230"), out[0..32]);
    Kmac(256).createWithOptions(&out, &range(4), key, .{ .customization = "My Tagged Application" });
    try testing.expectEqualSlices(u8, &hex("20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"), &out);

    var x = Kmac(128).init(key);
    x.update(&range(4));
    x.squeeze(out[0..10]);
    x.squeeze(out[10..32]);
    try testing.expectEqualSlices(u8, &hex("cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35"), out[0..32]);
}

test "TupleHash NIST samples" {
    const e1 = [_]u8{ 0, 1, 2 };
    const e2 = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
    const e3 = [_]u8{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    var out: [64]u8 = undefined;
    TupleHash(128).hash(&.{ &e1, &e2 }, out[0..32], .{});
    try testing.expectEqualSlices(u8, &hex("c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1"), out[0..32]);
    TupleHash(128).hash(&.{ &e1, &e2, &e3 }, out[0..32], .{ .customization = "My Tuple App" });
    try testing.expectEqualSlices(u8, &hex("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84"), out[0..32]);
}

test "ParallelHash NIST samples" {
    const x = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };
    var out: [64]u8 = undefined;
    ParallelHash(128).hash(&x, out[0..32], .{ .block_size = 8 });
    try testing.expectEqualSlices(u8, &hex("ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5"), out[0..32]);
    ParallelHash(128).hash(&x, out[0..32], .{ .block_size = 8, .customization = "Parallel Data" });
    try testing.expectEqualSlices(u8, &hex("fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206"), out[0..32]);
    ParallelHash(256).hash(&x, &out, .{ .block_size = 8 });
    try testing.expectEqualSlices(u8, &hex("bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429"), &out);
    var h = ParallelHash(256).init(.{ .block_size = 8, .customization = "Parallel Data" });
    for (x) |b| h.update(&.{b});
    h.squeeze(&out);
    try testing.expectEqualSlices(u8, &hex("538e105f1a22f44ed2f5cc1674fbd40be803d9c99bf5f8d90a2c8193f3fe6ea768e5c1a20987e2c9c65febed03887a51d35624ed12377594b5585541dc377efc"), &out);
}

test "TurboSHAKE RFC 9861 vectors" {
    var out: [64]u8 = undefined;
    TurboShake(128).hash("", out[0..32], .{});
    try testing.expectEqualSlices(u8, &hex("1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c"), out[0..32]);
    TurboShake(128).hash(&.{ 0xff, 0xff, 0xff }, out[0..32], .{ .domain = 0x01 });
    try testing.expectEqualSlices(u8, &hex("bf323f940494e88ee1c540fe660be8a0c93f43d15ec006998462fa994eed5dab"), out[0..32]);
}

/// Runs the same random message through ours and std's, in random pieces.
fn expectSameStream(comptime Ours: type, ours_init: anytype, comptime Std: type, std_init: anytype, comptime xof: bool) !void {
    var prng = std.Random.DefaultPrng.init(0x800185);
    const rnd = prng.random();
    var data: [1200]u8 = undefined;
    rnd.bytes(&data);
    for (0..120) |iter| {
        const len = if (iter < 40) iter else rnd.intRangeAtMost(usize, 0, data.len);
        const out_len = rnd.intRangeAtMost(usize, 1, 500);
        var a = ours_init();
        var b = std_init();
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, len - pos);
            a.update(data[pos..][0..n]);
            b.update(data[pos..][0..n]);
            pos += n;
        }
        var want: [500]u8 = undefined;
        var got: [500]u8 = undefined;
        if (xof) {
            a.squeeze(got[0 .. out_len / 2]);
            a.squeeze(got[out_len / 2 .. out_len]);
            b.squeeze(want[0..out_len]);
        } else {
            a.final(got[0..out_len]);
            b.final(want[0..out_len]);
        }
        try testing.expectEqualSlices(u8, want[0..out_len], got[0..out_len]);
    }
    _ = Ours;
    _ = Std;
}

test "cSHAKE, KMAC, TupleHash and TurboSHAKE match std.crypto" {
    const key = "key material that is longer than nothing";
    const S = "customization";
    inline for (.{ 128, 256 }) |strength| {
        const StdC = if (strength == 128) sha3.CShake128 else sha3.CShake256;
        const StdK = if (strength == 128) sha3.KMac128 else sha3.KMac256;
        const StdT = if (strength == 128) sha3.TupleHash128 else sha3.TupleHash256;
        const StdTurbo = if (strength == 128) sha3.TurboShake128(0x1f) else sha3.TurboShake256(0x1f);
        const StdTurbo6 = if (strength == 128) sha3.TurboShake128(0x06) else sha3.TurboShake256(0x06);
        try expectSameStream(CShake(strength), struct {
            fn f() CShake(strength) {
                return .init(.{ .customization = S });
            }
        }.f, StdC, struct {
            fn f() StdC {
                return .init(.{ .context = S });
            }
        }.f, true);
        try expectSameStream(CShake(strength), struct {
            fn f() CShake(strength) {
                return .init(.{});
            }
        }.f, StdC, struct {
            fn f() StdC {
                return .init(.{});
            }
        }.f, true);
        inline for (.{ false, true }) |xof| {
            try expectSameStream(Kmac(strength), struct {
                fn f() Kmac(strength) {
                    return .initWithOptions(key, .{ .customization = S });
                }
            }.f, StdK, struct {
                fn f() StdK {
                    return .initWithOptions(key, .{ .context = S });
                }
            }.f, xof);
            try expectSameStream(TupleHash(strength), struct {
                fn f() TupleHash(strength) {
                    return .init(.{ .customization = S });
                }
            }.f, StdT, struct {
                fn f() StdT {
                    return .initWithOptions(.{ .context = S });
                }
            }.f, xof);
        }
        try expectSameStream(TurboShake(strength), struct {
            fn f() TurboShake(strength) {
                return .init(.{});
            }
        }.f, StdTurbo, struct {
            fn f() StdTurbo {
                return .init(.{});
            }
        }.f, true);
        try expectSameStream(TurboShake(strength), struct {
            fn f() TurboShake(strength) {
                return .init(.{ .domain = 0x06 });
            }
        }.f, StdTurbo6, struct {
            fn f() StdTurbo6 {
                return .init(.{});
            }
        }.f, true);
    }
}

test "ParallelHash: any split of the input and any block size gives the one-shot result" {
    var prng = std.Random.DefaultPrng.init(0x9a11);
    const rnd = prng.random();
    var data: [700]u8 = undefined;
    rnd.bytes(&data);
    for (0..60) |_| {
        const len = rnd.intRangeAtMost(usize, 0, data.len);
        const b = rnd.intRangeAtMost(usize, 1, 300);
        var want: [40]u8 = undefined;
        ParallelHash(128).hash(data[0..len], &want, .{ .block_size = b });
        var h = ParallelHash(128).init(.{ .block_size = b });
        var pos: usize = 0;
        while (pos < len) {
            const n = rnd.intRangeAtMost(usize, 0, len - pos);
            h.update(data[pos..][0..n]);
            pos += n;
        }
        var got: [40]u8 = undefined;
        h.final(&got);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "ParallelHash follows the definition: cSHAKE over the SHAKE chaining values" {
    const data = range(53);
    const b = 10;
    var want: [32]u8 = undefined;
    var z = CShake(128).init(.{ .function_name = "ParallelHash" });
    z.update(leftEncode(b).slice());
    var i: usize = 0;
    var n: u64 = 0;
    while (i < data.len) : (i += b) {
        var cv: [32]u8 = undefined;
        sha3.Shake128.hash(data[i..@min(i + b, data.len)], &cv, .{});
        z.update(&cv);
        n += 1;
    }
    z.update(rightEncode(n).slice());
    z.update(rightEncode(256).slice());
    z.final(&want);
    var got: [32]u8 = undefined;
    ParallelHash(128).hash(&data, &got, .{ .block_size = b });
    try testing.expectEqualSlices(u8, &want, &got);
}
