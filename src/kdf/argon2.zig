//! Argon2d, Argon2i and Argon2id (RFC 9106), version 0x13, over the BLAKE2b
//! core of `src/hash/blake2.zig`.
//!
//! New in crypto-api-ng (0.8.5 has no password hashing). The core is
//! target-agnostic and allocation-free: the caller passes the memory matrix
//! (`blockCount` blocks of 1 KiB). Lanes are filled one after another on one
//! thread; the result does not depend on the order because a segment never
//! references a segment of another lane that is filled in the same slice.
//!
//! `hash` zeroes the whole matrix and every local copy before it returns.

const std = @import("std");
const Blake2b = @import("../hash/blake2.zig").Blake2b;

/// The Argon2 type `y` of RFC 9106 section 3.1.
pub const Mode = enum(u32) {
    argon2d = 0,
    argon2i = 1,
    argon2id = 2,
};

/// The only version implemented (RFC 9106 has no other).
pub const version: u32 = 0x13;
/// One block of the memory matrix: 1024 bytes as 128 little-endian words.
pub const Block = [128]u64;
pub const block_len = 1024;
pub const sync_points = 4;

pub const Params = struct {
    /// Passes over the memory (`t`), at least 1.
    t: u32,
    /// Memory size in KiB (`m`), at least 8 * p. It is rounded down to a
    /// multiple of 4 * p blocks.
    m: u32,
    /// Lanes (`p`), 1 to 2^24 - 1.
    p: u32,
    /// Optional key `K`.
    secret: []const u8 = "",
    /// Optional associated data `X`.
    ad: []const u8 = "",
};

pub const Error = error{ WeakParameters, OutputTooLong };

const max_u32 = std.math.maxInt(u32);

/// Check the parameters against the limits of RFC 9106 section 3.1. The salt
/// must be at least 8 bytes (the reference implementation's minimum; the RFC
/// recommends 16) and the tag at least 4.
pub fn check(out_len: usize, password_len: usize, salt_len: usize, params: Params) Error!void {
    if (out_len < 4) return error.WeakParameters;
    if (out_len > max_u32) return error.OutputTooLong;
    if (password_len > max_u32 or salt_len > max_u32) return error.WeakParameters;
    if (params.secret.len > max_u32 or params.ad.len > max_u32) return error.WeakParameters;
    if (salt_len < 8) return error.WeakParameters;
    if (params.t < 1 or params.p < 1 or params.p > 0xFF_FFFF) return error.WeakParameters;
    if (params.m / 8 < params.p) return error.WeakParameters;
}

/// Blocks in the memory matrix: `m` rounded down to a multiple of `4 * p`.
pub fn blockCount(params: Params) u64 {
    const q = 4 * @as(u64, params.p);
    return q * (params.m / q);
}

// ---- BLAKE2b plumbing ------------------------------------------------------

/// Incremental BLAKE2b over the core, holding back the last block for `final`.
const B2 = struct {
    st: Blake2b.State,
    buf: [Blake2b.block_len]u8,
    n: usize,

    fn init(digest_bytes: usize) B2 {
        var self: B2 = .{ .st = undefined, .buf = @splat(0), .n = 0 };
        Blake2b.init(&self.st, @intCast(digest_bytes), 0, "", "");
        return self;
    }

    fn update(self: *B2, data: []const u8) void {
        var rest = data;
        while (rest.len > 0) {
            if (self.n == Blake2b.block_len) {
                Blake2b.blocks(&self.st, &self.buf);
                self.n = 0;
            }
            const take = @min(rest.len, Blake2b.block_len - self.n);
            @memcpy(self.buf[self.n..][0..take], rest[0..take]);
            self.n += take;
            rest = rest[take..];
        }
    }

    fn final(self: *B2, out: *[Blake2b.digest_len]u8) void {
        Blake2b.final(&self.st, self.buf[0..self.n], out);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

fn le32(x: usize) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, @intCast(x), .little);
    return b;
}

/// The variable-length hash H' of RFC 9106 section 3.3 over the concatenation of `parts`.
fn hPrime(out: []u8, parts: []const []const u8) void {
    var v: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &v);
    var h = B2.init(@min(out.len, 64));
    h.update(&le32(out.len));
    for (parts) |part| h.update(part);
    h.final(&v);
    if (out.len <= 64) {
        @memcpy(out, v[0..out.len]);
        return;
    }
    const r = (out.len + 31) / 32 - 2;
    @memcpy(out[0..32], v[0..32]);
    var i: usize = 1;
    while (i < r) : (i += 1) {
        var g = B2.init(64);
        g.update(&v);
        g.final(&v);
        @memcpy(out[32 * i ..][0..32], v[0..32]);
    }
    const last = out.len - 32 * r;
    var g = B2.init(last);
    g.update(&v);
    g.final(&v);
    @memcpy(out[32 * r ..][0..last], v[0..last]);
}

// ---- the compression function G ----------------------------------------------

inline fn fBlaMka(x: u64, y: u64) u64 {
    const xy = @as(u64, @as(u32, @truncate(x))) * @as(u64, @as(u32, @truncate(y)));
    return x +% y +% (xy << 1);
}

inline fn gb(v: *[16]u64, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize) void {
    v[a] = fBlaMka(v[a], v[b]);
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 32);
    v[c] = fBlaMka(v[c], v[d]);
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 24);
    v[a] = fBlaMka(v[a], v[b]);
    v[d] = std.math.rotr(u64, v[d] ^ v[a], 16);
    v[c] = fBlaMka(v[c], v[d]);
    v[b] = std.math.rotr(u64, v[b] ^ v[c], 63);
}

/// The permutation P on row `i` (words 16i..16i+15) or, with `column`, on
/// column `i` (word pairs 2i, 2i+1 of every row).
fn mix(r: *Block, comptime column: bool, i: usize) void {
    var v: [16]u64 = undefined;
    for (0..16) |k| {
        const at = if (column) 16 * (k >> 1) + 2 * i + (k & 1) else 16 * i + k;
        v[k] = r[at];
    }
    gb(&v, 0, 4, 8, 12);
    gb(&v, 1, 5, 9, 13);
    gb(&v, 2, 6, 10, 14);
    gb(&v, 3, 7, 11, 15);
    gb(&v, 0, 5, 10, 15);
    gb(&v, 1, 6, 11, 12);
    gb(&v, 2, 7, 8, 13);
    gb(&v, 3, 4, 9, 14);
    for (0..16) |k| {
        const at = if (column) 16 * (k >> 1) + 2 * i + (k & 1) else 16 * i + k;
        r[at] = v[k];
    }
    std.crypto.secureZero(u64, &v);
}

/// next = G(prev, ref), XORed into the old `next` when `xor` (passes after the first).
fn fillBlock(prev: *const Block, ref: *const Block, next: *Block, xor: bool) void {
    var r: Block = undefined;
    var tmp: Block = undefined;
    for (&r, prev, ref) |*w, a, b| w.* = a ^ b;
    tmp = r;
    if (xor) {
        for (&tmp, next) |*w, n| w.* ^= n;
    }
    for (0..8) |i| mix(&r, false, i);
    for (0..8) |i| mix(&r, true, i);
    for (next, tmp, r) |*w, a, b| w.* = a ^ b;
    std.crypto.secureZero(u64, &r);
    std.crypto.secureZero(u64, &tmp);
}

fn loadBlock(b: *Block, bytes: *const [block_len]u8) void {
    for (b, 0..) |*w, i| w.* = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
}

fn storeBlock(bytes: *[block_len]u8, b: *const Block) void {
    for (b, 0..) |w, i| std.mem.writeInt(u64, bytes[8 * i ..][0..8], w, .little);
}

// ---- the memory matrix -------------------------------------------------------

const Position = struct { pass: u32, lane: u32, slice: u32 };

fn fillSegment(memory: []Block, params: Params, mode: Mode, pos: Position) void {
    const lanes: usize = params.p;
    const lane_len = memory.len / lanes;
    const seg_len = lane_len / sync_points;
    const independent = mode == .argon2i or (mode == .argon2id and pos.pass == 0 and pos.slice < 2);

    var input: Block = @splat(0);
    var address: Block = @splat(0);
    const zero: Block = @splat(0);
    defer std.crypto.secureZero(u64, &input);
    defer std.crypto.secureZero(u64, &address);
    if (independent) {
        input[0] = pos.pass;
        input[1] = pos.lane;
        input[2] = pos.slice;
        input[3] = memory.len;
        input[4] = params.t;
        input[5] = @backingInt(mode);
    }

    var start: usize = 0;
    if (pos.pass == 0 and pos.slice == 0) {
        start = 2;
        if (independent) nextAddresses(&address, &input, &zero);
    }

    var cur = @as(usize, pos.lane) * lane_len + @as(usize, pos.slice) * seg_len + start;
    var prev = if (cur % lane_len == 0) cur + lane_len - 1 else cur - 1;
    var i = start;
    while (i < seg_len) : ({
        i += 1;
        cur += 1;
        prev += 1;
    }) {
        if (cur % lane_len == 1) prev = cur - 1;
        var rand: u64 = undefined;
        if (independent) {
            if (i % 128 == 0) nextAddresses(&address, &input, &zero);
            rand = address[i % 128];
        } else {
            rand = memory[prev][0];
        }
        var ref_lane: usize = @intCast((rand >> 32) % lanes);
        if (pos.pass == 0 and pos.slice == 0) ref_lane = pos.lane;
        const same = ref_lane == pos.lane;

        // Reference area (RFC 9106 section 3.4.1.2).
        var area: u64 = undefined;
        if (pos.pass == 0) {
            if (pos.slice == 0) {
                area = i - 1;
            } else if (same) {
                area = @as(u64, pos.slice) * seg_len + i - 1;
            } else {
                area = @as(u64, pos.slice) * seg_len - @intFromBool(i == 0);
            }
        } else if (same) {
            area = lane_len - seg_len + i - 1;
        } else {
            area = lane_len - seg_len - @intFromBool(i == 0);
        }
        var rel: u64 = rand & 0xFFFF_FFFF;
        rel = (rel * rel) >> 32;
        rel = area - 1 - ((area * rel) >> 32);
        const start_pos: u64 = if (pos.pass != 0 and pos.slice != sync_points - 1) (@as(u64, pos.slice) + 1) * seg_len else 0;
        const ref_index: usize = @intCast((start_pos + rel) % lane_len);

        fillBlock(&memory[prev], &memory[ref_lane * lane_len + ref_index], &memory[cur], pos.pass != 0);
    }
}

fn nextAddresses(address: *Block, input: *Block, zero: *const Block) void {
    input[6] +%= 1;
    fillBlock(zero, input, address, false);
    fillBlock(zero, address, address, false);
}

/// Derive `out` (4 to 2^32 - 1 bytes) from `password` and `salt`. `memory`
/// must hold exactly `blockCount(params)` blocks; its contents on entry do not
/// matter and it is zeroed on return. The parameters must have passed `check`.
pub fn hash(out: []u8, password: []const u8, salt: []const u8, params: Params, mode: Mode, memory: []Block) void {
    std.debug.assert(memory.len == blockCount(params) and memory.len > 0);
    defer std.crypto.secureZero(u64, std.mem.bytesAsSlice(u64, std.mem.sliceAsBytes(memory)));
    const lanes: usize = params.p;
    const lane_len = memory.len / lanes;

    // H0 (RFC 9106 section 3.2), followed by the two words H' adds per block.
    var h0: [72]u8 = undefined;
    defer std.crypto.secureZero(u8, &h0);
    {
        var h = B2.init(64);
        h.update(&le32(params.p));
        h.update(&le32(out.len));
        h.update(&le32(params.m));
        h.update(&le32(params.t));
        h.update(&le32(version));
        h.update(&le32(@backingInt(mode)));
        h.update(&le32(password.len));
        h.update(password);
        h.update(&le32(salt.len));
        h.update(salt);
        h.update(&le32(params.secret.len));
        h.update(params.secret);
        h.update(&le32(params.ad.len));
        h.update(params.ad);
        h.final(h0[0..64]);
    }

    var bytes: [block_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    for (0..lanes) |lane| {
        h0[68..72].* = le32(lane);
        for (0..2) |j| {
            h0[64..68].* = le32(j);
            hPrime(&bytes, &.{&h0});
            loadBlock(&memory[lane * lane_len + j], &bytes);
        }
    }

    var pass: u32 = 0;
    while (pass < params.t) : (pass += 1) {
        var slice: u32 = 0;
        while (slice < sync_points) : (slice += 1) {
            var lane: u32 = 0;
            while (lane < params.p) : (lane += 1) {
                fillSegment(memory, params, mode, .{ .pass = pass, .lane = lane, .slice = slice });
            }
        }
    }

    var c: Block = memory[lane_len - 1];
    defer std.crypto.secureZero(u64, &c);
    for (1..lanes) |lane| {
        for (&c, memory[lane * lane_len + lane_len - 1]) |*w, x| w.* ^= x;
    }
    storeBlock(&bytes, &c);
    hPrime(out, &.{&bytes});
}

// ---- tests -----------------------------------------------------------------

const testing = std.testing;

fn derive(out: []u8, password: []const u8, salt: []const u8, params: Params, mode: Mode) !void {
    try check(out.len, password.len, salt.len, params);
    const memory = try testing.allocator.alloc(Block, @intCast(blockCount(params)));
    defer testing.allocator.free(memory);
    hash(out, password, salt, params, mode, memory);
    for (memory) |b| for (b) |w| try testing.expectEqual(@as(u64, 0), w);
}

fn expectHex(want: []const u8, got: []const u8) !void {
    var buf: [256]u8 = undefined;
    const w = try std.fmt.hexToBytes(&buf, want);
    try testing.expectEqualSlices(u8, w, got);
}

const rfc_password: [32]u8 = @splat(0x01);
const rfc_salt: [16]u8 = @splat(0x02);
const rfc_secret: [8]u8 = @splat(0x03);
const rfc_ad: [12]u8 = @splat(0x04);
const rfc_params: Params = .{ .t = 3, .m = 32, .p = 4, .secret = &rfc_secret, .ad = &rfc_ad };

test "RFC 9106 section 5.1: Argon2d" {
    var tag: [32]u8 = undefined;
    try derive(&tag, &rfc_password, &rfc_salt, rfc_params, .argon2d);
    try expectHex("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb", &tag);
}

test "RFC 9106 section 5.2: Argon2i" {
    var tag: [32]u8 = undefined;
    try derive(&tag, &rfc_password, &rfc_salt, rfc_params, .argon2i);
    try expectHex("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8", &tag);
}

test "RFC 9106 section 5.3: Argon2id" {
    var tag: [32]u8 = undefined;
    try derive(&tag, &rfc_password, &rfc_salt, rfc_params, .argon2id);
    try expectHex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", &tag);
}

test "parameter checks" {
    const ok: Params = .{ .t = 1, .m = 8, .p = 1 };
    try check(4, 0, 8, ok);
    try testing.expectError(error.WeakParameters, check(3, 0, 8, ok));
    try testing.expectError(error.WeakParameters, check(32, 0, 7, ok));
    try testing.expectError(error.WeakParameters, check(32, 0, 8, .{ .t = 0, .m = 8, .p = 1 }));
    try testing.expectError(error.WeakParameters, check(32, 0, 8, .{ .t = 1, .m = 15, .p = 2 }));
    try testing.expectError(error.WeakParameters, check(32, 0, 8, .{ .t = 1, .m = 1 << 30, .p = 1 << 24 }));
    try check(32, 0, 8, .{ .t = 1, .m = 16, .p = 2 });
    try testing.expectEqual(@as(u64, 16), blockCount(.{ .t = 1, .m = 19, .p = 2 }));
    try testing.expectEqual(@as(u64, 24), blockCount(.{ .t = 1, .m = 24, .p = 3 }));
}

test "H' matches BLAKE2b for short outputs and chains for long ones" {
    // T <= 64 is plain BLAKE2b-T of LE32(T) || input.
    var a: [40]u8 = undefined;
    hPrime(&a, &.{ "ab", "c" });
    var b: [40]u8 = undefined;
    std.crypto.hash.blake2.Blake2b(320).hash(&le32(40) ++ "abc", &b, .{});
    try testing.expectEqualSlices(u8, &b, &a);
    // T = 100: r = 2, W1 from V1, V2 from V1, last 100 - 64 = 36 bytes from V2.
    var long: [100]u8 = undefined;
    hPrime(&long, &.{"abc"});
    var v1: [64]u8 = undefined;
    std.crypto.hash.blake2.Blake2b512.hash(&le32(100) ++ "abc", &v1, .{});
    var v2: [64]u8 = undefined;
    std.crypto.hash.blake2.Blake2b512.hash(&v1, &v2, .{});
    var v3: [36]u8 = undefined;
    std.crypto.hash.blake2.Blake2b(288).hash(&v2, &v3, .{});
    try testing.expectEqualSlices(u8, v1[0..32], long[0..32]);
    try testing.expectEqualSlices(u8, v2[0..32], long[32..64]);
    try testing.expectEqualSlices(u8, &v3, long[64..100]);
}

test "vectors of the reference implementation (phc-winner-argon2 test.c, README)" {
    var tag: [32]u8 = undefined;
    try derive(&tag, "password", "somesalt", .{ .t = 2, .m = 65536, .p = 1 }, .argon2i);
    try expectHex("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0", &tag);
    try derive(&tag, "password", "somesalt", .{ .t = 2, .m = 65536, .p = 1 }, .argon2id);
    try expectHex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", &tag);
    var tag24: [24]u8 = undefined;
    try derive(&tag24, "password", "somesalt", .{ .t = 2, .m = 65536, .p = 4 }, .argon2i);
    try expectHex("45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6", &tag24);
}

test "agrees with std.crypto.pwhash.argon2 (all three modes)" {
    const S = std.crypto.pwhash.argon2;
    var password: [70]u8 = undefined;
    for (&password, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    const cases = [_]struct { t: u32, m: u32, p: u24, len: usize, salt: usize, secret: usize, ad: usize }{
        .{ .t = 1, .m = 8, .p = 1, .len = 4, .salt = 8, .secret = 0, .ad = 0 },
        .{ .t = 1, .m = 16, .p = 2, .len = 64, .salt = 16, .secret = 3, .ad = 0 },
        .{ .t = 2, .m = 64, .p = 1, .len = 65, .salt = 9, .secret = 0, .ad = 5 },
        .{ .t = 3, .m = 77, .p = 3, .len = 100, .salt = 33, .secret = 32, .ad = 12 },
        .{ .t = 1, .m = 600, .p = 1, .len = 32, .salt = 16, .secret = 0, .ad = 0 },
        .{ .t = 4, .m = 300, .p = 5, .len = 1024, .salt = 16, .secret = 1, .ad = 1 },
        .{ .t = 2, .m = 1024, .p = 7, .len = 31, .salt = 64, .secret = 0, .ad = 0 },
    };
    for (cases) |c| {
        for ([_]Mode{ .argon2i, .argon2id, .argon2d }) |mode| {
            const params: Params = .{ .t = c.t, .m = c.m, .p = c.p, .secret = password[0..c.secret], .ad = password[1 .. 1 + c.ad] };
            var ours: [1024]u8 = undefined;
            var theirs: [1024]u8 = undefined;
            try derive(ours[0..c.len], password[0 .. c.len % 70], password[2 .. 2 + c.salt], params, mode);
            const sm: S.Mode = switch (mode) {
                .argon2i => .argon2i,
                .argon2id => .argon2id,
                .argon2d => .argon2d,
            };
            try S.kdf(testing.allocator, theirs[0..c.len], password[0 .. c.len % 70], password[2 .. 2 + c.salt], .{
                .t = c.t,
                .m = c.m,
                .p = c.p,
                .secret = if (c.secret == 0) null else params.secret,
                .ad = if (c.ad == 0) null else params.ad,
            }, sm, testing.io);
            try testing.expectEqualSlices(u8, theirs[0..c.len], ours[0..c.len]);
        }
    }
}
