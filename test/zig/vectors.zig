//! The JSON test vectors of the JavaScript suite (test/vectors), run against
//! the public Zig API. build.zig embeds each file under its path relative to
//! test/vectors, so this test needs no file system access.

const std = @import("std");
const testing = std.testing;
const cryptoapi = @import("crypto_api_ng");

const gpa = testing.allocator;

fn parse(comptime T: type, comptime file: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, gpa, @embedFile(file), .{ .ignore_unknown_fields = true });
}

fn unhex(hex: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex.len / 2);
    errdefer gpa.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// The digest of `message`, once in one call and once in uneven pieces; both must be equal.
fn digestOf(comptime H: type, message: []const u8, options: H.Options) ![H.digest_length]u8 {
    var one: [H.digest_length]u8 = undefined;
    var h = H.init(options);
    h.update(message);
    h.final(&one);

    var pieces = H.init(options);
    var rest = message;
    var step: usize = 1;
    while (rest.len > 0) : (step = step * 3 + 1) {
        const n = @min(step, rest.len);
        pieces.update(rest[0..n]);
        rest = rest[n..];
    }
    var two: [H.digest_length]u8 = undefined;
    pieces.final(&two);
    try testing.expectEqualSlices(u8, &one, &two);
    return one;
}

const Simple = []const struct { name: []const u8, inputHex: []const u8, hex: []const u8 };

fn checkSimple(comptime H: type, comptime file: []const u8) !void {
    const parsed = try parse(Simple, file);
    defer parsed.deinit();
    try testing.expect(parsed.value.len > 0);
    for (parsed.value) |v| {
        const input = try unhex(v.inputHex);
        defer gpa.free(input);
        const want = try unhex(v.hex);
        defer gpa.free(want);
        const got = try digestOf(H, input, .{});
        testing.expectEqualSlices(u8, want, &got) catch |err| {
            std.debug.print("{s}: {s}\n", .{ file, v.name });
            return err;
        };
    }
}

test "hash vectors" {
    try checkSimple(cryptoapi.Md2, "md2.json");
    try checkSimple(cryptoapi.Md4, "md4.json");
    try checkSimple(cryptoapi.Md5, "md5.json");
    try checkSimple(cryptoapi.Has160, "has160.json");
    try checkSimple(cryptoapi.Ripemd128, "ripemd128.json");
    try checkSimple(cryptoapi.Ripemd160, "ripemd160.json");
    try checkSimple(cryptoapi.Ripemd256, "ripemd256.json");
    try checkSimple(cryptoapi.Ripemd320, "ripemd320.json");
    try checkSimple(cryptoapi.Sha0, "sha0.json");
    try checkSimple(cryptoapi.Sha1, "sha1.json");
    try checkSimple(cryptoapi.Sha224, "sha224.json");
    try checkSimple(cryptoapi.Sha256, "sha256.json");
    try checkSimple(cryptoapi.Sha384, "sha384.json");
    try checkSimple(cryptoapi.Sha512, "sha512.json");
    try checkSimple(cryptoapi.Sha512_224, "sha512-224.json");
    try checkSimple(cryptoapi.Sha512_256, "sha512-256.json");
    try checkSimple(cryptoapi.Sm3, "sm3.json");
    try checkSimple(cryptoapi.Snefru(128, 2), "snefru128-2.json");
    try checkSimple(cryptoapi.Snefru128, "snefru128-8.json");
    try checkSimple(cryptoapi.Snefru(256, 4), "snefru256-4.json");
    try checkSimple(cryptoapi.Snefru256, "snefru256-8.json");
    try checkSimple(cryptoapi.Whirlpool, "whirlpool.json");
    try checkSimple(cryptoapi.Whirlpool0, "whirlpool-0.json");
    try checkSimple(cryptoapi.WhirlpoolT, "whirlpool-t.json");
}

const Keyed = []const struct { name: []const u8, keyHex: []const u8, inputHex: []const u8, hex: []const u8 };

fn checkHmac(comptime H: type, comptime file: []const u8) !void {
    const M = cryptoapi.Hmac(H);
    const parsed = try parse(Keyed, file);
    defer parsed.deinit();
    try testing.expect(parsed.value.len > 0);
    for (parsed.value) |v| {
        const key = try unhex(v.keyHex);
        defer gpa.free(key);
        const input = try unhex(v.inputHex);
        defer gpa.free(input);
        const want = try unhex(v.hex);
        defer gpa.free(want);
        var got: [M.mac_length]u8 = undefined;
        M.create(&got, input, key);
        // Some vectors (RFC 4231 test case 5) are truncated MACs.
        testing.expectEqualSlices(u8, want, got[0..want.len]) catch |err| {
            std.debug.print("{s}: {s}\n", .{ file, v.name });
            return err;
        };
    }
}

test "HMAC vectors" {
    try checkHmac(cryptoapi.Has160, "hmac-has160.json");
    try checkHmac(cryptoapi.Md5, "hmac-md5.json");
    try checkHmac(cryptoapi.Sha1, "hmac-sha1.json");
    try checkHmac(cryptoapi.Sha224, "hmac-sha224.json");
    try checkHmac(cryptoapi.Sha256, "hmac-sha256.json");
    try checkHmac(cryptoapi.Sha384, "hmac-sha384.json");
    try checkHmac(cryptoapi.Sha512, "hmac-sha512.json");
}

test "SHA-3, Keccak and SHAKE vectors" {
    const V = []const struct { algo: []const u8, name: []const u8, inputHex: []const u8 = "", hex: []const u8, repeatByte: ?[]const u8 = null, count: usize = 0 };
    const parsed = try parse(V, "sha3.json");
    defer parsed.deinit();
    var seen: usize = 0;
    for (parsed.value) |v| {
        const input = if (v.repeatByte) |byte_hex| blk: {
            const buf = try gpa.alloc(u8, v.count);
            @memset(buf, try std.fmt.parseInt(u8, byte_hex, 16));
            break :blk buf;
        } else try unhex(v.inputHex);
        defer gpa.free(input);
        const want = try unhex(v.hex);
        defer gpa.free(want);

        const got = try gpa.alloc(u8, want.len);
        defer gpa.free(got);
        var matched = false;
        inline for (.{
            .{ "sha3-224", cryptoapi.Sha3_224 },   .{ "sha3-256", cryptoapi.Sha3_256 },
            .{ "sha3-384", cryptoapi.Sha3_384 },   .{ "sha3-512", cryptoapi.Sha3_512 },
            .{ "keccak224", cryptoapi.Keccak224 }, .{ "keccak256", cryptoapi.Keccak256 },
            .{ "keccak384", cryptoapi.Keccak384 }, .{ "keccak512", cryptoapi.Keccak512 },
        }) |entry| {
            if (std.mem.eql(u8, v.algo, entry[0])) {
                const d = try digestOf(entry[1], input, .{});
                @memcpy(got, &d);
                matched = true;
            }
        }
        inline for (.{ .{ "shake128", cryptoapi.Shake128 }, .{ "shake256", cryptoapi.Shake256 } }) |entry| {
            if (std.mem.eql(u8, v.algo, entry[0])) {
                entry[1].hash(input, got, .{});
                matched = true;
            }
        }
        try testing.expect(matched);
        testing.expectEqualSlices(u8, want, got) catch |err| {
            std.debug.print("sha3.json: {s} {s}\n", .{ v.algo, v.name });
            return err;
        };
        seen += 1;
    }
    try testing.expectEqual(parsed.value.len, seen);
}

/// The inputs of scripts/gen-blake-vectors.py and the JS tests.
fn pattern(length: usize, tag: usize) ![]u8 {
    const out = try gpa.alloc(u8, length);
    for (out, 0..) |*b, i| b.* = @truncate(i * 31 + tag * 17 + length);
    return out;
}

fn sequence(length: usize) ![]u8 {
    const out = try gpa.alloc(u8, length);
    for (out, 0..) |*b, i| b.* = @truncate(i);
    return out;
}

test "BLAKE2 official known answers" {
    const V = []const struct { hash: []const u8, keyed: bool, inLen: usize, hex: []const u8 };
    const parsed = try parse(V, "blake/blake2-kat.json");
    defer parsed.deinit();
    try testing.expect(parsed.value.len > 0);
    for (parsed.value) |v| {
        const input = try sequence(v.inLen);
        defer gpa.free(input);
        const want = try unhex(v.hex);
        defer gpa.free(want);
        if (std.mem.eql(u8, v.hash, "blake2b")) {
            const key = try sequence(64);
            defer gpa.free(key);
            const got = try digestOf(cryptoapi.Blake2b512, input, .{ .key = if (v.keyed) key else null });
            try testing.expectEqualSlices(u8, want, &got);
        } else {
            try testing.expectEqualStrings("blake2s", v.hash);
            const key = try sequence(32);
            defer gpa.free(key);
            const got = try digestOf(cryptoapi.Blake2s256, input, .{ .key = if (v.keyed) key else null });
            try testing.expectEqualSlices(u8, want, &got);
        }
    }
}

fn blake2Params(comptime family: enum { b, s }, bits: usize, input: []const u8, key: []const u8, salt: []const u8, person: []const u8, want: []const u8) !void {
    const max = if (family == .b) 512 else 256;
    inline for (1..max / 8 + 1) |bytes| {
        if (bits == bytes * 8) {
            const H = if (family == .b) cryptoapi.Blake2b(bytes * 8) else cryptoapi.Blake2s(bytes * 8);
            const got = try digestOf(H, input, .{ .key = key, .salt = salt, .context = person });
            return testing.expectEqualSlices(u8, want, &got);
        }
    }
    return error.UnsupportedLength;
}

test "BLAKE2 digest length, key, salt and personalization" {
    const V = []const struct { algo: []const u8, length: usize, inLen: usize, keyLen: usize = 0, saltLen: usize = 0, personLen: usize = 0, hex: []const u8 };
    const parsed = try parse(V, "blake/blake2-params.json");
    defer parsed.deinit();
    try testing.expect(parsed.value.len > 0);
    for (parsed.value) |v| {
        const input = try pattern(v.inLen, 0);
        defer gpa.free(input);
        const key = try pattern(v.keyLen, 1);
        defer gpa.free(key);
        const salt = try pattern(v.saltLen, 2);
        defer gpa.free(salt);
        const person = try pattern(v.personLen, 3);
        defer gpa.free(person);
        const want = try unhex(v.hex);
        defer gpa.free(want);
        if (std.mem.eql(u8, v.algo, "blake2b")) {
            try blake2Params(.b, v.length, input, key, salt, person, want);
        } else {
            try testing.expectEqualStrings("blake2s", v.algo);
            try blake2Params(.s, v.length, input, key, salt, person, want);
        }
    }
}

test "BLAKE3 official vectors: hash, keyed hash, derive key, extended output" {
    const V = struct {
        key: []const u8,
        context_string: []const u8,
        cases: []const struct { input_len: usize, hash: []const u8, keyed_hash: []const u8, derive_key: []const u8 },
    };
    const parsed = try parse(V, "blake/blake3.json");
    defer parsed.deinit();
    const key: [32]u8 = parsed.value.key[0..32].*;
    try testing.expect(parsed.value.cases.len > 0);
    for (parsed.value.cases) |c| {
        const input = try gpa.alloc(u8, c.input_len);
        defer gpa.free(input);
        for (input, 0..) |*b, i| b.* = @intCast(i % 251);

        inline for (.{ "hash", "keyed_hash", "derive_key" }) |mode| {
            const want = try unhex(@field(c, mode));
            defer gpa.free(want);
            const got = try gpa.alloc(u8, want.len);
            defer gpa.free(got);
            var h = if (comptime std.mem.eql(u8, mode, "hash"))
                cryptoapi.Blake3.init(.{})
            else if (comptime std.mem.eql(u8, mode, "keyed_hash"))
                cryptoapi.Blake3.init(.{ .key = key })
            else
                cryptoapi.Blake3.initKdf(parsed.value.context_string);
            h.update(input);
            h.final(got);
            testing.expectEqualSlices(u8, want, got) catch |err| {
                std.debug.print("blake3.json: {s} len {d}\n", .{ mode, c.input_len });
                return err;
            };
        }
    }
}

const Blocks = []const struct { length: usize, tag: usize, digest: []const u8 };

fn checkBlocks(comptime H: type, comptime file: []const u8) !void {
    const parsed = try parse(Blocks, file);
    defer parsed.deinit();
    try testing.expect(parsed.value.len > 0);
    for (parsed.value) |v| {
        const input = try pattern(v.length, v.tag);
        defer gpa.free(input);
        const want = try unhex(v.digest);
        defer gpa.free(want);
        const got = try digestOf(H, input, .{});
        // Truncated variants (Tiger/160, Tiger/128) are a prefix of the full digest.
        testing.expectEqualSlices(u8, want[0..H.digest_length], &got) catch |err| {
            std.debug.print("{s}: length {d}\n", .{ file, v.length });
            return err;
        };
    }
}

test "Tiger, Tiger2 and Streebog vectors" {
    try checkBlocks(cryptoapi.Tiger, "blocks/tiger.json");
    try checkBlocks(cryptoapi.Tiger160, "blocks/tiger.json");
    try checkBlocks(cryptoapi.Tiger128, "blocks/tiger.json");
    try checkBlocks(cryptoapi.Tiger2, "blocks/tiger2.json");
    try checkBlocks(cryptoapi.Streebog256, "blocks/streebog256.json");
    try checkBlocks(cryptoapi.Streebog512, "blocks/streebog512.json");
}

const Sp800Row = struct {
    algo: []const u8,
    strength: u32,
    xof: bool,
    input: []const u8 = "",
    tuple: []const []const u8 = &.{},
    key: []const u8 = "",
    functionName: []const u8 = "",
    customization: []const u8,
    blockSize: usize = 0,
    length: usize,
    output: []const u8,
};

fn sp800Output(comptime strength: u32, v: Sp800Row, out: []u8) !void {
    const input = try unhex(v.input);
    defer gpa.free(input);
    const S = v.customization;
    if (std.mem.eql(u8, v.algo, "cshake")) {
        const C = if (strength == 128) cryptoapi.CShake128 else cryptoapi.CShake256;
        C.hash(input, out, .{ .function_name = v.functionName, .customization = S });
    } else if (std.mem.eql(u8, v.algo, "kmac")) {
        const K = if (strength == 128) cryptoapi.Kmac128 else cryptoapi.Kmac256;
        const key = try unhex(v.key);
        defer gpa.free(key);
        var h = K.initWithOptions(key, .{ .customization = S });
        h.update(input);
        if (v.xof) h.squeeze(out) else h.final(out);
    } else if (std.mem.eql(u8, v.algo, "tuplehash")) {
        const T = if (strength == 128) cryptoapi.TupleHash128 else cryptoapi.TupleHash256;
        var h = T.init(.{ .customization = S });
        for (v.tuple) |e| {
            const element = try unhex(e);
            defer gpa.free(element);
            h.update(element);
        }
        if (v.xof) h.squeeze(out) else h.final(out);
    } else if (std.mem.eql(u8, v.algo, "parallelhash")) {
        const P = if (strength == 128) cryptoapi.ParallelHash128 else cryptoapi.ParallelHash256;
        var h = P.init(.{ .block_size = v.blockSize, .customization = S });
        h.update(input);
        if (v.xof) h.squeeze(out) else h.final(out);
    } else return error.UnknownAlgorithm;
}

test "keccak-modes/sp800-185.json (NIST SP 800-185 samples)" {
    const parsed = try parse([]const Sp800Row, "keccak-modes/sp800-185.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 36), parsed.value.len);
    for (parsed.value) |v| {
        const want = try unhex(v.output);
        defer gpa.free(want);
        const got = try gpa.alloc(u8, v.length / 8);
        defer gpa.free(got);
        if (v.strength == 128) try sp800Output(128, v, got) else try sp800Output(256, v, got);
        testing.expectEqualSlices(u8, want, got) catch |err| {
            std.debug.print("sp800-185.json: {s}{d} xof={}\n", .{ v.algo, v.strength, v.xof });
            return err;
        };
    }
}

const Spec = struct { pattern: ?usize = null, ff: ?usize = null };
const KtRow = struct {
    algo: []const u8,
    message: Spec,
    customization: Spec = .{ .pattern = 0 },
    domain: u8 = 0x1f,
    length: usize,
    skip: usize,
    output: []const u8,
};

fn specBytes(s: Spec) ![]u8 {
    if (s.ff) |n| {
        const out = try gpa.alloc(u8, n);
        @memset(out, 0xff);
        return out;
    }
    const out = try gpa.alloc(u8, s.pattern.?);
    for (out, 0..) |*b, i| b.* = @intCast(i % 251);
    return out;
}

test "keccak-modes/kangarootwelve.json (RFC 9861 vectors)" {
    const parsed = try parse([]const KtRow, "keccak-modes/kangarootwelve.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 54), parsed.value.len);
    for (parsed.value) |v| {
        const msg = try specBytes(v.message);
        defer gpa.free(msg);
        const custom = try specBytes(v.customization);
        defer gpa.free(custom);
        const want = try unhex(v.output);
        defer gpa.free(want);
        const got = try gpa.alloc(u8, v.length);
        defer gpa.free(got);
        if (std.mem.eql(u8, v.algo, "kt128")) {
            cryptoapi.KT128.hash(msg, got, .{ .customization = custom });
        } else if (std.mem.eql(u8, v.algo, "kt256")) {
            cryptoapi.KT256.hash(msg, got, .{ .customization = custom });
        } else if (std.mem.eql(u8, v.algo, "turboshake128")) {
            cryptoapi.TurboShake128.hash(msg, got, .{ .domain = v.domain });
        } else if (std.mem.eql(u8, v.algo, "turboshake256")) {
            cryptoapi.TurboShake256.hash(msg, got, .{ .domain = v.domain });
        } else return error.UnknownAlgorithm;
        testing.expectEqualSlices(u8, want, got[v.skip..]) catch |err| {
            std.debug.print("kangarootwelve.json: {s} {d}\n", .{ v.algo, msg.len });
            return err;
        };
    }
}

/// The sanity buffer of the xxHash test suite (tests/sanity_test.c).
fn sanityBuffer(comptime n: usize) [n]u8 {
    var out: [n]u8 = undefined;
    var gen: u64 = 2654435761;
    for (&out) |*b| {
        b.* = @truncate(gen >> 56);
        gen *%= 11400714785074694797;
    }
    return out;
}

test "XXH3 and XXH128: the xxHash sanity values" {
    const Row = struct { length: usize, seed: []const u8, xxh3: ?[]const u8 = null, xxh128: ?[]const u8 = null };
    const parsed = try parse([]const Row, "fast/xxh3.json");
    defer parsed.deinit();
    try testing.expect(parsed.value.len > 1000);
    const buf = sanityBuffer(4096 + 64 + 1);
    for (parsed.value) |v| {
        const seed = try std.fmt.parseInt(u64, v.seed, 16);
        const m = buf[0..v.length];
        if (v.xxh3) |want| {
            const w = try unhex(want);
            defer gpa.free(w);
            const got = try digestOf(cryptoapi.XxHash3, m, .{ .seed = seed });
            try testing.expectEqualSlices(u8, w, &got);
        }
        if (v.xxh128) |want| {
            const w = try unhex(want);
            defer gpa.free(w);
            const got = try digestOf(cryptoapi.XxHash128, m, .{ .seed = seed });
            try testing.expectEqualSlices(u8, w, &got);
        }
    }
}

test "SipHash-2-4 and SipHash-1-3 reference vectors" {
    const Row = struct { length: usize, siphash24: []const u8, siphash13: []const u8 };
    const parsed = try parse([]const Row, "fast/siphash.json");
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 64), parsed.value.len);
    var key: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    var msg: [64]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(i);
    for (parsed.value) |v| {
        const w24 = try unhex(v.siphash24);
        defer gpa.free(w24);
        const w13 = try unhex(v.siphash13);
        defer gpa.free(w13);
        try testing.expectEqualSlices(u8, w24, &try digestOf(cryptoapi.SipHash24, msg[0..v.length], .{ .key = key }));
        try testing.expectEqualSlices(u8, w13, &try digestOf(cryptoapi.SipHash13, msg[0..v.length], .{ .key = key }));
    }
}
