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
