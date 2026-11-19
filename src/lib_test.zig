//! Tests of the public Zig API (`lib.zig`): known answers, streaming in
//! pieces, and agreement with `std.crypto` for the algorithms both have.
//! The shared JSON test vectors are checked by test/zig/vectors.zig.

const std = @import("std");
const testing = std.testing;
const lib = @import("lib.zig");

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var buf: [512]u8 = undefined;
    const want = try std.fmt.hexToBytes(&buf, expected);
    try testing.expectEqualSlices(u8, want, actual);
}

fn digestOf(comptime H: type, data: []const u8) [H.digest_length]u8 {
    var out: [H.digest_length]u8 = undefined;
    H.hash(data, &out, .{});
    return out;
}

test "known answers" {
    try expectHex("da853b0d3f88d99b30283a69e6ded6bb", &digestOf(lib.Md2, "abc"));
    try expectHex("a448017aaf21d8525fc10ae87aa6729d", &digestOf(lib.Md4, "abc"));
    try expectHex("900150983cd24fb0d6963f7d28e17f72", &digestOf(lib.Md5, "abc"));
    try expectHex("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", &digestOf(lib.Sha0, "abc"));
    try expectHex("a9993e364706816aba3e25717850c26c9cd0d89d", &digestOf(lib.Sha1, "abc"));
    try expectHex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", &digestOf(lib.Ripemd160, "abc"));
    try expectHex("975e810488cf2a3d49838478124afce4b1c78804", &digestOf(lib.Has160, "abc"));
    try expectHex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", &digestOf(lib.Sm3, "abc"));
    try expectHex("4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5", &digestOf(lib.Whirlpool, "abc"));
    try expectHex("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93", &digestOf(lib.Tiger, "abc"));
    try expectHex("2aab1484e8c158f2bfb8c5ff41b57a525129131c", &digestOf(lib.Tiger160, "abc"));
    try expectHex("8617f366566a011837f4fb4ba5bedea2", &digestOf(lib.Snefru128, ""));
    try expectHex("8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881", &digestOf(lib.Snefru256, ""));
    const m1 = "012345678901234567890123456789012345678901234567890123456789012";
    try expectHex("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500", &digestOf(lib.Streebog256, m1));
    try expectHex("1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48", &digestOf(lib.Streebog512, m1));
    try expectHex("cbf43926", &digestOf(lib.Crc32, "123456789"));
    try expectHex("e3069283", &digestOf(lib.Crc32c, "123456789"));
    try expectHex("02cc5d05", &digestOf(lib.XxHash32, ""));
    try expectHex("ef46db3751d8e999", &digestOf(lib.XxHash64, ""));
    try expectHex("78af5f94892f3950", &digestOf(lib.XxHash3, "abc"));
    try expectHex("06b05ab6733a618578af5f94892f3950", &digestOf(lib.XxHash128, "abc"));
    try expectHex("b3dd93fa", &digestOf(lib.Murmur3_32, "abc"));
    try expectHex("6778ad3f3f3f96b4522dca264174a23b", &digestOf(lib.Murmur3_128, "abc"));
    try expectHex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", &digestOf(lib.Keccak256, ""));
}

/// Every hash type with a fixed digest and no required options.
const fixed = .{
    lib.Md2,         lib.Md4,         lib.Md5,          lib.Sha0,          lib.Sha1,
    lib.Sha224,      lib.Sha256,      lib.Sha384,       lib.Sha512,        lib.Sha512_224,
    lib.Sha512_256,  lib.Sm3,         lib.Has160,       lib.Ripemd128,     lib.Ripemd160,
    lib.Ripemd256,   lib.Ripemd320,   lib.Whirlpool,    lib.Whirlpool0,    lib.WhirlpoolT,
    lib.Snefru128,   lib.Snefru256,   lib.Snefru(448, 2), lib.Tiger,       lib.Tiger2,
    lib.Streebog256, lib.Streebog512, lib.Crc32,        lib.Crc32c,        lib.XxHash32,
    lib.XxHash64,    lib.Blake2b512,  lib.Blake2b160,   lib.Blake2s256,    lib.Blake2s128,
    lib.Sha3_224,    lib.Sha3_256,    lib.Sha3_384,     lib.Sha3_512,      lib.Keccak224,
    lib.Keccak256,   lib.Keccak384,   lib.Keccak512,  lib.XxHash3,       lib.XxHash128,
    lib.Murmur3_32,  lib.Murmur3_128,
};

fn randomData(comptime n: usize, seed: u64) [n]u8 {
    var prng = std.Random.DefaultPrng.init(seed);
    var data: [n]u8 = undefined;
    prng.random().bytes(&data);
    return data;
}

test "input in pieces gives the one-shot digest" {
    const data = randomData(700, 1);
    inline for (fixed) |H| {
        for ([_]usize{ 0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 135, 136, 137, 255, 256, 700 }) |len| {
            const want = digestOf(H, data[0..len]);
            // Every split point for short inputs, a few for long ones.
            var split: usize = 0;
            while (split <= len) : (split += if (len < 200) 1 else 37) {
                var h = H.init(.{});
                h.update(data[0..split]);
                h.update("");
                h.update(data[split..len]);
                try testing.expectEqualSlices(u8, &want, &h.finalResult());
            }
            var h = H.init(.{});
            for (data[0..len]) |b| h.update(&.{b});
            try testing.expectEqualSlices(u8, &want, &h.finalResult());
        }
    }
}

fn expectSameAsStd(comptime H: type, comptime S: type) !void {
    const data = randomData(2200, 2);
    var len: usize = 0;
    while (len <= data.len) : (len += if (len < 300) 1 else 97) {
        var a: [H.digest_length]u8 = undefined;
        var b: [S.digest_length]u8 = undefined;
        H.hash(data[0..len], &a, .{});
        S.hash(data[0..len], &b, .{});
        try testing.expectEqualSlices(u8, &b, &a);
    }
}

test "agrees with std.crypto" {
    const sha2 = std.crypto.hash.sha2;
    const sha3 = std.crypto.hash.sha3;
    try expectSameAsStd(lib.Md5, std.crypto.hash.Md5);
    try expectSameAsStd(lib.Sha1, std.crypto.hash.Sha1);
    try expectSameAsStd(lib.Sha224, sha2.Sha224);
    try expectSameAsStd(lib.Sha256, sha2.Sha256);
    try expectSameAsStd(lib.Sha384, sha2.Sha384);
    try expectSameAsStd(lib.Sha512, sha2.Sha512);
    try expectSameAsStd(lib.Sha512_224, sha2.Sha512_224);
    try expectSameAsStd(lib.Sha512_256, sha2.Sha512_256);
    try expectSameAsStd(lib.Sha3_224, sha3.Sha3_224);
    try expectSameAsStd(lib.Sha3_256, sha3.Sha3_256);
    try expectSameAsStd(lib.Sha3_384, sha3.Sha3_384);
    try expectSameAsStd(lib.Sha3_512, sha3.Sha3_512);
    try expectSameAsStd(lib.Keccak256, sha3.Keccak256);
    try expectSameAsStd(lib.Keccak512, sha3.Keccak512);
    try expectSameAsStd(lib.Blake2b512, std.crypto.hash.blake2.Blake2b512);
    try expectSameAsStd(lib.Blake2b256, std.crypto.hash.blake2.Blake2b256);
    try expectSameAsStd(lib.Blake2s256, std.crypto.hash.blake2.Blake2s256);
    try expectSameAsStd(lib.Blake2s128, std.crypto.hash.blake2.Blake2s128);
}

test "BLAKE2 key, salt and personalization agree with std.crypto" {
    const data = randomData(300, 3);
    const key = randomData(64, 4);
    const salt = randomData(16, 5);
    const ctx = randomData(16, 6);
    inline for (.{
        .{ lib.Blake2b512, std.crypto.hash.blake2.Blake2b512, 16 },
        .{ lib.Blake2s256, std.crypto.hash.blake2.Blake2s256, 8 },
    }) |pair| {
        const H = pair[0];
        const S = pair[1];
        for ([_]usize{ 0, 1, 64, 65, 128, 129, 300 }) |len| {
            for ([_]usize{ 1, 7, H.key_length_max }) |klen| {
                var a: [H.digest_length]u8 = undefined;
                var b: [S.digest_length]u8 = undefined;
                H.hash(data[0..len], &a, .{ .key = key[0..klen], .salt = salt[0..pair[2]], .context = ctx[0..pair[2]] });
                S.hash(data[0..len], &b, .{ .key = key[0..klen], .salt = salt[0..pair[2]].*, .context = ctx[0..pair[2]].* });
                try testing.expectEqualSlices(u8, &b, &a);
            }
        }
    }
}

test "BLAKE3 agrees with std.crypto in all three modes" {
    const S = std.crypto.hash.Blake3;
    const data = randomData(5000, 7);
    const key = randomData(32, 8);
    const context = "crypto-api-ng 2026-11-17 test context";
    var len: usize = 0;
    while (len <= data.len) : (len += if (len < 2100) 1 else 333) {
        var a: [100]u8 = undefined;
        var b: [100]u8 = undefined;
        lib.Blake3.hash(data[0..len], &a, .{});
        S.hash(data[0..len], &b, .{});
        try testing.expectEqualSlices(u8, &b, &a);

        lib.Blake3.hash(data[0..len], &a, .{ .key = key });
        S.hash(data[0..len], &b, .{ .key = key });
        try testing.expectEqualSlices(u8, &b, &a);

        var k = lib.Blake3.initKdf(context);
        k.update(data[0..len]);
        k.final(&a);
        var ks = S.initKdf(context, .{});
        ks.update(data[0..len]);
        ks.final(&b);
        try testing.expectEqualSlices(u8, &b, &a);
    }
}

test "SHAKE agrees with std.crypto, including squeeze" {
    const data = randomData(400, 9);
    inline for (.{ .{ lib.Shake128, std.crypto.hash.sha3.Shake128 }, .{ lib.Shake256, std.crypto.hash.sha3.Shake256 } }) |pair| {
        for ([_]usize{ 0, 1, 135, 136, 137, 167, 168, 169, 400 }) |len| {
            var a: [500]u8 = undefined;
            var b: [500]u8 = undefined;
            var h = pair[0].init(.{});
            h.update(data[0..len]);
            h.final(a[0..10]);
            h.squeeze(a[10..300]);
            h.squeeze(a[300..]);
            pair[1].hash(data[0..len], &b, .{});
            try testing.expectEqualSlices(u8, &b, &a);
        }
    }
}

test "SP 800-185 and RFC 9861 types agree with std.crypto" {
    const sha3 = std.crypto.hash.sha3;
    const data = randomData(20000, 13);
    const key = "a KMAC key";
    for ([_]usize{ 0, 1, 167, 168, 169, 8191, 8192, 8193, 20000 }) |len| {
        const m = data[0..len];
        var a: [300]u8 = undefined;
        var b: [300]u8 = undefined;
        inline for (.{ .{ lib.CShake128, sha3.CShake128 }, .{ lib.CShake256, sha3.CShake256 } }) |pair| {
            pair[0].hash(m, &a, .{ .customization = "S" });
            pair[1].hash(m, &b, .{ .context = "S" });
            try testing.expectEqualSlices(u8, &b, &a);
        }
        inline for (.{ .{ lib.Kmac128, sha3.KMac128 }, .{ lib.Kmac256, sha3.KMac256 } }) |pair| {
            pair[0].createWithOptions(a[0..40], m, key, .{ .customization = "S" });
            pair[1].createWithOptions(b[0..40], m, key, .{ .context = "S" });
            try testing.expectEqualSlices(u8, b[0..40], a[0..40]);
        }
        inline for (.{ .{ lib.TupleHash128, sha3.TupleHash128 }, .{ lib.TupleHash256, sha3.TupleHash256 } }) |pair| {
            var x = pair[0].init(.{ .customization = "S" });
            var y = pair[1].initWithOptions(.{ .context = "S" });
            x.update(m[0 .. len / 2]);
            x.update(m[len / 2 ..]);
            y.update(m[0 .. len / 2]);
            y.update(m[len / 2 ..]);
            x.squeeze(&a);
            y.squeeze(&b);
            try testing.expectEqualSlices(u8, &b, &a);
        }
        inline for (.{ .{ lib.TurboShake128, sha3.TurboShake128(0x0b) }, .{ lib.TurboShake256, sha3.TurboShake256(0x0b) } }) |pair| {
            pair[0].hash(m, &a, .{ .domain = 0x0b });
            pair[1].hash(m, &b, .{});
            try testing.expectEqualSlices(u8, &b, &a);
        }
        inline for (.{ .{ lib.KT128, sha3.KT128 }, .{ lib.KT256, sha3.KT256 } }) |pair| {
            pair[0].hash(m, &a, .{ .customization = key });
            try pair[1].hash(m, &b, .{ .customization = key });
            try testing.expectEqualSlices(u8, &b, &a);
        }
    }
}

test "ParallelHash known answers (NIST SP 800-185 samples)" {
    const x = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };
    var out: [32]u8 = undefined;
    lib.ParallelHash128.hash(&x, &out, .{ .block_size = 8, .customization = "Parallel Data" });
    try expectHex("fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206", &out);
    var h = lib.ParallelHash128.init(.{ .block_size = 8 });
    h.update(&x);
    h.squeeze(&out);
    try expectHex("fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3", &out);
}

test "checksums agree with std.hash" {
    const data = randomData(500, 10);
    for (0..data.len + 1) |len| {
        const m = data[0..len];
        try testing.expectEqual(std.hash.Crc32.hash(m), std.mem.readInt(u32, &digestOf(lib.Crc32, m), .big));
        try testing.expectEqual(std.hash.crc.@"CRC-32/ISCSI".hash(m), std.mem.readInt(u32, &digestOf(lib.Crc32c, m), .big));
        var x32: [4]u8 = undefined;
        lib.XxHash32.hash(m, &x32, .{ .seed = 0x9e3779b1 });
        try testing.expectEqual(std.hash.XxHash32.hash(0x9e3779b1, m), std.mem.readInt(u32, &x32, .big));
        var x64: [8]u8 = undefined;
        lib.XxHash64.hash(m, &x64, .{ .seed = 0x123456789abcdef });
        try testing.expectEqual(std.hash.XxHash64.hash(0x123456789abcdef, m), std.mem.readInt(u64, &x64, .big));
        lib.XxHash3.hash(m, &x64, .{ .seed = 0x9e3779b185ebca8d });
        try testing.expectEqual(std.hash.XxHash3.hash(0x9e3779b185ebca8d, m), std.mem.readInt(u64, &x64, .big));
        lib.Murmur3_32.hash(m, &x32, .{ .seed = 0x9747b28c });
        try testing.expectEqual(std.hash.Murmur3_32.hashWithSeed(m, 0x9747b28c), std.mem.readInt(u32, &x32, .big));
    }
}

test "XXH3 in pieces across the 64-byte hold-back" {
    const data = randomData(5000, 13);
    for ([_]usize{ 0, 1, 240, 241, 1087, 1088, 1089, 2111, 2112, 2113, 4096, 5000 }) |len| {
        const m = data[0..len];
        const want = digestOf(lib.XxHash128, m);
        for ([_]usize{ 1, 63, 64, 65, 1023, 1024, 1025, 3000 }) |step| {
            var h = lib.XxHash128.init(.{});
            var rest = m;
            while (rest.len > 0) {
                const n = @min(step, rest.len);
                h.update(rest[0..n]);
                rest = rest[n..];
            }
            try testing.expectEqualSlices(u8, &want, &h.finalResult());
        }
        var x: [8]u8 = undefined;
        lib.XxHash3.hash(m, &x, .{ .seed = 7 });
        try testing.expectEqual(std.hash.XxHash3.hash(7, m), std.mem.readInt(u64, &x, .big));
    }
}

test "SipHash agrees with std.crypto.auth.siphash" {
    const data = randomData(300, 14);
    const key = randomData(16, 15);
    for (0..data.len + 1) |len| {
        const m = data[0..len];
        var want: [8]u8 = undefined;
        std.crypto.auth.siphash.SipHash64(2, 4).create(&want, m, &key);
        var got: [8]u8 = undefined;
        lib.SipHash24.hash(m, &got, .{ .key = key });
        try testing.expectEqualSlices(u8, &want, &got);
        std.crypto.auth.siphash.SipHash64(1, 3).create(&want, m, &key);
        var h = lib.SipHash13.init(.{ .key = key });
        h.update(m[0 .. len / 2]);
        h.update(m[len / 2 ..]);
        try testing.expectEqualSlices(u8, &want, &h.finalResult());
    }
}

test "HMAC agrees with std.crypto for every key length class" {
    const data = randomData(300, 11);
    const key = randomData(300, 12);
    inline for (.{
        .{ lib.Hmac(lib.Md5), std.crypto.auth.hmac.HmacMd5 },
        .{ lib.Hmac(lib.Sha1), std.crypto.auth.hmac.HmacSha1 },
        .{ lib.Hmac(lib.Sha256), std.crypto.auth.hmac.sha2.HmacSha256 },
        .{ lib.Hmac(lib.Sha512), std.crypto.auth.hmac.sha2.HmacSha512 },
        .{ lib.Hmac(lib.Sha3_256), std.crypto.auth.hmac.Hmac(std.crypto.hash.sha3.Sha3_256) },
    }) |pair| {
        for ([_]usize{ 0, 1, 63, 64, 65, 128, 129, 136, 137, 300 }) |klen| {
            var a: [pair[0].mac_length]u8 = undefined;
            var b: [pair[1].mac_length]u8 = undefined;
            pair[0].create(&a, data[0 .. klen % 200], key[0..klen]);
            pair[1].create(&b, data[0 .. klen % 200], key[0..klen]);
            try testing.expectEqualSlices(u8, &b, &a);
        }
    }
}

test "HMAC over the algorithms std lacks (RFC 2286 RIPEMD-160)" {
    var out: [20]u8 = undefined;
    lib.Hmac(lib.Ripemd160).create(&out, "what do ya want for nothing?", "Jefe");
    try expectHex("dda6c0213a485a9e24f4742064a7f033b43c4069", &out);
    lib.Hmac(lib.Ripemd160).create(&out, "Hi There", &@as([20]u8, @splat(0x0b)));
    try expectHex("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668", &out);
}

test "PBKDF2 (RFC 6070, RFC 7914)" {
    var dk20: [20]u8 = undefined;
    try lib.pbkdf2(&dk20, "password", "salt", 1, lib.Sha1);
    try expectHex("0c60c80f961f0e71f3a9b524af6012062fe037a6", &dk20);
    try lib.pbkdf2(&dk20, "password", "salt", 4096, lib.Sha1);
    try expectHex("4b007901b765489abead49d926f721d065a429c1", &dk20);
    var dk25: [25]u8 = undefined;
    try lib.pbkdf2(&dk25, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, lib.Sha1);
    try expectHex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", &dk25);
    var dk64: [64]u8 = undefined;
    try lib.pbkdf2(&dk64, "passwd", "salt", 1, lib.Sha256);
    try expectHex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783", &dk64);
    try testing.expectError(error.WeakParameters, lib.pbkdf2(&dk20, "p", "s", 0, lib.Sha1));
}

test "PBKDF2 over Whirlpool agrees with std's pbkdf2 over this Hmac" {
    var a: [100]u8 = undefined;
    var b: [100]u8 = undefined;
    try lib.pbkdf2(&a, "pw", "NaCl", 3, lib.Whirlpool);
    try std.crypto.pwhash.pbkdf2(&b, "pw", "NaCl", 3, lib.Hmac(lib.Whirlpool));
    try testing.expectEqualSlices(u8, &b, &a);
}

test "HKDF (RFC 5869)" {
    var ikm: [22]u8 = @splat(0x0b);
    var salt: [13]u8 = undefined;
    for (&salt, 0..) |*b, i| b.* = @intCast(i);
    var info: [10]u8 = undefined;
    for (&info, 0..) |*b, i| b.* = @intCast(0xf0 + i);
    const H = lib.Hkdf(lib.Sha256);
    const prk = H.extract(&salt, &ikm);
    try expectHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", &prk);
    var okm: [42]u8 = undefined;
    H.expand(&okm, &info, prk);
    try expectHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", &okm);

    // Test case 4: SHA-1.
    const H1 = lib.Hkdf(lib.Sha1);
    const prk1 = H1.extract(&salt, ikm[0..11]);
    try expectHex("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243", &prk1);
    H1.expand(&okm, &info, prk1);
    try expectHex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896", &okm);
}

test "final wipes the hasher" {
    var h = lib.Ripemd160.init(.{});
    h.update("secret");
    _ = h.finalResult();
    for (std.mem.asBytes(&h)) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "final wipes the SP 800-185 and KangarooTwelve hashers" {
    var k = lib.Kmac128.init("secret key");
    k.update("secret");
    _ = k.finalResult();
    for (std.mem.asBytes(&k)) |b| try testing.expectEqual(@as(u8, 0), b);
    var p = lib.ParallelHash256.init(.{ .block_size = 3 });
    p.update("secret message");
    _ = p.finalResult();
    for (std.mem.asBytes(&p)) |b| try testing.expectEqual(@as(u8, 0), b);
    var t = lib.KT128.init(.{});
    t.update(&@as([9000]u8, @splat(7)));
    _ = t.finalResult();
    for (std.mem.asBytes(&t)) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "argon2.kdf: RFC 9106 section 5" {
    const password: [32]u8 = @splat(0x01);
    const salt: [16]u8 = @splat(0x02);
    const secret: [8]u8 = @splat(0x03);
    const ad: [12]u8 = @splat(0x04);
    const params: lib.argon2.Params = .{ .t = 3, .m = 32, .p = 4, .secret = &secret, .ad = &ad };
    var tag: [32]u8 = undefined;
    try lib.argon2.kdf(testing.allocator, &tag, &password, &salt, params, .argon2d);
    try expectHex("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb", &tag);
    try lib.argon2.kdf(testing.allocator, &tag, &password, &salt, params, .argon2i);
    try expectHex("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8", &tag);
    try lib.argon2.kdf(testing.allocator, &tag, &password, &salt, params, .argon2id);
    try expectHex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", &tag);
    try testing.expectError(error.WeakParameters, lib.argon2.kdf(testing.allocator, &tag, "pw", "short", .{ .t = 1, .m = 8, .p = 1 }, .argon2id));
    try testing.expectError(error.OutOfMemory, lib.argon2.kdf(testing.failing_allocator, &tag, "pw", "saltsalt", .{ .t = 1, .m = 8, .p = 1 }, .argon2id));
}

test "scrypt.kdf: RFC 7914 section 12" {
    var dk: [64]u8 = undefined;
    try lib.scrypt.kdf(testing.allocator, &dk, "password", "NaCl", .{ .ln = 10, .r = 8, .p = 16 });
    try expectHex("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", &dk);
    try testing.expectError(error.WeakParameters, lib.scrypt.kdf(testing.allocator, &dk, "pw", "salt", .{ .ln = 0, .r = 8, .p = 1 }));
    try testing.expectError(error.OutOfMemory, lib.scrypt.kdf(testing.failing_allocator, &dk, "pw", "salt", .{ .ln = 4, .r = 1, .p = 1 }));
}

test "runtime.version matches lib.version" {
    var buf: [32]u8 = undefined;
    const v = lib.version;
    const text = try std.fmt.bufPrint(&buf, "{d}.{d}.{d}", .{ v.major, v.minor, v.patch });
    try std.testing.expectEqualStrings(text, @import("runtime.zig").version);
}
