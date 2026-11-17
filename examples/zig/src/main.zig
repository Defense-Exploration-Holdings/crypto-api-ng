const std = @import("std");
const cryptoapi = @import("crypto_api_ng");

pub fn main() void {
    const message = "The quick brown fox jumps over the lazy dog";

    // Streaming: init, update as often as needed, final.
    var h = cryptoapi.Whirlpool.init(.{});
    h.update("The quick brown fox ");
    h.update("jumps over the lazy dog");
    var whirlpool: [cryptoapi.Whirlpool.digest_length]u8 = undefined;
    h.final(&whirlpool);
    std.debug.print("whirlpool  {x}\n", .{whirlpool});

    // One call.
    var ripemd: [cryptoapi.Ripemd160.digest_length]u8 = undefined;
    cryptoapi.Ripemd160.hash(message, &ripemd, .{});
    std.debug.print("ripemd160  {x}\n", .{ripemd});

    std.debug.print("streebog   {x}\n", .{hashOf(cryptoapi.Streebog256, message)});
    std.debug.print("sm3        {x}\n", .{hashOf(cryptoapi.Sm3, message)});

    // HMAC, PBKDF2 and HKDF take any of the hash types.
    var mac: [cryptoapi.Hmac(cryptoapi.Sm3).mac_length]u8 = undefined;
    cryptoapi.Hmac(cryptoapi.Sm3).create(&mac, message, "key");
    std.debug.print("hmac-sm3   {x}\n", .{mac});

    var key: [32]u8 = undefined;
    cryptoapi.pbkdf2(&key, "password", "salt", 1000, cryptoapi.Streebog512) catch unreachable;
    std.debug.print("pbkdf2     {x}\n", .{key});
}

fn hashOf(comptime H: type, data: []const u8) [H.digest_length]u8 {
    var out: [H.digest_length]u8 = undefined;
    H.hash(data, &out, .{});
    return out;
}

test "RIPEMD-160 of the pangram" {
    var out: [20]u8 = undefined;
    cryptoapi.Ripemd160.hash("The quick brown fox jumps over the lazy dog", &out, .{});
    var want: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "37f332f68db77bd9d7edd4969571ad671cf9dd3b");
    try std.testing.expectEqualSlices(u8, &want, &out);
}
