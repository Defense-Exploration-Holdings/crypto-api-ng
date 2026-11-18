//! crypto-api-ng for Zig: the hash functions of crypto-api-ng as a native Zig
//! module, with no WebAssembly or JavaScript involved.
//!
//! Every hash type follows the interface of `std.crypto.hash`:
//!
//!     const cryptoapi = @import("crypto_api_ng");
//!
//!     var h = cryptoapi.Whirlpool.init(.{});
//!     h.update("abc");
//!     var digest: [cryptoapi.Whirlpool.digest_length]u8 = undefined;
//!     h.final(&digest);
//!
//!     // or in one call
//!     cryptoapi.Ripemd160.hash("abc", &digest160, .{});
//!
//! Each type has `block_length`, `digest_length`, `Options`, `init`, `update`,
//! `final`, `finalResult` and `hash`, so it also works with code written for
//! `std.crypto` hashes. `final` wipes the hasher; call `init` again to reuse
//! one. Copying a hasher value forks its state.
//!
//! `Hmac`, `pbkdf2` and `Hkdf` accept any of the hash types here (and the
//! `std.crypto` ones). `argon2.kdf` and `scrypt.kdf` hash passwords with an
//! allocator for their work memory, like `std.crypto.pwhash`.
//!
//! Some of these algorithms are broken or weak (MD2, MD4, MD5, SHA-0, SHA-1,
//! HAS-160, Snefru with few passes) and are here for compatibility with
//! existing data and protocols. CRC-32, CRC-32C, XXH32, XXH64, XXH3 and
//! MurmurHash3 are checksums, not cryptographic hashes. SipHash is a keyed
//! hash for hash tables, not a general-purpose MAC. No function here claims
//! constant-time execution.

const std = @import("std");

const md2 = @import("hash/md2.zig");
const md4 = @import("hash/md4.zig");
const md5 = @import("hash/md5.zig");
const sha1 = @import("hash/sha1.zig");
const sha256 = @import("hash/sha256.zig");
const sha512 = @import("hash/sha512.zig");
const sm3 = @import("hash/sm3.zig");
const has160 = @import("hash/has160.zig");
const ripemd = @import("hash/ripemd.zig");
const snefru = @import("hash/snefru.zig");
const whirlpool = @import("hash/whirlpool.zig");
const keccak = @import("hash/keccak.zig");
const blake2 = @import("hash/blake2.zig");
const blake3 = @import("hash/blake3.zig");
const tiger = @import("hash/tiger.zig");
const streebog = @import("hash/streebog.zig");
const crc32 = @import("hash/crc32.zig");
const xxhash = @import("hash/xxhash.zig");
const xxh3 = @import("hash/xxh3.zig");
const siphash = @import("hash/siphash.zig");
const murmur3 = @import("hash/murmur3.zig");
const argon2_core = @import("kdf/argon2.zig");
const scrypt_core = @import("kdf/scrypt.zig");

/// Library version.
pub const version = std.SemanticVersion{ .major = 1, .minor = 3, .patch = 0 };

fn wipe(ptr: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(ptr));
}

// ---- Merkle-Damgard hashes over cores that buffer themselves ----------------

/// A hash over a core that keeps its own buffer and length: `initFn` starts
/// it, `updateFn` absorbs, `finalFn` writes `full` bytes, of which the first
/// `digest` are the digest.
fn Buffered(
    comptime State: type,
    comptime block: usize,
    comptime full: usize,
    comptime digest: usize,
    comptime initFn: fn (*State) void,
    comptime updateFn: fn (*State, []const u8) void,
    comptime finalFn: fn (*State, *[full]u8) void,
) type {
    return struct {
        const Self = @This();
        pub const block_length = block;
        pub const digest_length = digest;
        pub const Options = struct {};

        st: State,

        pub fn init(options: Options) Self {
            _ = options;
            var self: Self = undefined;
            initFn(&self.st);
            return self;
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            updateFn(&self.st, data);
        }

        pub fn final(self: *Self, out: *[digest_length]u8) void {
            var buf: [full]u8 = undefined;
            finalFn(&self.st, &buf);
            out.* = buf[0..digest].*;
            std.crypto.secureZero(u8, &buf);
            wipe(&self.st);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// MD2 (RFC 1319).
pub const Md2 = Buffered(md2.State, md2.block_len, md2.digest_len, md2.digest_len, struct {
    fn f(st: *md2.State) void {
        md2.init(st, md2.default_rounds);
    }
}.f, md2.update, md2.final);

/// MD4 (RFC 1320).
pub const Md4 = Buffered(md4.State, md4.block_len, md4.digest_len, md4.digest_len, struct {
    fn f(st: *md4.State) void {
        md4.init(st, 0);
    }
}.f, md4.update, md4.final);

/// MD5 (RFC 1321).
pub const Md5 = Buffered(md5.State, md5.block_len, md5.digest_len, md5.digest_len, md5.init, md5.update, md5.final);

fn ShaOne(comptime variant: sha1.Variant) type {
    return Buffered(sha1.State, sha1.block_len, sha1.digest_len, sha1.digest_len, struct {
        fn f(st: *sha1.State) void {
            sha1.init(st, sha1.max_rounds);
        }
    }.f, struct {
        fn f(st: *sha1.State, data: []const u8) void {
            sha1.update(variant, st, data);
        }
    }.f, struct {
        fn f(st: *sha1.State, out: *[sha1.digest_len]u8) void {
            sha1.final(variant, st, out);
        }
    }.f);
}

/// SHA-0, the 1993 version of SHA-1 (FIPS 180).
pub const Sha0 = ShaOne(.sha0);
/// SHA-1 (FIPS 180-4).
pub const Sha1 = ShaOne(.sha1);

fn Sha2x32(comptime bits: u32) type {
    return Buffered(sha256.State, sha256.block_len, sha256.digest_len, bits / 8, struct {
        fn f(st: *sha256.State) void {
            sha256.init(st, bits, sha256.max_rounds);
        }
    }.f, sha256.update, sha256.final);
}

/// SHA-224 (FIPS 180-4).
pub const Sha224 = Sha2x32(224);
/// SHA-256 (FIPS 180-4).
pub const Sha256 = Sha2x32(256);

fn Sha2x64(comptime iv_bits: u32, comptime bits: u32) type {
    return Buffered(sha512.State, sha512.block_len, sha512.digest_len, bits / 8, struct {
        fn f(st: *sha512.State) void {
            sha512.init(st, iv_bits, sha512.max_rounds);
        }
    }.f, sha512.update, sha512.final);
}

/// SHA-384 (FIPS 180-4).
pub const Sha384 = Sha2x64(384, 384);
/// SHA-512 (FIPS 180-4).
pub const Sha512 = Sha2x64(512, 512);
/// SHA-512/224 (FIPS 180-4).
pub const Sha512_224 = Sha2x64(224, 224);
/// SHA-512/256 (FIPS 180-4).
pub const Sha512_256 = Sha2x64(256, 256);

/// SM3 (GB/T 32905-2016).
pub const Sm3 = Buffered(sm3.State, sm3.block_len, sm3.digest_len, sm3.digest_len, struct {
    fn f(st: *sm3.State) void {
        sm3.init(st, sm3.max_rounds);
    }
}.f, sm3.update, sm3.final);

/// HAS-160 (TTAS.KO-12.0011/R2).
pub const Has160 = Buffered(has160.State, has160.block_len, has160.digest_len, has160.digest_len, struct {
    fn f(st: *has160.State) void {
        has160.init(st, has160.default_rounds);
    }
}.f, has160.update, has160.final);

fn RipemdOf(comptime C: type) type {
    return Buffered(C.State, ripemd.block_len, C.digest_len, C.digest_len, struct {
        fn f(st: *C.State) void {
            C.init(st, 0);
        }
    }.f, C.update, C.final);
}

/// RIPEMD-128.
pub const Ripemd128 = RipemdOf(ripemd.Ripemd128);
/// RIPEMD-160.
pub const Ripemd160 = RipemdOf(ripemd.Ripemd160);
/// RIPEMD-256.
pub const Ripemd256 = RipemdOf(ripemd.Ripemd256);
/// RIPEMD-320.
pub const Ripemd320 = RipemdOf(ripemd.Ripemd320);

fn WhirlpoolOf(comptime C: type) type {
    return Buffered(whirlpool.State, whirlpool.block_len, whirlpool.digest_len, whirlpool.digest_len, struct {
        fn f(st: *whirlpool.State) void {
            C.init(st, whirlpool.max_rounds);
        }
    }.f, C.update, C.final);
}

/// Whirlpool (ISO/IEC 10118-3:2004), the final version.
pub const Whirlpool = WhirlpoolOf(whirlpool.whirlpool);
/// Whirlpool-0, the original 2000 submission.
pub const Whirlpool0 = WhirlpoolOf(whirlpool.whirlpool0);
/// Whirlpool-T, the 2001 revision with the new S-box.
pub const WhirlpoolT = WhirlpoolOf(whirlpool.whirlpoolT);

// ---- Snefru -------------------------------------------------------------------

/// Snefru (Merkle, 1990, version 2.5 S-boxes) with a `bits`-bit digest (32 to
/// 448 in steps of 32) and `passes` passes (1 to 8). The usual variants are
/// `Snefru128` and `Snefru256`, which use 8 passes.
pub fn Snefru(comptime bits: u32, comptime passes: u8) type {
    if (bits % 32 != 0 or bits < 32 or bits > 448) @compileError("Snefru digest size must be 32 to 448 bits in steps of 32");
    if (passes < 1 or passes > snefru.max_rounds) @compileError("Snefru passes must be 1 to 8");
    const words: u8 = bits / 32;
    const bl = (16 - @as(usize, words)) * 4;
    return struct {
        const Self = @This();
        pub const block_length = bl;
        pub const digest_length = bits / 8;
        pub const Options = struct {};

        st: snefru.State,
        /// The core counts bytes modulo 2^32; the length field needs all 64 bits.
        total: u64,

        pub fn init(options: Options) Self {
            _ = options;
            var self: Self = undefined;
            snefru.init(&self.st, words, passes);
            self.total = 0;
            return self;
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            snefru.update(&self.st, data);
            self.total +%= data.len;
        }

        pub fn final(self: *Self, out: *[digest_length]u8) void {
            const st = &self.st;
            var block: [bl]u8 = @splat(0);
            const n: usize = st.buffered;
            if (n > 0) {
                @memcpy(block[0..n], st.buf[0..n]);
                snefru.compress(&st.hash, words, &block, passes);
                @memset(block[0..n], 0);
            }
            std.mem.writeInt(u64, block[bl - 8 ..][0..8], self.total *% 8, .big);
            snefru.compress(&st.hash, words, &block, passes);
            for (0..words) |i| std.mem.writeInt(u32, out[i * 4 ..][0..4], st.hash[i], .big);
            std.crypto.secureZero(u8, &block);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// Snefru-128, 8 passes.
pub const Snefru128 = Snefru(128, 8);
/// Snefru-256, 8 passes.
pub const Snefru256 = Snefru(256, 8);

// ---- hashes whose cores keep the last block for `final` -----------------------

/// Buffers input for a core whose `blocks` takes whole blocks and whose
/// `final` takes the last 0..block bytes. The buffer is only compressed once
/// more input follows, so `final` always sees the end of the message.
fn HoldBack(comptime block: usize) type {
    return struct {
        const Self = @This();
        buf: [block]u8 = undefined,
        n: usize = 0,

        fn feed(self: *Self, st: anytype, comptime blocksFn: anytype, data: []const u8) void {
            var rest = data;
            while (rest.len > 0) {
                if (self.n == block) {
                    blocksFn(st, &self.buf);
                    self.n = 0;
                }
                if (self.n == 0 and rest.len > block) {
                    const whole = (rest.len - 1) / block * block;
                    blocksFn(st, rest[0..whole]);
                    rest = rest[whole..];
                    continue;
                }
                const take = @min(block - self.n, rest.len);
                @memcpy(self.buf[self.n..][0..take], rest[0..take]);
                self.n += take;
                rest = rest[take..];
            }
        }

        fn tail(self: *const Self) []const u8 {
            return self.buf[0..self.n];
        }
    };
}

/// A hash over a hold-back core with no options.
fn Tailed(comptime C: type, comptime digest: usize) type {
    return struct {
        const Self = @This();
        pub const block_length = C.block_len;
        pub const digest_length = digest;
        pub const Options = struct {};

        st: C.State,
        buf: HoldBack(C.block_len),

        pub fn init(options: Options) Self {
            _ = options;
            var self: Self = .{ .st = undefined, .buf = .{} };
            C.init(&self.st);
            return self;
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.buf.feed(&self.st, C.blocks, data);
        }

        pub fn final(self: *Self, out: *[digest_length]u8) void {
            var full: [C.digest_len]u8 = undefined;
            C.final(&self.st, self.buf.tail(), &full);
            out.* = full[0..digest].*;
            std.crypto.secureZero(u8, &full);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// Tiger (Anderson and Biham, 1995), 192-bit digest.
pub const Tiger = Tailed(tiger.Tiger, 24);
/// Tiger/160: the first 160 bits of Tiger.
pub const Tiger160 = Tailed(tiger.Tiger, 20);
/// Tiger/128: the first 128 bits of Tiger.
pub const Tiger128 = Tailed(tiger.Tiger, 16);
/// Tiger2: Tiger with the padding byte 0x80, 192-bit digest.
pub const Tiger2 = Tailed(tiger.Tiger2, 24);

/// Streebog-256 (GOST R 34.11-2012, RFC 6986).
pub const Streebog256 = Tailed(streebog.Streebog256, 32);
/// Streebog-512 (GOST R 34.11-2012, RFC 6986).
pub const Streebog512 = Tailed(streebog.Streebog512, 64);

/// CRC-32 (ISO-HDLC, as used by zlib, PNG and Ethernet), written most
/// significant byte first. A checksum, not a cryptographic hash.
pub const Crc32 = Tailed(crc32.Crc32, 4);
/// CRC-32C (Castagnoli, as used by iSCSI and ext4), written most significant
/// byte first. A checksum, not a cryptographic hash.
pub const Crc32c = Tailed(crc32.Crc32c, 4);

fn XxHash(comptime C: type, comptime Seed: type) type {
    return struct {
        const Self = @This();
        pub const block_length = C.block_len;
        pub const digest_length = C.digest_len;
        pub const Options = struct { seed: Seed = 0 };

        st: C.State,
        buf: HoldBack(C.block_len),

        pub fn init(options: Options) Self {
            var self: Self = .{ .st = undefined, .buf = .{} };
            C.init(&self.st, options.seed);
            return self;
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.buf.feed(&self.st, C.blocks, data);
        }

        /// Writes the digest in the byte order of the type (see its doc comment).
        pub fn final(self: *Self, out: *[digest_length]u8) void {
            C.final(&self.st, self.buf.tail(), out);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// XXH32 with an optional 32-bit seed. A checksum, not a cryptographic hash.
pub const XxHash32 = XxHash(xxhash.Xxh32, u32);
/// XXH64 with an optional 64-bit seed. A checksum, not a cryptographic hash.
pub const XxHash64 = XxHash(xxhash.Xxh64, u64);

/// Like `HoldBack`, but once a block has been compressed at least `keep`
/// bytes stay behind it, so the tail is `keep` to `block + keep - 1` bytes.
fn HoldBackKeep(comptime block: usize, comptime keep: usize) type {
    return struct {
        const Self = @This();
        const cap = block + keep - 1;
        buf: [cap]u8 = undefined,
        n: usize = 0,

        fn feed(self: *Self, st: anytype, comptime blocksFn: anytype, data: []const u8) void {
            var rest = data;
            while (rest.len > 0) {
                if (self.n == cap) {
                    blocksFn(st, self.buf[0..block]);
                    std.mem.copyForwards(u8, self.buf[0 .. cap - block], self.buf[block..cap]);
                    self.n = cap - block;
                }
                if (self.n == 0 and rest.len > cap) {
                    const whole = (rest.len - keep) / block * block;
                    blocksFn(st, rest[0..whole]);
                    rest = rest[whole..];
                    continue;
                }
                const take = @min(cap - self.n, rest.len);
                @memcpy(self.buf[self.n..][0..take], rest[0..take]);
                self.n += take;
                rest = rest[take..];
            }
        }

        fn tail(self: *const Self) []const u8 {
            return self.buf[0..self.n];
        }
    };
}

fn Xxh3Of(comptime C: type) type {
    return struct {
        const Self = @This();
        pub const block_length = C.block_len;
        pub const digest_length = C.digest_len;
        pub const Options = struct { seed: u64 = 0 };

        st: C.State,
        buf: HoldBackKeep(C.block_len, C.keep_len),

        pub fn init(options: Options) Self {
            var self: Self = .{ .st = undefined, .buf = .{} };
            C.init(&self.st, options.seed);
            return self;
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.buf.feed(&self.st, C.blocks, data);
        }

        /// Writes the hash most significant byte first (the canonical form).
        pub fn final(self: *Self, out: *[digest_length]u8) void {
            C.final(&self.st, self.buf.tail(), out);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// XXH3, 64-bit (`XXH3_64bits_withSeed`), with an optional 64-bit seed. A
/// checksum, not a cryptographic hash.
pub const XxHash3 = Xxh3Of(xxh3.Xxh3_64);
/// XXH3, 128-bit (`XXH3_128bits_withSeed`, XXH128), with an optional 64-bit
/// seed; the high 64 bits come first. A checksum, not a cryptographic hash.
pub const XxHash128 = Xxh3Of(xxh3.Xxh3_128);

fn SipHashOf(comptime C: type) type {
    return struct {
        const Self = @This();
        pub const block_length = C.block_len;
        pub const digest_length = C.digest_len;
        pub const key_length = siphash.key_len;
        /// `key` is required; it should be random and secret.
        pub const Options = struct { key: [key_length]u8 };

        st: C.State,
        buf: HoldBack(C.block_len),

        pub fn init(options: Options) Self {
            var self: Self = .{ .st = undefined, .buf = .{} };
            C.init(&self.st, &options.key);
            return self;
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.buf.feed(&self.st, C.blocks, data);
        }

        /// Writes the 64-bit result least significant byte first, as the
        /// reference implementation and `std.crypto.auth.siphash` do.
        pub fn final(self: *Self, out: *[digest_length]u8) void {
            C.final(&self.st, self.buf.tail(), out);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// SipHash-2-4 with a 128-bit key and a 64-bit output: a keyed hash for hash
/// tables that face untrusted input. Not a general-purpose MAC.
pub const SipHash24 = SipHashOf(siphash.SipHash24);
/// SipHash-1-3, the variant used by the hash tables of Rust and Python.
pub const SipHash13 = SipHashOf(siphash.SipHash13);

/// MurmurHash3 x86_32 with an optional 32-bit seed, written most significant
/// byte first. A checksum, not a cryptographic hash.
pub const Murmur3_32 = XxHash(murmur3.X86_32, u32);
/// MurmurHash3 x64_128 with an optional 32-bit seed, in the byte order of the
/// reference implementation (h1 then h2, each least significant byte first).
/// A checksum, not a cryptographic hash.
pub const Murmur3_128 = XxHash(murmur3.X64_128, u32);

// ---- BLAKE2 ---------------------------------------------------------------------

fn Blake2Of(comptime C: type, comptime out_bits: u16) type {
    if (out_bits % 8 != 0 or out_bits < 8 or out_bits > C.digest_len * 8)
        @compileError(std.fmt.comptimePrint("BLAKE2 digest size must be 8 to {d} bits in steps of 8", .{C.digest_len * 8}));
    return struct {
        const Self = @This();
        pub const block_length = C.block_len;
        pub const digest_length = out_bits / 8;
        pub const key_length_max = C.key_len_max;
        pub const salt_length = C.param_len;
        pub const context_length = C.param_len;

        /// `key` is at most `key_length_max` bytes; `salt` and `context` (the
        /// personalization string) at most `salt_length` bytes each, zero
        /// padded. Longer values panic.
        pub const Options = struct {
            key: ?[]const u8 = null,
            salt: ?[]const u8 = null,
            context: ?[]const u8 = null,
        };

        st: C.State,
        buf: HoldBack(C.block_len),

        pub fn init(options: Options) Self {
            const key = options.key orelse "";
            const salt = options.salt orelse "";
            const context = options.context orelse "";
            if (key.len > key_length_max) @panic("BLAKE2 key too long");
            if (salt.len > salt_length) @panic("BLAKE2 salt too long");
            if (context.len > context_length) @panic("BLAKE2 context too long");
            var self: Self = .{ .st = undefined, .buf = .{} };
            C.init(&self.st, digest_length, @intCast(key.len), salt, context);
            if (key.len > 0) {
                // The key, zero padded to one block, is the first block of the message.
                var block: [block_length]u8 = @splat(0);
                @memcpy(block[0..key.len], key);
                self.update(&block);
                std.crypto.secureZero(u8, &block);
            }
            return self;
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.buf.feed(&self.st, C.blocks, data);
        }

        pub fn final(self: *Self, out: *[digest_length]u8) void {
            var full: [C.digest_len]u8 = undefined;
            C.final(&self.st, self.buf.tail(), &full);
            out.* = full[0..digest_length].*;
            std.crypto.secureZero(u8, &full);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// BLAKE2b (RFC 7693) with an `out_bits`-bit digest (8 to 512).
pub fn Blake2b(comptime out_bits: u16) type {
    return Blake2Of(blake2.Blake2b, out_bits);
}
/// BLAKE2s (RFC 7693) with an `out_bits`-bit digest (8 to 256).
pub fn Blake2s(comptime out_bits: u16) type {
    return Blake2Of(blake2.Blake2s, out_bits);
}
pub const Blake2b128 = Blake2b(128);
pub const Blake2b160 = Blake2b(160);
pub const Blake2b256 = Blake2b(256);
pub const Blake2b384 = Blake2b(384);
pub const Blake2b512 = Blake2b(512);
pub const Blake2s128 = Blake2s(128);
pub const Blake2s160 = Blake2s(160);
pub const Blake2s224 = Blake2s(224);
pub const Blake2s256 = Blake2s(256);

// ---- BLAKE3 ---------------------------------------------------------------------

/// BLAKE3: plain and keyed hashing, key derivation, and output of any length.
pub const Blake3 = struct {
    const Self = @This();
    pub const block_length = blake3.block_len;
    /// The default output length. `final` writes as many bytes as `out` holds.
    pub const digest_length = 32;
    pub const key_length = 32;

    /// With `key`, the keyed hash mode.
    pub const Options = struct { key: ?[key_length]u8 = null };

    st: blake3.State,
    stack: blake3.Stack,
    buf: [blake3.chunk_len]u8,
    n: usize,

    fn begin(key: [8]u32, flags: u32) Self {
        var self: Self = undefined;
        self.st = .{ .key = key, .flags = flags, ._reserved = 0, .chunks = 0 };
        self.n = 0;
        return self;
    }

    fn keyWords(key: *const [key_length]u8) [8]u32 {
        var w: [8]u32 = undefined;
        for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, key[i * 4 ..][0..4], .little);
        return w;
    }

    pub fn init(options: Options) Self {
        if (options.key) |key| {
            var w = keyWords(&key);
            defer std.crypto.secureZero(u32, &w);
            return begin(w, blake3.flag_keyed_hash);
        }
        return begin(blake3.iv, 0);
    }

    /// The key derivation mode: `context` should be a hardcoded, globally
    /// unique string that names the application and purpose. Feed the key
    /// material with `update`.
    pub fn initKdf(context: []const u8) Self {
        var ctx = begin(blake3.iv, blake3.flag_derive_key_context);
        ctx.update(context);
        var key: [key_length]u8 = undefined;
        ctx.final(&key);
        var w = keyWords(&key);
        std.crypto.secureZero(u8, &key);
        defer std.crypto.secureZero(u32, &w);
        return begin(w, blake3.flag_derive_key_material);
    }

    /// Hash `data` into `out`, which may have any length.
    pub fn hash(data: []const u8, out: []u8, options: Options) void {
        var h = init(options);
        h.update(data);
        h.final(out);
    }

    pub fn update(self: *Self, data: []const u8) void {
        const cl = blake3.chunk_len;
        var rest = data;
        while (rest.len > 0) {
            if (self.n == cl) {
                blake3.update(&self.st, &self.stack, &self.buf);
                self.n = 0;
            }
            if (self.n == 0 and rest.len > cl) {
                const whole = (rest.len - 1) / cl * cl;
                blake3.update(&self.st, &self.stack, rest[0..whole]);
                rest = rest[whole..];
                continue;
            }
            const take = @min(cl - self.n, rest.len);
            @memcpy(self.buf[self.n..][0..take], rest[0..take]);
            self.n += take;
            rest = rest[take..];
        }
    }

    /// Write `out.len` bytes of output (32 is the standard digest length).
    pub fn final(self: *Self, out: []u8) void {
        var params = blake3.root(&self.st, &self.stack, self.buf[0..self.n]);
        blake3.xof(&params, 0, out);
        wipe(&params);
        wipe(self);
    }

    pub fn finalResult(self: *Self) [digest_length]u8 {
        var out: [digest_length]u8 = undefined;
        self.final(&out);
        return out;
    }
};

// ---- SHA-3, Keccak and SHAKE -----------------------------------------------------

/// A sponge over the Keccak-f[1600] core with the given rate and domain suffix.
fn Sponge(comptime rate: u32, comptime suffix: u8) type {
    return struct {
        const Self = @This();
        st: keccak.State,
        buf: [rate]u8,
        n: usize,

        fn init() Self {
            var self: Self = undefined;
            keccak.init(&self.st, rate);
            self.n = 0;
            return self;
        }

        fn update(self: *Self, data: []const u8) void {
            var rest = data;
            if (self.n > 0) {
                const take = @min(rate - self.n, rest.len);
                @memcpy(self.buf[self.n..][0..take], rest[0..take]);
                self.n += take;
                rest = rest[take..];
                if (self.n < rate) return;
                keccak.blocks(&self.st, &self.buf);
                self.n = 0;
            }
            const whole = rest.len - rest.len % rate;
            keccak.blocks(&self.st, rest[0..whole]);
            rest = rest[whole..];
            @memcpy(self.buf[0..rest.len], rest);
            self.n = rest.len;
        }

        fn final(self: *Self, out: []u8) void {
            keccak.final(&self.st, self.buf[0..self.n], suffix, out);
            std.crypto.secureZero(u8, &self.buf);
        }
    };
}

fn FixedSponge(comptime bits: u32, comptime suffix: u8) type {
    const rate = 200 - 2 * (bits / 8);
    return struct {
        const Self = @This();
        pub const block_length = rate;
        pub const digest_length = bits / 8;
        pub const Options = struct {};

        sponge: Sponge(rate, suffix),

        pub fn init(options: Options) Self {
            _ = options;
            return .{ .sponge = .init() };
        }

        pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.sponge.update(data);
        }

        pub fn final(self: *Self, out: *[digest_length]u8) void {
            self.sponge.final(out);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// SHA3-224 (FIPS 202).
pub const Sha3_224 = FixedSponge(224, keccak.suffix_sha3);
/// SHA3-256 (FIPS 202).
pub const Sha3_256 = FixedSponge(256, keccak.suffix_sha3);
/// SHA3-384 (FIPS 202).
pub const Sha3_384 = FixedSponge(384, keccak.suffix_sha3);
/// SHA3-512 (FIPS 202).
pub const Sha3_512 = FixedSponge(512, keccak.suffix_sha3);
/// Keccak-224 with the padding of the original submission.
pub const Keccak224 = FixedSponge(224, keccak.suffix_keccak);
/// Keccak-256 with the padding of the original submission (the "keccak256"
/// of Ethereum).
pub const Keccak256 = FixedSponge(256, keccak.suffix_keccak);
/// Keccak-384 with the padding of the original submission.
pub const Keccak384 = FixedSponge(384, keccak.suffix_keccak);
/// Keccak-512 with the padding of the original submission.
pub const Keccak512 = FixedSponge(512, keccak.suffix_keccak);

fn ShakeOf(comptime strength: u32) type {
    const rate = 200 - 2 * (strength / 8);
    return struct {
        const Self = @This();
        pub const block_length = rate;
        /// The output length `hash` and `finalResult` use: twice the strength.
        pub const digest_length = 2 * strength / 8;
        pub const Options = struct {};

        sponge: Sponge(rate, keccak.suffix_shake),

        pub fn init(options: Options) Self {
            _ = options;
            return .{ .sponge = .init() };
        }

        /// Hash `data` into `out`, which may have any length.
        pub fn hash(data: []const u8, out: []u8, options: Options) void {
            var h = init(options);
            h.update(data);
            h.final(out);
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.sponge.update(data);
        }

        /// End the input and write the first `out.len` bytes of output. More
        /// output follows with `squeeze`.
        pub fn final(self: *Self, out: []u8) void {
            self.sponge.final(out);
        }

        /// Continue the output after `final`.
        pub fn squeeze(self: *Self, out: []u8) void {
            keccak.squeeze(&self.sponge.st, out);
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// SHAKE128 (FIPS 202), output of any length.
pub const Shake128 = ShakeOf(128);
/// SHAKE256 (FIPS 202), output of any length.
pub const Shake256 = ShakeOf(256);

// ---- HMAC, PBKDF2, HKDF -------------------------------------------------------------

/// HMAC (RFC 2104) over any hash type of this module or of `std.crypto.hash`
/// with a fixed `digest_length`. The interface matches
/// `std.crypto.auth.hmac.Hmac`. Key material is wiped when no longer needed.
pub fn Hmac(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const mac_length = H.digest_length;
        pub const key_length_min = 0;
        pub const key_length = mac_length;

        inner: H,
        outer: H,

        pub fn create(out: *[mac_length]u8, msg: []const u8, key: []const u8) void {
            var ctx = init(key);
            ctx.update(msg);
            ctx.final(out);
        }

        pub fn init(key: []const u8) Self {
            var k: [H.block_length]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &k);
            if (key.len > H.block_length) {
                H.hash(key, k[0..mac_length], .{});
            } else {
                @memcpy(k[0..key.len], key);
            }
            var pad: [H.block_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &pad);
            var self: Self = .{ .inner = H.init(.{}), .outer = H.init(.{}) };
            for (&pad, k) |*p, b| p.* = b ^ 0x36;
            self.inner.update(&pad);
            for (&pad, k) |*p, b| p.* = b ^ 0x5c;
            self.outer.update(&pad);
            return self;
        }

        pub fn update(self: *Self, msg: []const u8) void {
            self.inner.update(msg);
        }

        pub fn final(self: *Self, out: *[mac_length]u8) void {
            var ih: [mac_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &ih);
            self.inner.final(&ih);
            self.outer.update(&ih);
            self.outer.final(out);
            wipe(self);
        }

        pub fn finalResult(self: *Self) [mac_length]u8 {
            var out: [mac_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

/// PBKDF2 (RFC 8018) with HMAC over the hash type `H`. Fills `dk`.
/// Fails with `error.WeakParameters` when `rounds` is 0 and with
/// `error.OutputTooLong` when `dk` is longer than the standard allows.
pub fn pbkdf2(dk: []u8, password: []const u8, salt: []const u8, rounds: u32, comptime H: type) (std.crypto.errors.WeakParametersError || std.crypto.errors.OutputTooLongError)!void {
    return std.crypto.pwhash.pbkdf2(dk, password, salt, rounds, Hmac(H));
}

/// HKDF (RFC 5869) with HMAC over the hash type `H`: `extract`, `expand`,
/// as in `std.crypto.kdf.hkdf.Hkdf`.
pub fn Hkdf(comptime H: type) type {
    return std.crypto.kdf.hkdf.Hkdf(Hmac(H));
}

// ---- Password hashing: Argon2, scrypt -------------------------------------------------

/// Argon2d, Argon2i and Argon2id (RFC 9106, version 0x13), on one thread.
pub const argon2 = struct {
    pub const Mode = argon2_core.Mode;
    /// `t` passes, `m` KiB of memory, `p` lanes, and the optional `secret`
    /// (key K) and `ad` (associated data X).
    pub const Params = argon2_core.Params;
    pub const Error = argon2_core.Error || std.mem.Allocator.Error;

    /// Fill `derived_key` (4 bytes or more) with the Argon2 tag of `password`
    /// and `salt` (8 bytes or more). The memory matrix (`m` KiB, rounded down
    /// to a multiple of `4 * p` blocks) comes from `allocator` and is zeroed
    /// before it is freed. Fails with `error.WeakParameters` for parameters
    /// outside RFC 9106 (`t` 0, `m` below `8 * p`, a short salt or tag).
    pub fn kdf(allocator: std.mem.Allocator, derived_key: []u8, password: []const u8, salt: []const u8, params: Params, mode: Mode) Error!void {
        try argon2_core.check(derived_key.len, password.len, salt.len, params);
        const blocks = std.math.cast(usize, argon2_core.blockCount(params)) orelse return error.OutOfMemory;
        const memory = try allocator.alignedAlloc(argon2_core.Block, .@"16", blocks);
        defer allocator.free(memory);
        argon2_core.hash(derived_key, password, salt, params, mode, memory);
    }
};

/// scrypt (RFC 7914).
pub const scrypt = struct {
    /// `ln` is log2 of the cost N, `r` the block size, `p` the parallelization.
    pub const Params = scrypt_core.Params;
    pub const Error = scrypt_core.Error || std.mem.Allocator.Error;

    /// Fill `derived_key` with the scrypt key of `password` and `salt`. The
    /// work memory (about `128 * r * (2^ln + p)` bytes) comes from `allocator`
    /// and is zeroed before it is freed. Fails with `error.WeakParameters` for
    /// parameters outside RFC 7914 (`ln` 0, `2^ln` not below `2^(16 r)`,
    /// `r * p` of 2^30 or more, an empty key).
    pub fn kdf(allocator: std.mem.Allocator, derived_key: []u8, password: []const u8, salt: []const u8, params: Params) Error!void {
        try scrypt_core.check(derived_key.len, params);
        const words = scrypt_core.workWords(params) orelse return error.OutOfMemory;
        const work = try allocator.alignedAlloc(u32, .@"16", words);
        defer allocator.free(work);
        scrypt_core.hash(derived_key, password, salt, params, work);
    }
};

test {
    _ = @import("lib_test.zig");
}
