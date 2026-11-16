//! BLAKE3 (hash, keyed hash and derive-key modes, with extendable output).
//!
//! A new algorithm (crypto-api 0.8.5 has no BLAKE), so no original to stay
//! compatible with. As for BLAKE2, the JS hasher owns buffering; wasm gets
//! whole chunks (`update`) and the last chunk (`root`), and produces output
//! bytes (`xof`):
//!
//!   * `update` hashes complete 1024-byte chunks into chaining values and
//!     merges them into the stack of subtree roots, exactly like the
//!     reference implementation's `add_chunk_chaining_value`.
//!   * `root` finishes the message: the last chunk (1..1024 bytes, or 0 for an
//!     empty message) and the parents above it. It writes the parameters of the
//!     root compression (`RootParams`), not output bytes, so output of any
//!     length can be produced from them.
//!   * `xof` writes output bytes from output block `seek` on.
//!
//! The JS hasher keeps the last chunk until `finalize()`, so a chunk is only
//! added to the tree once more input follows, as the reference does.

const std = @import("std");

pub const block_len = 64;
pub const chunk_len = 1024;
/// A message of 2^64 bytes has 2^54 chunks, so at most 54 entries are pending.
pub const max_depth = 54;
pub const out_block_len = 64;

pub const flag_chunk_start: u32 = 1;
pub const flag_chunk_end: u32 = 2;
pub const flag_parent: u32 = 4;
pub const flag_root: u32 = 8;
pub const flag_keyed_hash: u32 = 16;
pub const flag_derive_key_context: u32 = 32;
pub const flag_derive_key_material: u32 = 64;

pub const iv = [8]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/// Layout is part of the wasm ABI (see packages/crypto-api/src/hasher/blake3.mjs);
/// a change bumps `runtime.abi_version`.
pub const State = extern struct {
    /// The key words: the IV for plain hashing, the key for keyed hashing, the
    /// hash of the context string for key derivation.
    key: [8]u32,
    /// Flags every compression in this hash carries: 0, `flag_keyed_hash` or
    /// `flag_derive_key_material` (or `flag_derive_key_context` while hashing
    /// the context string itself).
    flags: u32,
    _reserved: u32,
    /// Complete chunks added to the tree so far.
    chunks: u64,

    comptime {
        std.debug.assert(@sizeOf(State) == 48);
        std.debug.assert(@offsetOf(State, "flags") == 32);
        std.debug.assert(@offsetOf(State, "chunks") == 40);
    }
};

/// The stack of chaining values of finished subtrees: `popcount(chunks)`
/// entries, the oldest (largest subtree) first.
pub const Stack = [max_depth][8]u32;

/// The parameters of the root compression. Output block `i` is
/// `compress(cv, block, i, block_len, flags | root)`.
pub const RootParams = extern struct {
    cv: [8]u32,
    block: [block_len]u8,
    block_len: u32,
    flags: u32,

    comptime {
        std.debug.assert(@sizeOf(RootParams) == 104);
    }
};

/// The schedule of message words for each of the 7 rounds.
const schedule = blk: {
    const perm = [16]u8{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };
    var s: [7][16]u8 = undefined;
    for (0..16) |i| s[0][i] = @intCast(i);
    for (1..7) |r| {
        for (0..16) |i| s[r][i] = s[r - 1][perm[i]];
    }
    break :blk s;
};

inline fn g(v: *[16]u32, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize, x: u32, y: u32) void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = std.math.rotr(u32, v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u32, v[b] ^ v[c], 12);
    v[a] = v[a] +% v[b] +% y;
    v[d] = std.math.rotr(u32, v[d] ^ v[a], 8);
    v[c] = v[c] +% v[d];
    v[b] = std.math.rotr(u32, v[b] ^ v[c], 7);
}

/// The compression function; returns all 16 output words (the first 8 are the
/// new chaining value).
pub fn compress(cv: *const [8]u32, block: *const [block_len]u8, counter: u64, len: u32, flags: u32) [16]u32 {
    var m: [16]u32 = undefined;
    for (&m, 0..) |*w, i| w.* = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);

    var v: [16]u32 = undefined;
    v[0..8].* = cv.*;
    v[8..12].* = iv[0..4].*;
    v[12] = @truncate(counter);
    v[13] = @truncate(counter >> 32);
    v[14] = len;
    v[15] = flags;

    inline for (0..7) |r| {
        const s = comptime schedule[r];
        g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    var out: [16]u32 = undefined;
    for (0..8) |i| {
        out[i] = v[i] ^ v[i + 8];
        out[i + 8] = v[i + 8] ^ cv[i];
    }
    return out;
}

/// The last compression of a chunk, not yet turned into a chaining value (it
/// becomes the root output when the chunk is the whole tree).
const ChunkEnd = struct {
    cv: [8]u32,
    block: [block_len]u8,
    block_len: u32,
    flags: u32,
    /// Chunk number for a chunk, 0 for a parent.
    counter: u64,

    fn chainingValue(self: *const ChunkEnd) [8]u32 {
        return compress(&self.cv, &self.block, self.counter, self.block_len, self.flags)[0..8].*;
    }
};

/// Hash `data` (0..chunk_len bytes) as chunk number `counter` up to, but not
/// including, the compression of its last block.
fn chunkEnd(st: *const State, data: []const u8, counter: u64) ChunkEnd {
    std.debug.assert(data.len <= chunk_len);
    var cv = st.key;
    var pos: usize = 0;
    var first: u32 = flag_chunk_start;
    // All blocks but the last.
    while (data.len - pos > block_len) : (pos += block_len) {
        cv = compress(&cv, data[pos..][0..block_len], counter, block_len, st.flags | first)[0..8].*;
        first = 0;
    }
    var block: [block_len]u8 = @splat(0);
    const rest = data.len - pos;
    @memcpy(block[0..rest], data[pos..]);
    return .{ .cv = cv, .block = block, .block_len = @intCast(rest), .flags = st.flags | first | flag_chunk_end, .counter = counter };
}

fn parentBlock(left: *const [8]u32, right: *const [8]u32) [block_len]u8 {
    var block: [block_len]u8 = undefined;
    for (left, 0..) |w, i| std.mem.writeInt(u32, block[i * 4 ..][0..4], w, .little);
    for (right, 0..) |w, i| std.mem.writeInt(u32, block[32 + i * 4 ..][0..4], w, .little);
    return block;
}

fn parentCv(st: *const State, left: *const [8]u32, right: *const [8]u32) [8]u32 {
    var block = parentBlock(left, right);
    defer std.crypto.secureZero(u8, &block);
    return compress(&st.key, &block, 0, block_len, st.flags | flag_parent)[0..8].*;
}

/// Add `nchunks` complete chunks (`data.len == nchunks * chunk_len`) to the
/// tree. `st.chunks` must stay below 2^53 (so the stack cannot overflow); the
/// caller guarantees that more input follows these chunks.
pub fn update(st: *State, stack: *Stack, data: []const u8) void {
    std.debug.assert(data.len % chunk_len == 0);
    var pos: usize = 0;
    while (pos < data.len) : (pos += chunk_len) {
        var end = chunkEnd(st, data[pos..][0..chunk_len], st.chunks);
        var cv = end.chainingValue();
        // The last block of the chunk (message bytes) and the key words it was started from.
        std.crypto.secureZero(u8, std.mem.asBytes(&end));
        st.chunks += 1;
        // Merge finished pairs: one parent for every trailing zero bit of the count.
        var total = st.chunks;
        var depth: usize = @popCount(st.chunks - 1);
        while (total & 1 == 0) : (total >>= 1) {
            depth -= 1;
            cv = parentCv(st, &stack[depth], &cv);
        }
        stack[depth] = cv;
        std.crypto.secureZero(u32, &cv);
    }
}

/// Finish the message with `tail`, its last chunk (1..chunk_len bytes; 0 only
/// when the whole message is empty), and return the parameters of the root
/// compression. Does not modify `st` or `stack`.
pub fn root(st: *const State, stack: *const Stack, tail: []const u8) RootParams {
    var end = chunkEnd(st, tail, st.chunks);
    var depth: usize = @popCount(st.chunks);
    while (depth > 0) {
        depth -= 1;
        const right = end.chainingValue();
        end = .{
            .cv = st.key,
            .block = parentBlock(&stack[depth], &right),
            .block_len = block_len,
            .flags = st.flags | flag_parent,
            .counter = 0,
        };
    }
    const params: RootParams = .{ .cv = end.cv, .block = end.block, .block_len = end.block_len, .flags = end.flags };
    std.crypto.secureZero(u8, std.mem.asBytes(&end));
    return params;
}

/// Write output bytes `[seek * 64, seek * 64 + out.len)` of the extendable
/// output of the hash that produced `params`.
pub fn xof(params: *const RootParams, seek: u64, out: []u8) void {
    var counter = seek;
    var pos: usize = 0;
    while (pos < out.len) : (counter += 1) {
        const words = compress(&params.cv, &params.block, counter, params.block_len, params.flags | flag_root);
        var bytes: [out_block_len]u8 = undefined;
        for (words, 0..) |w, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], w, .little);
        const n = @min(out_block_len, out.len - pos);
        @memcpy(out[pos..][0..n], bytes[0..n]);
        pos += n;
    }
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

/// What `State` holds at the start of a hash.
fn begin(key: ?[32]u8, context: ?[]const u8) State {
    var st = State{ .key = iv, .flags = 0, ._reserved = 0, .chunks = 0 };
    if (key) |k| {
        for (&st.key, 0..) |*w, i| w.* = std.mem.readInt(u32, k[i * 4 ..][0..4], .little);
        st.flags = flag_keyed_hash;
    }
    if (context) |c| {
        var ctx = State{ .key = iv, .flags = flag_derive_key_context, ._reserved = 0, .chunks = 0 };
        var out: [32]u8 = undefined;
        hashAll(&ctx, c, &out, 0);
        for (&st.key, 0..) |*w, i| w.* = std.mem.readInt(u32, out[i * 4 ..][0..4], .little);
        st.flags = flag_derive_key_material;
    }
    return st;
}

/// Hash `message` the way the JS hasher drives the core: whole chunks go to
/// `update` only while more input follows; the rest is the tail. The input is
/// handed over in `step`-sized pieces (0 = in one piece) to test buffering.
fn hashAll(st: *State, message: []const u8, out: []u8, step: usize) void {
    var stack: Stack = undefined;
    var buf: [2 * chunk_len]u8 = undefined;
    var buffered: usize = 0;
    var rest = message;
    const piece = if (step == 0) @max(message.len, 1) else step;
    while (rest.len > 0) {
        const take = @min(piece, rest.len);
        // The buffer never holds more than chunk_len + (the previous remainder).
        var give = rest[0..take];
        while (give.len > 0) {
            const room = buf.len - buffered;
            const n = @min(room, give.len);
            @memcpy(buf[buffered..][0..n], give[0..n]);
            buffered += n;
            give = give[n..];
            if (buffered > chunk_len) {
                const full = (buffered - 1) / chunk_len * chunk_len;
                update(st, &stack, buf[0..full]);
                std.mem.copyForwards(u8, buf[0 .. buffered - full], buf[full..buffered]);
                buffered -= full;
            }
        }
        rest = rest[take..];
    }
    const params = root(st, &stack, buf[0..buffered]);
    xof(&params, 0, out);
}

fn fill(buf: []u8, seed: u8) void {
    var x: u32 = @as(u32, seed) *% 2654435761 +% 12345;
    for (buf) |*b| {
        x = x *% 1664525 +% 1013904223;
        b.* = @truncate(x >> 24);
    }
}

test "state and root layouts" {
    try testing.expectEqual(@as(usize, 48), @sizeOf(State));
    try testing.expectEqual(@as(usize, 104), @sizeOf(RootParams));
    try testing.expectEqual(@as(usize, 1728), @sizeOf(Stack));
}

test "schedule matches the reference permutation" {
    // Round 1 of the reference: m[perm[i]] with perm = 2 6 3 10 7 0 4 13 1 11 12 5 9 14 15 8.
    try testing.expectEqualSlices(u8, &.{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 }, &schedule[1]);
    try testing.expectEqualSlices(u8, &.{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 }, &schedule[2]);
}

test "empty input" {
    var st = begin(null, null);
    var out: [32]u8 = undefined;
    hashAll(&st, "", &out, 0);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    try testing.expectEqualSlices(u8, &want, &out);
}

test "matches std.crypto in hash, keyed and derive-key modes, any split and output length" {
    var msg: [8 * chunk_len + 100]u8 = undefined;
    fill(&msg, 3);
    var key: [32]u8 = undefined;
    fill(&key, 5);
    const context = "crypto-api-ng test context";

    const lengths = [_]usize{ 0, 1, 2, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 3073, 4096, 4097, 7 * 1024, 7 * 1024 + 1, 8 * 1024, msg.len };
    for (lengths) |len| {
        for ([_]usize{ 0, 1, 63, 64, 1000, 1024, 1025, 5000 }) |step| {
            for ([_]usize{ 32, 131, 64, 200 }) |out_len| {
                var want: [200]u8 = undefined;
                var got: [200]u8 = undefined;

                Blake3.hash(msg[0..len], want[0..out_len], .{});
                var st = begin(null, null);
                hashAll(&st, msg[0..len], got[0..out_len], step);
                try testing.expectEqualSlices(u8, want[0..out_len], got[0..out_len]);

                Blake3.hash(msg[0..len], want[0..out_len], .{ .key = key });
                st = begin(key, null);
                hashAll(&st, msg[0..len], got[0..out_len], step);
                try testing.expectEqualSlices(u8, want[0..out_len], got[0..out_len]);

                var kdf = Blake3.initKdf(context, .{});
                kdf.update(msg[0..len]);
                kdf.final(want[0..out_len]);
                st = begin(null, context);
                hashAll(&st, msg[0..len], got[0..out_len], step);
                try testing.expectEqualSlices(u8, want[0..out_len], got[0..out_len]);
            }
        }
    }
}

test "a context longer than one chunk matches std.crypto" {
    var context: [2500]u8 = undefined;
    fill(&context, 17);
    var want: [64]u8 = undefined;
    var got: [64]u8 = undefined;
    var kdf = Blake3.initKdf(&context, .{});
    kdf.update("key material");
    kdf.final(&want);
    var st = begin(null, &context);
    hashAll(&st, "key material", &got, 0);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "xof seek gives the same bytes as a long read" {
    var msg: [3000]u8 = undefined;
    fill(&msg, 8);
    var st = begin(null, null);
    var long: [64 * 7 + 5]u8 = undefined;
    hashAll(&st, &msg, &long, 0);

    var st2 = begin(null, null);
    var stack: Stack = undefined;
    update(&st2, &stack, msg[0..2048]);
    const params = root(&st2, &stack, msg[2048..]);
    var piece: [64 * 3]u8 = undefined;
    xof(&params, 2, &piece);
    try testing.expectEqualSlices(u8, long[128..][0..piece.len], &piece);
}

const Blake3 = std.crypto.hash.Blake3;
