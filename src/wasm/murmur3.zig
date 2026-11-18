//! wasm root for the "murmur3" family: MurmurHash3 x86_32 and x64_128 (`murmur3_32_*` and
//! `murmur3_128_*` exports). Compiled to zig-out/wasm/murmur3.wasm by build.zig. Export shape: see
//! blake2_exports.zig and docs/abi.md.

comptime {
    _ = @import("common.zig");
    const exports = @import("blake2_exports.zig");
    exports.exportHasherScrub("murmur3_32", @import("core").murmur3.X86_32, 512);
    exports.exportHasherScrub("murmur3_128", @import("core").murmur3.X64_128, 512);
}
