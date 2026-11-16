//! wasm root for the "xxhash" family: XXH32 and XXH64 (`xxhash32_*` and `xxhash64_*` exports).
//! Compiled to zig-out/wasm/xxhash.wasm by build.zig. Export shape: see blake2_exports.zig and
//! docs/abi.md.

comptime {
    _ = @import("common.zig");
    const exports = @import("blake2_exports.zig");
    exports.exportHasherScrub("xxhash32", @import("core").xxhash.Xxh32, 512);
    exports.exportHasherScrub("xxhash64", @import("core").xxhash.Xxh64, 512);
}
