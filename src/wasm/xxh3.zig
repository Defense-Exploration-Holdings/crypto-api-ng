//! wasm root for the "xxh3" family: XXH3-64 and XXH3-128 (`xxh3_*` and `xxh128_*` exports).
//! Compiled to zig-out/wasm/xxh3.wasm by build.zig. Export shape: see blake2_exports.zig and
//! docs/abi.md.

comptime {
    _ = @import("common.zig");
    const exports = @import("blake2_exports.zig");
    exports.exportHasherScrub("xxh3", @import("core").xxh3.Xxh3_64, 1024);
    exports.exportHasherScrub("xxh128", @import("core").xxh3.Xxh3_128, 1024);
}
