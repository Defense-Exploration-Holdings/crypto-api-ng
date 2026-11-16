//! wasm root for the "crc32" family: CRC-32 and CRC-32C share the code and differ in a table,
//! so one module serves both (`crc32_*` and `crc32c_*` exports). Compiled to
//! zig-out/wasm/crc32.wasm by build.zig. Export shape: see blake2_exports.zig and docs/abi.md.

comptime {
    _ = @import("common.zig");
    const exports = @import("blake2_exports.zig");
    exports.exportHasherScrub("crc32", @import("core").crc32.Crc32, 256);
    exports.exportHasherScrub("crc32c", @import("core").crc32.Crc32c, 256);
}
