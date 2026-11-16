//! wasm root for the "streebog" family: Streebog-256 and Streebog-512 share the tables and the
//! compression function, so one module serves both (`streebog256_*` and `streebog512_*`
//! exports). Compiled to zig-out/wasm/streebog.wasm by build.zig. Export shape: see
//! blake2_exports.zig and docs/abi.md.

comptime {
    _ = @import("common.zig");
    const exports = @import("blake2_exports.zig");
    // The compression keeps several 64-byte working values in its frames: the deepest call leaves about
    // 2.3 KiB (measured with test/memory-wipe.test.js: 2048 still leaks, 2560 does not), so clear over twice that.
    exports.exportHasherScrub("streebog256", @import("core").streebog.Streebog256, 6144);
    exports.exportHasherScrub("streebog512", @import("core").streebog.Streebog512, 6144);
}
