//! wasm root for the "tiger" family: Tiger and Tiger2 share the S-boxes and the
//! compression function, so one module serves both (`tiger_*` and `tiger2_*`
//! exports). Compiled to zig-out/wasm/tiger.wasm by build.zig. Export shape: see
//! blake2_exports.zig and docs/abi.md.

comptime {
    _ = @import("common.zig");
    const exports = @import("blake2_exports.zig");
    exports.exportHasher("tiger", @import("core").tiger.Tiger);
    exports.exportHasher("tiger2", @import("core").tiger.Tiger2);
}
