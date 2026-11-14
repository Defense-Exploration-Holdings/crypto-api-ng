//! wasm root for the "has160" family. Compiled to zig-out/wasm/has160.wasm by
//! build.zig. Export shape: see le32_exports.zig and docs/abi.md.

comptime {
    _ = @import("common.zig");
    @import("le32_exports.zig").exportHasher("has160", @import("core").has160);
}
