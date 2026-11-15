//! wasm root for the "blake2b" family. Compiled to zig-out/wasm/blake2b.wasm by
//! build.zig. Export shape: see blake2_exports.zig and docs/abi.md.

comptime {
    _ = @import("common.zig");
    @import("blake2_exports.zig").exportHasher("blake2b", @import("core").blake2.Blake2b);
}
