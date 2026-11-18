//! wasm root for the "siphash" family: SipHash-2-4 and SipHash-1-3 (`siphash24_*` and
//! `siphash13_*` exports). Compiled to zig-out/wasm/siphash.wasm by build.zig. Export shape: see
//! blake2_exports.zig and docs/abi.md.

comptime {
    _ = @import("common.zig");
    const exports = @import("blake2_exports.zig");
    exports.exportHasherScrub("siphash24", @import("core").siphash.SipHash24, 512);
    exports.exportHasherScrub("siphash13", @import("core").siphash.SipHash13, 512);
}
