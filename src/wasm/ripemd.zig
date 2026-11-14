//! wasm root for the "ripemd" family: RIPEMD-128, -160, -256 and -320 in one
//! module. Compiled to zig-out/wasm/ripemd.wasm by build.zig. Export shape:
//! see le32_exports.zig and docs/abi.md (prefixes `ripemd128`, `ripemd160`,
//! `ripemd256`, `ripemd320`).

comptime {
    _ = @import("common.zig");
    const ex = @import("le32_exports.zig");
    const r = @import("core").ripemd;
    ex.exportHasher("ripemd128", r.Ripemd128);
    ex.exportHasher("ripemd160", r.Ripemd160);
    ex.exportHasher("ripemd256", r.Ripemd256);
    ex.exportHasher("ripemd320", r.Ripemd320);
}
