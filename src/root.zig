//! crypto-api-ng core library root.
//!
//! Everything here is target-agnostic Zig: no wasm-specific code, no OS calls.
//! Algorithm modules are added alongside `runtime` and re-exported from here so
//! `zig build test` (native) covers them. The wasm export surface lives in
//! `wasm.zig`.

pub const runtime = @import("runtime.zig");
pub const md5 = @import("hash/md5.zig");
pub const le32 = @import("hash/le32.zig");
pub const md4 = @import("hash/md4.zig");
pub const has160 = @import("hash/has160.zig");
pub const ripemd = @import("hash/ripemd.zig");
pub const snefru = @import("hash/snefru.zig");

test {
    // Pull in tests from every module referenced above.
    @import("std").testing.refAllDecls(@This());
}
