//! crypto-api-ng core library root.
//!
//! Everything here is target-agnostic Zig: no wasm-specific code, no OS calls.
//! Algorithm modules are added alongside `runtime` and re-exported from here so
//! `zig build test` (native) covers them. The wasm export surface lives in
//! `wasm.zig`.

pub const runtime = @import("runtime.zig");
pub const md5 = @import("hash/md5.zig");
pub const be32 = @import("hash/be32.zig");
pub const sha1 = @import("hash/sha1.zig");
pub const sha256 = @import("hash/sha256.zig");
pub const sm3 = @import("hash/sm3.zig");
pub const sha512 = @import("hash/sha512.zig");

test {
    // Pull in tests from every module referenced above.
    @import("std").testing.refAllDecls(@This());
}
