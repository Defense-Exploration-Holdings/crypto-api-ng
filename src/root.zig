//! crypto-api-ng core library root.
//!
//! Everything here is target-agnostic Zig: no wasm-specific code, no OS calls.
//! Algorithm modules are added alongside `runtime` and re-exported from here so
//! `zig build test` (native) covers them. The wasm export surface lives in
//! `wasm.zig`.

pub const runtime = @import("runtime.zig");

test {
    // Pull in tests from every module referenced above.
    @import("std").testing.refAllDecls(@This());
}
