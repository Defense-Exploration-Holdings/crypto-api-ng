//! Runtime conventions shared by all algorithm ports.
//!
//! See docs/abi.md for the JS <-> wasm calling convention.

const std = @import("std");

/// Bump this whenever the exported wasm ABI changes incompatibly. The JS loader
/// refuses to run against a module whose ABI version differs from its own.
pub const abi_version: u32 = 2;

/// Library version, kept in sync with package.json by hand until a release
/// script exists.
pub const version = "0.0.0";

/// Status codes returned by exported functions that can fail. Zero is success.
/// Non-zero values are stable once released.
pub const Status = enum(i32) {
    ok = 0,
    invalid_argument = 1,
    out_of_memory = 2,
    invalid_state = 3,
    _,
};

test "abi_version is non-zero" {
    try std.testing.expect(abi_version != 0);
}

test "Status.ok is zero" {
    try std.testing.expectEqual(@as(i32, 0), @intFromEnum(Status.ok));
}
