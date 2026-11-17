//! A project that uses crypto-api-ng as a Zig package. Here the dependency is
//! the repository itself (`.path = "../.."` in build.zig.zon); a real project
//! adds it with `zig fetch --save`, see the README.
//!
//!   zig build run     print a few digests
//!   zig build test    run the example's test

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const crypto_api_ng = b.dependency("crypto_api_ng", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "digests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "crypto_api_ng", .module = crypto_api_ng.module("crypto_api_ng") }},
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    b.step("run", "Print a few digests").dependOn(&run.step);

    const tests = b.addTest(.{ .root_module = exe.root_module });
    b.step("test", "Run the example's test").dependOn(&b.addRunArtifact(tests).step);
}
