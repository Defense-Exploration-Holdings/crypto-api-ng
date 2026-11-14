//! Build graph for crypto-api-ng.
//!
//!   zig build              install the wasm module to zig-out/wasm/ (debug mode by default)
//!   zig build wasm         same as above, explicit
//!   zig build test         run Zig unit tests on the native target
//!   zig build test-js      build the wasm, then run the Node test suite against it
//!   zig build check        run every test suite (Zig + JS)
//!
//! Options:
//!   --release=<mode>       small | fast | safe   (omit for debug)
//!   -Doptimize=<mode>      debug | safe | fast | small   (Zig 0.17 renamed these from Release*)

const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    // ---- wasm module ------------------------------------------------------
    // wasm32-freestanding: no libc, no OS. All I/O happens in the JS loader.
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
        // Baseline wasm + the widely shipped extensions. Keep this list
        // conservative: every feature here must work in Node LTS and
        // evergreen browsers.
        .cpu_features_add = std.Target.wasm.featureSet(&.{ .bulk_memory, .sign_ext, .nontrapping_fptoint }),
    });

    const wasm_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .single_threaded = true,
    });

    const wasm = b.addExecutable(.{
        .name = "crypto-api",
        .root_module = wasm_mod,
    });
    wasm.entry = .disabled; // library-style module, no _start
    wasm.rdynamic = true; // export every `export fn`

    const install_wasm = b.addInstallArtifact(wasm, .{
        .dest_dir = .{ .override = .{ .custom = "wasm" } },
    });

    const wasm_step = b.step("wasm", "Build zig-out/wasm/crypto-api.wasm");
    wasm_step.dependOn(&install_wasm.step);
    b.getInstallStep().dependOn(&install_wasm.step);

    // ---- zig unit tests (native) -----------------------------------------
    // Algorithms are written target-agnostic in src/, so their unit tests run
    // natively (fast, debuggable). wasm.zig itself is exercised by the JS tests.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = b.standardTargetOptions(.{}),
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run Zig unit tests (native target)");
    test_step.dependOn(&run_unit_tests.step);

    // ---- JS tests against the built wasm ---------------------------------
    const node_tests = b.addSystemCommand(&.{ "node", "--test", "test/*.test.js" });
    node_tests.step.dependOn(&install_wasm.step);
    node_tests.setCwd(b.path("."));

    const test_js_step = b.step("test-js", "Build the wasm and run the Node test suite");
    test_js_step.dependOn(&node_tests.step);

    const check_step = b.step("check", "Run all test suites (Zig + JS)");
    check_step.dependOn(test_step);
    check_step.dependOn(test_js_step);
}
