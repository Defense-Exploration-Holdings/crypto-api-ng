//! Build graph for crypto-api-ng.
//!
//!   zig build              install the wasm module to zig-out/wasm/ (debug mode by default)
//!   zig build wasm         same as above, explicit
//!   zig build families     build zig-out/wasm/<family>.wasm (one module per algorithm family)
//!   zig build js           generate embedded wasm byte modules (js/generated/, packages/crypto-api/wasm/)
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

    // ---- per-family wasm modules -------------------------------------------
    // One module per algorithm family (src/wasm/<family>.zig), so a user who
    // imports one algorithm only pays for that family. To add a family, append
    // its name to `families`; the root file must exist at src/wasm/<name>.zig.
    // Each is also embedded as packages/crypto-api/wasm/<name>.mjs (see `js`).
    const families = [_][]const u8{ "md", "md2", "has160", "ripemd", "sha1", "sha256", "sha512", "sm3", "snefru", "whirlpool", "blake2b", "blake2s", "blake3" };
    // Fixed linear memory: 2 pages = 128 KiB (scratch 64 KiB + 256 B, a 16 KiB
    // stack, data). max == initial so memory can never grow and JS may cache
    // views of it.
    const family_memory_bytes = 2 * 64 * 1024;

    const js_step = b.step("js", "Generate embedded wasm byte modules (js/generated, packages/crypto-api/wasm)");
    const family_step = b.step("families", "Build zig-out/wasm/<family>.wasm for every family");
    var family_embeds: [families.len]*std.Build.Step = undefined;
    // The algorithm library as a module, so family roots in src/wasm/ can reach
    // it with @import("core") (Zig forbids relative imports above a module root).
    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .single_threaded = true,
    });
    inline for (families, 0..) |family, i| {
        const fam_mod = b.createModule(.{
            .root_source_file = b.path("src/wasm/" ++ family ++ ".zig"),
            .target = wasm_target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{.{ .name = "core", .module = core_mod }},
        });
        const fam = b.addExecutable(.{ .name = family, .root_module = fam_mod });
        fam.entry = .disabled;
        fam.rdynamic = true;
        fam.stack_size = 16 * 1024;
        fam.initial_memory = family_memory_bytes;
        fam.max_memory = family_memory_bytes;
        const install_fam = b.addInstallArtifact(fam, .{ .dest_dir = .{ .override = .{ .custom = "wasm" } } });
        family_step.dependOn(&install_fam.step);
        b.getInstallStep().dependOn(&install_fam.step);

        const embed_fam = b.addSystemCommand(&.{ "node", "scripts/embed-wasm.mjs" });
        embed_fam.addFileArg(fam.getEmittedBin());
        embed_fam.addArg("packages/crypto-api/wasm/" ++ family ++ ".mjs");
        embed_fam.setCwd(b.path("."));
        js_step.dependOn(&embed_fam.step);
        family_embeds[i] = &embed_fam.step;
    }

    // ---- embedded-bytes JS module (synchronous loading) -------------------
    // Writes js/generated/wasm-bytes.js (base64) so js/sync.js can instantiate
    // the module synchronously with no fetch or fs access.
    const embed = b.addSystemCommand(&.{ "node", "scripts/embed-wasm.mjs" });
    embed.addFileArg(wasm.getEmittedBin());
    embed.addArg("js/generated/wasm-bytes.js");
    embed.setCwd(b.path("."));
    js_step.dependOn(&embed.step);

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
    node_tests.step.dependOn(&embed.step);
    node_tests.step.dependOn(family_step);
    node_tests.step.dependOn(js_step);
    node_tests.setCwd(b.path("."));

    const test_js_step = b.step("test-js", "Build the wasm and run the Node test suite");
    test_js_step.dependOn(&node_tests.step);

    const check_step = b.step("check", "Run all test suites (Zig + JS)");
    check_step.dependOn(test_step);
    check_step.dependOn(test_js_step);
}
