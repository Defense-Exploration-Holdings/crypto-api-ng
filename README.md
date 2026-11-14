# crypto-api-ng

A maintained port of [`crypto-api`](https://github.com/nf404/crypto-api) to Zig, compiled to WebAssembly (`wasm32-freestanding`) behind a thin JavaScript loader.

Goals: keep the original list of crypto APIs, add current and relevant ones, and be much faster. Release plan: **v1** = behavior-identical port (a drop-in for existing users), **v2** = bug fixes and API cleanup.

> **Status: scaffold only.** The runtime, build, loader and test wiring exist; no algorithms are ported yet. `src/wasm.zig` exports only module metadata, `alloc`/`free`, and a `smoke_xor` plumbing check.

## Required toolchain

| Tool | Version | Pinned in |
|------|---------|-----------|
| Zig  | **0.17.1** | `.zig-version`, `build.zig.zon` (`minimum_zig_version`) |
| Node.js | **22** (LTS or newer) | `.nvmrc`, `package.json` `engines` |
| Python 3 + pip | any recent 3.x, only to bootstrap Zig | `scripts/install-zig.sh` |

No other dependencies: no npm packages, no Zig packages, no libc, no WASI, no Emscripten, no binaryen/wasm-opt (yet).

Zig 0.17 differs from the 0.13-0.15 docs most tutorials still show. The optimize modes are renamed to `debug|safe|fast|small`, `standardOptimizeOption` is driven by `--release=…`, and `std.Io` / `std.process.Init` replace the old main/IO APIs. When unsure, read the toolchain's own `lib/std` sources.

### Setting up an environment

```sh
scripts/install-zig.sh            # installs the pinned Zig to ~/.local/bin (pass a prefix to change)
export PATH="$HOME/.local/bin:$PATH"
zig version                       # 0.17.1
node --version                    # v22.x
```

The script installs Zig from the official `ziglang` PyPI wheel, because `ziglang.org` is blocked in some sandboxes while PyPI is reachable. If pip fails it falls back to the official tarball. Environment builders only need outbound access to PyPI (`pypi.org`, `files.pythonhosted.org`) and, for the fallback, `ziglang.org`.

## Commands

```sh
zig build                         # build zig-out/wasm/crypto-api.wasm (debug)
zig build wasm --release=small    # size-optimized wasm   (also: --release=fast | --release=safe)
zig build test                    # Zig unit tests, native target
zig build test-js                 # build wasm, then run Node tests (test/*.test.js)
zig build check                   # everything above; run this before every commit
```

`npm run build`, `npm test` are thin aliases for the same commands.

## Layout

```
build.zig, build.zig.zon   build graph and package manifest
src/root.zig               target-agnostic library root; native tests start here
src/runtime.zig            ABI version, status codes, shared conventions
src/wasm.zig               the wasm export surface (only file with `export fn`)
js/index.js, index.d.ts    loader: instantiate wasm, ABI check, byte in/out helpers
test/*.test.js             Node tests run against the built wasm
docs/abi.md                JS <-> wasm calling conventions (read before adding exports)
scripts/install-zig.sh     pinned Zig installer
crypto-api/                upstream crypto-api as a git submodule (the behavioral oracle)
```

Add algorithms as target-agnostic Zig under `src/` (with `test` blocks, re-exported from `src/root.zig`), export them from `src/wasm.zig`, then wrap them in `js/`.

## Upstream submodule

`crypto-api/` is a git submodule of upstream (`.gitmodules`). Run `git submodule update --init` to check it out. Treat it as read-only: it is the reference implementation that ports are compared against.

## License

See [LICENSE-NOTES.md](LICENSE-NOTES.md). The license for this repository has not been chosen yet, and upstream's notice must be preserved.
