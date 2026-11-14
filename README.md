# crypto-api-ng

A maintained port of [`crypto-api`](https://github.com/nf404/crypto-api) to Zig, compiled to WebAssembly (`wasm32-freestanding`) behind a thin JavaScript loader.

Goals: keep the original list of crypto APIs, add current and relevant ones, and be much faster. Release plan: **v1** = behavior-identical port (a drop-in for existing users), **v2** = bug fixes and API cleanup.

> **Status: MD5, MD4, HAS-160, RIPEMD-128/160/256/320 and Snefru ported.** MD5 is the template (Zig core, wasm family module, JS facade with fallback to the original 0.8.5 code, differential tests). The rest is still to come, see `docs/PORT_PLAN.md` once merged. `src/wasm.zig` is the general runtime module (metadata, `alloc`/`free`, a `smoke_xor` plumbing check).

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
zig build families                # build zig-out/wasm/<family>.wasm, one module per algorithm family
zig build js                      # generate embedded wasm byte modules (js/generated/, packages/crypto-api/wasm/)
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
src/hash/<algo>.zig        algorithm cores (target-agnostic, with tests)
src/wasm.zig               general runtime wasm module (metadata, alloc/free, smoke test)
src/wasm/<family>.zig      one wasm root per algorithm family (the only other files with `export fn`)
packages/crypto-api/       the package under construction: facades in src/, verbatim original code in legacy/
js/index.js, index.d.ts    loader: async `load()` and sync `loadSync()`, ABI check, byte in/out helpers
js/sync.js                 sync entry: instantiates embedded bytes on import (needs `zig build js`)
test/*.test.js             Node tests run against the built wasm
docs/abi.md                JS <-> wasm calling conventions (read before adding exports)
docs/porting-guide.md      how to port an algorithm, using MD5 as the template
scripts/install-zig.sh     pinned Zig installer
scripts/embed-wasm.mjs     wasm -> base64 JS module generator (used by `zig build js`)
crypto-api/                upstream crypto-api as a git submodule (the behavioral oracle)
```

To add an algorithm, follow [docs/porting-guide.md](docs/porting-guide.md): core in `src/hash/`, exports in a family root under `src/wasm/`, facade in `packages/crypto-api/src/hasher/`, differential tests in `test/`.

## Upstream submodule

`crypto-api/` is a git submodule of upstream (`.gitmodules`). Run `git submodule update --init` to check it out. Treat it as read-only: it is the reference implementation that ports are compared against.

## License

See [LICENSE-NOTES.md](LICENSE-NOTES.md). The license for this repository has not been chosen yet, and upstream's notice must be preserved.
