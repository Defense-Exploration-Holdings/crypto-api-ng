# License notes

**Status: needs a decision from the maintainers before the first public release.** This file records what is known so far.

- This project is a port of [`nf404/crypto-api`](https://github.com/nf404/crypto-api), vendored here as the `crypto-api/` git submodule (see `.gitmodules`). A port of its algorithms and API surface is a derivative work, so the original copyright and license notice must be preserved in this repository and in published packages.
- The original is reported to be MIT-licensed (`crypto-api/LICENSE.md`, "Copyright (c) 2015 Aleksandr Mogilnikov"; `license: "MIT"` in its `package.json`). This was relayed by the port-planning thread; the submodule was not checked out where this file was written, so verify it, then copy the original notice verbatim into a `THIRD_PARTY_NOTICES` file.
- The license for the new Zig/wasm code (and the copyright holder line, presumably Defense Exploration Holdings) is not chosen yet. An MIT license is the natural fit if the original is MIT. Add `LICENSE` and set the `license` field in `package.json` when decided; `package.json` is `"private": true` until then so nothing can be published by accident.
- Zig's standard library (compiled into the wasm) is MIT-licensed; no notice is required for the binary beyond the above, but keep this in mind if third-party Zig packages are added later. Record any added dependency here.
- Test vectors taken from standards (NIST, RFCs) are fine to reuse; test vectors copied from the original's test suite fall under the original's license.
