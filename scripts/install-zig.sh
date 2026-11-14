#!/usr/bin/env bash
# Install the Zig version pinned in .zig-version.
#
# Strategy: use the official `ziglang` PyPI wheel (it bundles the real Zig
# toolchain). This works in sandboxes where ziglang.org / mirrors are blocked
# but PyPI is reachable. Falls back to the official tarball if pip fails.
#
# Usage: scripts/install-zig.sh [prefix]     (default prefix: $HOME/.local)
# Result: <prefix>/bin/zig  (add <prefix>/bin to PATH)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
want="$(tr -d '[:space:]' < "$root/.zig-version")"
prefix="${1:-$HOME/.local}"
bin="$prefix/bin"

if command -v zig >/dev/null 2>&1 && [ "$(zig version)" = "$want" ]; then
  echo "zig $want already installed at $(command -v zig)"
  exit 0
fi

mkdir -p "$bin"
venv="$prefix/share/zig-venv-$want"

if python3 -m venv "$venv" && "$venv/bin/pip" install --quiet "ziglang==$want"; then
  zigbin="$("$venv/bin/python" -c 'import ziglang, pathlib; print(pathlib.Path(ziglang.__file__).parent / "zig")')"
  ln -sf "$zigbin" "$bin/zig"
else
  echo "pip install failed; falling back to ziglang.org tarball" >&2
  arch="$(uname -m)"; os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  dest="$prefix/share/zig-$want"
  mkdir -p "$dest"
  curl -fsSL "https://ziglang.org/download/$want/zig-$arch-$os-$want.tar.xz" | tar -xJ -C "$dest" --strip-components=1
  ln -sf "$dest/zig" "$bin/zig"
fi

echo "installed: $("$bin/zig" version) -> $bin/zig"
case ":$PATH:" in *":$bin:"*) ;; *) echo "note: add $bin to PATH" ;; esac
