// The Zig toolchain install is pinned and hash-checked (scripts/install-zig.sh, scripts/zig-requirements.txt).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, copyFileSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (p) => readFileSync(join(root, p), 'utf8');

describe('Zig toolchain pin', () => {
  const requirements = read('scripts/zig-requirements.txt');

  it('requirements pin the version in .zig-version', () => {
    const want = read('.zig-version').trim();
    const m = requirements.match(/^ziglang==(\S+)/m);
    assert.ok(m, 'no ziglang== line');
    assert.equal(m[1], want);
  });

  it('every requirement hash is a distinct SHA-256 digest', () => {
    const hashes = [...requirements.matchAll(/--hash=sha256:(\S+)/g)].map((m) => m[1]);
    assert.ok(hashes.length >= 5, 'expected hashes for the supported platforms');
    for (const h of hashes) assert.match(h, /^[0-9a-f]{64}$/);
    assert.equal(new Set(hashes).size, hashes.length);
  });

  it('install-zig.sh refuses a requirements file for another version', { skip: process.platform === 'win32' }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'zig-pin-'));
    try {
      mkdirSync(join(dir, 'scripts'));
      copyFileSync(join(root, 'scripts', 'install-zig.sh'), join(dir, 'scripts', 'install-zig.sh'));
      copyFileSync(join(root, 'scripts', 'zig-requirements.txt'), join(dir, 'scripts', 'zig-requirements.txt'));
      writeFileSync(join(dir, '.zig-version'), '0.0.1\n');
      const r = spawnSync('bash', [join(dir, 'scripts', 'install-zig.sh'), join(dir, 'prefix')], {
        encoding: 'utf8', env: { ...process.env, PATH: '/usr/bin:/bin' },
      });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /pins ziglang==.* but \.zig-version is 0\.0\.1/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
