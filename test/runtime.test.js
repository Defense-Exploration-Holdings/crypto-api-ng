import { test } from 'node:test';
import assert from 'node:assert/strict';
import { load, EXPECTED_ABI_VERSION } from '../js/index.js';

const rt = await load();

test('module has no imports (freestanding)', async () => {
  const { readFile } = await import('node:fs/promises');
  const bytes = await readFile(new URL('../zig-out/wasm/crypto-api.wasm', import.meta.url));
  const mod = await WebAssembly.compile(bytes);
  assert.deepEqual(WebAssembly.Module.imports(mod), []);
});

test('abi version matches loader', () => {
  assert.equal(rt.exports.abi_version(), EXPECTED_ABI_VERSION);
});

test('version string matches package.json', async () => {
  const { readFile } = await import('node:fs/promises');
  const pkg = JSON.parse(await readFile(new URL('../packages/crypto-api/package.json', import.meta.url), 'utf8'));
  assert.equal(rt.version, pkg.version);
  const jsr = JSON.parse(await readFile(new URL('../packages/crypto-api/jsr.json', import.meta.url), 'utf8'));
  assert.equal(jsr.version, pkg.version);
  const zon = await readFile(new URL('../build.zig.zon', import.meta.url), 'utf8');
  assert.equal(/\.version = "([^"]+)"/.exec(zon)[1], pkg.version);
});

test('alloc/free round-trips bytes', () => {
  const input = Uint8Array.from({ length: 1000 }, (_, i) => i & 0xff);
  const { ptr, len } = rt.write(input);
  assert.notEqual(ptr, 0);
  assert.deepEqual(rt.read(ptr, len), input);
  rt.free(ptr, len);
});

test('alloc(0) returns 0 and free(0, 0) is a no-op', () => {
  assert.equal(rt.exports.alloc(0), 0);
  rt.free(0, 0);
});

test('withBytes frees on throw', () => {
  assert.throws(() => rt.withBytes(new Uint8Array(16), () => { throw new Error('boom'); }), /boom/);
});

test('large allocation survives memory growth', () => {
  const big = new Uint8Array(8 * 1024 * 1024).fill(7);
  const out = rt.withBytes(big, (ptr, len) => {
    // view() must be re-created after growth; this reads through a fresh view.
    assert.equal(rt.view(ptr, 1)[0], 7);
    assert.equal(rt.view(ptr + len - 1, 1)[0], 7);
    return len;
  });
  assert.equal(out, big.length);
});

test('sync entry point instantiates from embedded bytes', async () => {
  const { runtime } = await import('../js/sync.js');
  assert.equal(runtime.exports.abi_version(), EXPECTED_ABI_VERSION);
  assert.deepEqual(runtime.withBytes(Uint8Array.of(1, 2, 3), (p, n) => Array.from(runtime.view(p, n))), [1, 2, 3]);
});
