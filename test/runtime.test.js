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

test('version string is exposed', () => {
  assert.match(rt.version, /^\d+\.\d+\.\d+/);
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

test('smoke_xor folds bytes', () => {
  const out = rt.withBytes(Uint8Array.of(0x0f, 0xf0, 0xaa), (ptr, len) => rt.exports.smoke_xor(ptr, len));
  assert.equal(out, 0x0f ^ 0xf0 ^ 0xaa);
  assert.equal(rt.exports.smoke_xor(0, 0), 0);
});

test('large allocation survives memory growth', () => {
  const big = new Uint8Array(8 * 1024 * 1024).fill(7);
  const out = rt.withBytes(big, (ptr, len) => {
    const folded = rt.exports.smoke_xor(ptr, len);
    // view() must be re-created after growth; this reads through a fresh view.
    assert.equal(rt.view(ptr, 1)[0], 7);
    return folded;
  });
  assert.equal(out, 0); // even count of 7s xors to 0
});
