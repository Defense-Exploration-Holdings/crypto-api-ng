// The UMD bundles (ES5, WebAssembly embedded) hash with Tiger, Tiger2, Streebog, CRC-32, CRC-32C and xxHash like the ES modules
// do, with WebAssembly and, in a fresh process, without it (plain JavaScript engines).
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { PKG_ROOT, ensureBuilt } from './support.js';

before(ensureBuilt);

const EXPECTED = {
  tiger: '2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93',
  tiger2: 'f68d7bc5af4b43a06e048d7829560d4a9415658bb0b1f3bf',
  streebog256: '4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481',
  streebog512: '28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728',
  crc32: '352441c2',
  crc32c: '364b3fb7',
  xxhash32: '32d153ff',
  xxhash64: '44bc2cf5ad770999',
};

describe('Tiger, Streebog and the checksums in the bundles', () => {
  const run = (prelude, file) => JSON.parse(execFileSync(process.execPath, ['-e', `
    ${prelude}
    const api = require(${JSON.stringify(join(PKG_ROOT, file))});
    const out = { names: {}, modules: globalThis.__modules || 0 };
    for (const name of ['tiger', 'tiger2', 'streebog256', 'streebog512', 'crc32', 'crc32c', 'xxhash32', 'xxhash64']) out.names[name] = api.hash(name, 'abc');
    const big = 'q'.repeat(70000);
    out.big = ['tiger128', 'streebog', 'crc32', 'xxhash32', 'xxhash64'].map((n) => api.hash(n, big));
    out.seeded = [api.hash('xxhash32', 'abc', { seed: 5 }), api.hash('xxhash64', 'abc', { seed: 5 })];
    out.modules = globalThis.__modules || 0;
    console.log(JSON.stringify(out));
  `], { encoding: 'utf8' }));

  const spy = `
    if (typeof WebAssembly === 'object') {
      const M = WebAssembly.Module;
      globalThis.__modules = 0;
      WebAssembly.Module = function (bytes) { globalThis.__modules++; return new M(bytes); };
      WebAssembly.Module.prototype = M.prototype;
    }`;

  for (const file of ['crypto-api.js', 'crypto-api.min.js']) {
    it(`${file}: known answers, with the embedded wasm`, () => {
      const r = run(spy, file);
      assert.deepEqual(r.names, EXPECTED);
      assert.ok(r.modules >= 4, 'wasm modules compiled for the four families');
    });

    it(`${file}: identical results when WebAssembly is missing`, () => {
      const withWasm = run('', file);
      const without = run('delete globalThis.WebAssembly;', file);
      assert.deepEqual(without, withWasm);
      assert.deepEqual(without.names, EXPECTED);
    });
  }
});
