// The UMD bundles (ES5, WebAssembly embedded) hash with BLAKE2b, BLAKE2s and BLAKE3 like the ES modules
// do, with WebAssembly and, in a fresh process, without it (plain JavaScript engines).
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { PKG_ROOT, ensureBuilt } from './support.js';

before(ensureBuilt);

const EXPECTED = {
  blake2b: 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
  blake2s: '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982',
  blake3: '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
};

describe('BLAKE in the bundles', () => {
  const run = (prelude, file) => JSON.parse(execFileSync(process.execPath, ['-e', `
    ${prelude}
    const api = require(${JSON.stringify(join(PKG_ROOT, file))});
    const out = { names: {}, modules: globalThis.__modules || 0 };
    for (const name of ['blake2b', 'blake2s', 'blake3']) out.names[name] = api.hash(name, 'abc');
    const big = 'q'.repeat(70000);
    out.big = ['blake2b-256', 'blake2s-128', 'blake3'].map((n) => api.hash(n, big));
    out.keyed = [api.hash('blake2b', 'abc', { key: 'key', salt: 'salt' }), api.hash('blake3', 'abc', { context: 'ctx', length: 4000 }).length];
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
      assert.ok(r.modules >= 3, 'wasm modules compiled for the three algorithms');
    });

    it(`${file}: identical results when WebAssembly is missing`, () => {
      const withWasm = run('', file);
      const without = run('delete globalThis.WebAssembly;', file);
      assert.deepEqual(without, withWasm);
      assert.deepEqual(without.names, EXPECTED);
    });
  }
});
