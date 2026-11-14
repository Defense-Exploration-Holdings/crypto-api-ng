// The generated bundles (crypto-api.js, crypto-api.min.js, index.js) and src/index.mjs expose the same
// CryptoApi object as the original, and give the same answers for every getHasher() name, hash(),
// hmac() and getHmac(). Also: ES5 syntax, the embedded wasm is really used, and the same file keeps
// working when WebAssembly is missing.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import * as acorn from 'acorn';
import { loadOracle } from '../harness/load.mjs';
import { GET_HASHER_NAMES, UNKNOWN_HASHER_NAMES, HMAC_VARIANTS } from '../harness/catalog.mjs';
import { PKG_ROOT, ensureBuilt } from './support.js';

const require = createRequire(import.meta.url);

let oracle;
const subjects = {}; // label -> CryptoApi object

before(async () => {
  await ensureBuilt();
  oracle = (await loadOracle()).CryptoApi;
  subjects['index.js'] = require(join(PKG_ROOT, 'index.js'));
  subjects['crypto-api.js'] = require(join(PKG_ROOT, 'crypto-api.js'));
  subjects['crypto-api.min.js'] = require(join(PKG_ROOT, 'crypto-api.min.js'));
  subjects['src/index.mjs'] = (await import(pathToFileURL(join(PKG_ROOT, 'src', 'index.mjs')).href)).default;
  subjects['src/crypto-api.mjs'] = (await import(pathToFileURL(join(PKG_ROOT, 'src', 'crypto-api.mjs')).href)).default;
});

const outcome = (fn) => {
  try { return { ok: fn() }; } catch (e) { return { err: `${e?.constructor?.name}: ${e?.message}` }; }
};

// Binary strings (what update() takes) and UTF strings (what hash()/hmac() take).
const BINARY = ['', 'abc', 'x'.repeat(63), 'y'.repeat(64), 'z'.repeat(65), 'The quick brown fox'.repeat(20), '\x00\x01\xfe\xff'.repeat(40)];
const UTF = ['', 'abc', 'Привет, мир ☃ 😀', 'q'.repeat(300)];
const LABELS = ['index.js', 'crypto-api.js', 'crypto-api.min.js', 'src/index.mjs', 'src/crypto-api.mjs'];

describe('shape', () => {
  for (const label of LABELS) {
    it(`${label} exports the CryptoApi object of 0.8.5`, () => {
      const api = subjects[label];
      assert.deepEqual(Object.keys(api).sort(), Object.keys(oracle).sort());
      assert.deepEqual(Object.keys(api.encoder).sort(), ['fromArrayBuffer', 'fromUtf', 'toBase64', 'toHex']);
      for (const m of ['getHasher', 'hash', 'getHmac', 'hmac']) assert.equal(typeof api[m], 'function', m);
      assert.equal(api.constructor.name, oracle.constructor.name);
      for (const m of ['getHasher', 'hash', 'getHmac', 'hmac']) assert.equal(api[m].length, oracle[m].length, `${m}.length`);
    });
  }

  it('index.js is the same object as crypto-api.js', () => {
    assert.equal(subjects['index.js'], subjects['crypto-api.js']);
  });
});

describe('same answers as the original', () => {
  for (const label of LABELS) {
    describe(label, () => {
      it('hash() for every getHasher() name', () => {
        const api = subjects[label];
        for (const name of GET_HASHER_NAMES) {
          for (const msg of UTF) {
            assert.deepEqual(outcome(() => api.hash(name, msg)), outcome(() => oracle.hash(name, msg)), `${name} ${JSON.stringify(msg.slice(0, 12))}`);
          }
        }
      });

      it('getHasher() instances: update/finalize/getState', () => {
        const api = subjects[label];
        for (const name of GET_HASHER_NAMES) {
          const run = (a) => {
            const h = a.getHasher(name);
            const trace = [h.constructor.name, JSON.stringify(h.getState())];
            for (const part of BINARY) {
              h.update(part);
              trace.push(JSON.stringify(h.getState()));
            }
            trace.push(a.encoder.toHex(h.finalize()));
            return trace;
          };
          assert.deepEqual(run(api), run(oracle), name);
        }
      });

      it('options reach the hasher (getHasher(name, options))', () => {
        const api = subjects[label];
        const cases = [['sha1', { rounds: 20 }], ['sha256', { rounds: 10 }], ['sha256', { length: 224 }], ['sha512', { length: 256 }],
          ['ripemd', { length: 256 }], ['snefru', { rounds: 4 }], ['whirlpool', { type: 't' }], ['md2', { rounds: 9 }], ['has160', { rounds: 40 }]];
        for (const [name, options] of cases) {
          const run = (a) => outcome(() => a.hash(name, 'abc', structuredClone(options)));
          assert.deepEqual(run(api), run(oracle), `${name} ${JSON.stringify(options)}`);
        }
      });

      it('unknown names: getHasher() is undefined and hash() throws like the original', () => {
        const api = subjects[label];
        for (const name of UNKNOWN_HASHER_NAMES) {
          assert.equal(api.getHasher(name), undefined, name);
          assert.deepEqual(outcome(() => api.hash(name, 'abc')), outcome(() => oracle.hash(name, 'abc')), name);
        }
      });

      it('getHmac() and hmac()', () => {
        const api = subjects[label];
        for (const name of HMAC_VARIANTS.concat(['sha384', 'ripemd160', 'sha512/256', 'whirlpool'])) {
          for (const key of ['', 'key', 'k'.repeat(64), 'k'.repeat(65), 'k'.repeat(200), '\x00\xff\x80']) {
            const raw = (a) => {
              const m = a.getHmac(key, a.getHasher(name));
              m.update('The quick brown ');
              m.update('fox');
              return a.encoder.toHex(m.finalize());
            };
            assert.equal(raw(api), raw(oracle), `getHmac ${name} keylen=${key.length}`);
            for (const msg of UTF) {
              assert.equal(api.hmac('ключ' + key, msg, api.getHasher(name)), oracle.hmac('ключ' + key, msg, oracle.getHasher(name)), `hmac ${name}`);
            }
          }
        }
      });

      it('encoders', () => {
        const api = subjects[label];
        const inputs = ['', 'abc', 'Привет', '\ud800 lone', 'Ā'];
        for (const s of inputs) {
          assert.equal(api.encoder.fromUtf(s), oracle.encoder.fromUtf(s));
          assert.equal(api.encoder.toHex(s), oracle.encoder.toHex(s));
          assert.equal(api.encoder.toBase64(s), oracle.encoder.toBase64(s));
        }
        for (const b of [new Uint8Array([0, 1, 254, 255]).buffer, new Uint8Array([7, 8, 9]), [1, 2, 3], new Uint16Array([1, 256, 65535])]) {
          assert.equal(api.encoder.fromArrayBuffer(b), oracle.encoder.fromArrayBuffer(b));
        }
      });
    });
  }
});

describe('ES5 syntax', () => {
  for (const file of ['crypto-api.js', 'crypto-api.min.js']) {
    it(`${file} parses as ES5`, () => {
      acorn.parse(readFileSync(join(PKG_ROOT, file), 'utf8'), { ecmaVersion: 5, sourceType: 'script' });
    });
  }

  it('the minified build has a source map that points at it', () => {
    const map = JSON.parse(readFileSync(join(PKG_ROOT, 'crypto-api.min.js.map'), 'utf8'));
    assert.equal(map.version, 3);
    assert.deepEqual(map.sources, ['crypto-api.js']); // maps back to the unminified build shipped next to it
    assert.match(readFileSync(join(PKG_ROOT, 'crypto-api.min.js'), 'utf8'), /\/\/# sourceMappingURL=crypto-api\.min\.js\.map\s*$/);
  });
});

describe('WebAssembly use in the bundle (fresh process)', () => {
  const run = (prelude, file) => JSON.parse(execFileSync(process.execPath, ['-e', `
    ${prelude}
    const api = require(${JSON.stringify(join(PKG_ROOT, file))});
    const out = { md5: api.hash('md5', 'abc'), sha1: api.hash('sha1', 'abc'), snefru: api.hash('snefru', 'abc'), wasm: globalThis.__modules || 0 };
    const h = api.getHasher('md5'); h.update('x'.repeat(1000)); out.md5big = api.encoder.toHex(h.finalize());
    out.wasmAfter = globalThis.__modules || 0;
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
    it(`${file} compiles the embedded wasm and uses it`, () => {
      const r = run(spy, file);
      assert.ok(r.wasmAfter >= 1, 'no WebAssembly.Module was constructed');
      assert.equal(r.md5, '900150983cd24fb0d6963f7d28e17f72');
    });

    it(`${file} gives identical results when WebAssembly is missing`, () => {
      const withWasm = run('', file);
      const without = run('delete globalThis.WebAssembly;', file);
      assert.deepEqual(without, withWasm);
    });

    it(`${file} gives identical results when compiling wasm throws (CSP, Workers)`, () => {
      const withWasm = run('', file);
      const blocked = run(`WebAssembly.Module = function () { throw new Error('blocked by CSP'); };`, file);
      assert.deepEqual(blocked, withWasm);
    });
  }
});
