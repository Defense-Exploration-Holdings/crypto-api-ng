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
import { modelFromUtf } from '../harness/fixes-model.mjs';
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
  subjects['crypto-api.min.mjs'] = (await import(pathToFileURL(join(PKG_ROOT, 'crypto-api.min.mjs')).href)).default;
  subjects['src/index.mjs'] = (await import(pathToFileURL(join(PKG_ROOT, 'src', 'index.mjs')).href)).default;
  subjects['src/crypto-api.mjs'] = (await import(pathToFileURL(join(PKG_ROOT, 'src', 'crypto-api.mjs')).href)).default;
});

const outcome = (fn) => {
  try { return { ok: fn() }; } catch (e) { return { err: `${e?.constructor?.name}: ${e?.message}` }; }
};

// Binary strings (what update() takes) and UTF strings (what hash()/hmac() take).
const BINARY = ['', 'abc', 'x'.repeat(63), 'y'.repeat(64), 'z'.repeat(65), 'The quick brown fox'.repeat(20), '\x00\x01\xfe\xff'.repeat(40)];
const UTF = ['', 'abc', 'Привет, мир ☃ 😀', 'q'.repeat(300)];
const LABELS = ['index.js', 'crypto-api.js', 'crypto-api.min.js', 'crypto-api.min.mjs', 'src/index.mjs', 'src/crypto-api.mjs'];

describe('shape', () => {
  for (const label of LABELS) {
    it(`${label} exports the CryptoApi object of 0.8.5`, () => {
      const api = subjects[label];
      assert.deepEqual(Object.keys(api).sort(), Object.keys(oracle).sort());
      // The four encoders of 0.8.5, then the byte encoders crypto-api-ng added.
      assert.deepEqual(Object.keys(api.encoder).sort(), [
        'base64ToBytes', 'bytesToBase64', 'bytesToHex', 'bytesToUtf8', 'fromArrayBuffer', 'fromUtf', 'hexToBytes', 'toBase64', 'toHex', 'utf8ToBytes',
      ]);
      for (const m of ['getHasher', 'hash', 'getHmac', 'hmac']) assert.equal(typeof api[m], 'function', m);
      assert.equal(api.constructor.name, oracle.constructor.name);
      for (const m of ['getHasher', 'hash', 'getHmac', 'hmac']) assert.equal(api[m].length, oracle[m].length, `${m}.length`);
    });
  }

  for (const label of LABELS) {
    it(`${label}: bytes in, bytes out`, () => {
      const api = subjects[label];
      const bytes = api.hashBytes('sha256', 'abc');
      assert.ok(bytes instanceof Uint8Array);
      assert.equal(api.encoder.bytesToHex(bytes), api.hash('sha256', 'abc'));
      const hasher = api.getHasher('sha3-256');
      hasher.update(new Uint8Array([97, 98, 99]));
      assert.equal(hasher.digest('base64url'), api.encoder.bytesToBase64(api.hashBytes('sha3-256', 'abc'), { alphabet: 'base64url', omitPadding: true }));
      assert.equal(api.encoder.bytesToHex(api.hmacBytes('key', 'message', api.getHasher('md5'))), api.hmac('key', 'message', api.getHasher('md5')));
      assert.equal(api.encoder.bytesToUtf8(api.encoder.utf8ToBytes('h\u00e9llo \u{1F600}')), 'h\u00e9llo \u{1F600}');
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
        for (const name of UNKNOWN_HASHER_NAMES.filter((n) => n !== 'sm3')) {
          assert.equal(api.getHasher(name), undefined, name);
          assert.deepEqual(outcome(() => api.hash(name, 'abc')), outcome(() => oracle.hash(name, 'abc')), name);
        }
      });

      it('1.1 fixes: sm3, bytes in, wide characters and bad options rejected, repeatable Hmac', () => {
        const api = subjects[label];
        assert.equal(api.hash('sm3', 'abc'), '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
        const h = api.getHasher('sha256');
        h.update(new Uint8Array([97, 98, 99]));
        assert.equal(api.encoder.toHex(h.finalize()), oracle.hash('sha256', 'abc'));
        assert.throws(() => api.getHasher('md5').update('Ā'), TypeError);
        assert.throws(() => api.getHasher('md5').update(5), TypeError);
        assert.throws(() => api.getHasher('sha256', { rounds: 80 }), RangeError);
        const md5 = api.getHasher('md5');
        const m = api.getHmac('key', md5);
        m.update('message');
        const first = api.encoder.toHex(m.finalize());
        assert.equal(first, '4e4748e62b463521f6775fbf921234b5');
        assert.equal(api.encoder.toHex(m.finalize()), first);
        assert.equal(md5.state.length, 0);
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
          // 0.8.5 mis-encodes an unpaired surrogate; the fixed rule is in the fixes model.
          assert.equal(api.encoder.fromUtf(s), modelFromUtf(s));
          if (s.isWellFormed()) assert.equal(api.encoder.fromUtf(s), oracle.encoder.fromUtf(s));
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
  const load = (file) => file.endsWith('.mjs')
    ? `const api = (await import(${JSON.stringify(pathToFileURL(join(PKG_ROOT, file)).href)})).default;`
    : `const api = require(${JSON.stringify(join(PKG_ROOT, file))});`;
  const run = (prelude, file) => JSON.parse(execFileSync(process.execPath, [
    ...(file.endsWith('.mjs') ? ['--input-type=module'] : []), '-e', `
    ${prelude}
    ${load(file)}
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

  for (const file of ['crypto-api.js', 'crypto-api.min.js', 'crypto-api.min.mjs']) {
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

describe('ES module build (crypto-api.min.mjs)', () => {
  let esm;
  before(async () => {
    const { ESM_EXPORTS } = await import(join(PKG_ROOT, '..', '..', 'scripts', 'build-bundle.mjs'));
    esm = { ns: await import(pathToFileURL(join(PKG_ROOT, 'crypto-api.min.mjs')).href), ESM_EXPORTS };
  });

  it('parses as an ES2020 module', () => {
    acorn.parse(readFileSync(join(PKG_ROOT, 'crypto-api.min.mjs'), 'utf8'), { ecmaVersion: 2020, sourceType: 'module' });
  });

  it('has the CryptoApi object as default export and exactly the listed named exports', () => {
    const names = Object.keys(esm.ns).filter((k) => k !== 'default').sort();
    assert.deepEqual(names, esm.ESM_EXPORTS.map(([n]) => n).sort());
    const dts = readFileSync(join(PKG_ROOT, 'crypto-api.min.d.mts'), 'utf8');
    for (const n of names) assert.match(dts, new RegExp(`\\b${n} \\}`), `${n} is not declared`);
  });

  it('named exports are the modules under src/, built into the same file as the default export', async () => {
    for (const [name, file, from] of esm.ESM_EXPORTS) {
      const source = await import(pathToFileURL(join(PKG_ROOT, file)).href);
      assert.equal(typeof esm.ns[name], typeof source[from], name);
      if (typeof source[from] === 'function' && /^[A-Z]/.test(name)) assert.equal(esm.ns[name].name, source[from].name, name);
    }
    const api = esm.ns.default;
    assert.ok(api.getHasher('sha256') instanceof esm.ns.Sha256);
    assert.ok(api.getHasher('blake3') instanceof esm.ns.Blake3);
    assert.ok(api.getHmac('k', api.getHasher('md5')) instanceof esm.ns.Hmac);
    assert.equal(esm.ns.bytesToHex(new esm.ns.Sha256().digest()), api.hash('sha256', ''));
    assert.equal(esm.ns.toHex(esm.ns.fromUtf('\u00e9')), 'c3a9');
  });

  it('has a source map whose sources are files shipped next to it', () => {
    const map = JSON.parse(readFileSync(join(PKG_ROOT, 'crypto-api.min.mjs.map'), 'utf8'));
    assert.equal(map.version, 3);
    assert.ok(map.sources.includes('src/crypto-api.mjs'));
    assert.ok(map.sources.some((s) => s.startsWith('wasm/')));
    assert.match(readFileSync(join(PKG_ROOT, 'crypto-api.min.mjs'), 'utf8'), /\/\/# sourceMappingURL=crypto-api\.min\.mjs\.map\s*$/);
  });
});
