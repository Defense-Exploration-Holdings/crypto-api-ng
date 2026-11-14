// Facade tests for MD2: wasm-accelerated class vs the untouched crypto-api 0.8.5 class.
//
// The oracle is packages/crypto-api/legacy/hasher/md2.mjs, a verbatim copy of the
// original (only import specifiers differ). Everything is compared through the
// public surface: digests, getState() JSON, thrown errors. Modeled on
// test/be32-family.test.js; MD2 differs in being a Hasher8 (16-byte blocks, no
// length field) whose state is two arrays, `hash` (48) and `checksum` (16), that
// start as `new Array(n)` and turn into JSON nulls.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import Md2, { _internal } from '../packages/crypto-api/src/hasher/md2.mjs';
import LegacyMd2 from '../packages/crypto-api/legacy/hasher/md2.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hasher8 from '../packages/crypto-api/src/hasher/hasher8.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';

const vec = (name) => JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url), 'utf8'));
const FUZZ_ITERS = Number(process.env.FUZZ_ITERS || 200);
const B = 16;

const hex = (h) => toHex(h.finalize());
const json = (h) => JSON.stringify(h.getState());

/** Deterministic PRNG (mulberry32) so failures reproduce. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function binString(rand, len) {
  let s = '';
  for (let i = 0; i < len; i++) s += String.fromCharCode((rand() * 256) | 0);
  return s;
}

/** Run `fn`, returning its value or the error it threw as `{error: 'Type: msg'}`. */
function attempt(fn) {
  try {
    return { value: fn() };
  } catch (e) {
    return { error: `${e.constructor.name}: ${e.message}` };
  }
}

const update = (s) => (h) => h.update(s);
const finalize = () => (h) => h.finalize();
const opts = (o) => structuredClone(o);
const wasmUsed = (fn) => {
  const before = _internal.wasmCalls();
  fn();
  return _internal.wasmCalls() - before;
};

/** Apply the same steps to a fresh facade and a fresh original and compare every observation. */
function same(steps, label, options = {}) {
  const a = new Md2(opts(options));
  const b = new LegacyMd2(opts(options));
  steps.forEach((step, i) => {
    const ra = attempt(() => step(a));
    const rb = attempt(() => step(b));
    assert.deepEqual(ra, rb, `${label}: step ${i} result differs`);
    assert.equal(json(a), json(b), `${label}: step ${i} getState() differs`);
  });
  assert.deepEqual(a.options, b.options, `${label}: options differ`);
  return { a, b };
}

// rounds the wasm code serves, and ones it hands to the original (never huge: the original loops that long).
const INSIDE = [{}, { rounds: 1 }, { rounds: 2 }, { rounds: 17 }, { rounds: 18 }, { rounds: 19 }, { rounds: 50 }, { rounds: 255 },
  { rounds: 256 }, { rounds: 257 }, { rounds: 300 }, { rounds: 0 }, { rounds: NaN }, { rounds: null }];
const OUTSIDE = [{ rounds: 2.5 }, { rounds: '5' }, { rounds: -1 }, { rounds: true }, { rounds: 1.5 }, { rounds: -0.5 }];

const pristine = () => JSON.stringify({ message: '', length: 0, hash: new Array(48).fill(null), checksum: new Array(16).fill(null) });

describe('md2', () => {
  test('uses wasm in a normal environment', () => {
    assert.ok(_internal.runtime(), 'wasm failed to instantiate; run `zig build js` first');
    assert.equal(wasmUsed(() => {
      const h = new Md2();
      h.update('x'.repeat(B + 6));
      h.finalize();
    }), 2, 'one process() call and one finalize() call');
  });

  test('is a Hasher8 and an original-shaped hasher', () => {
    const h = new Md2();
    assert.ok(h instanceof Hasher);
    assert.ok(h instanceof Hasher8);
    assert.ok(h instanceof LegacyMd2);
    assert.equal(Md2.length, LegacyMd2.length);
    assert.equal(h.unitSize, 1);
    assert.equal(h.blockSizeInBytes, B);
    const o = {};
    assert.equal(new Md2(o).options, o, 'options object is kept by reference');
    assert.deepEqual(new Md2().options, { rounds: 18 });
    assert.deepEqual(new Md2().options, new LegacyMd2().options);
    for (const m of ['reset', 'update', 'finalize', 'getState', 'setState', 'process', 'processBlock']) {
      assert.equal(typeof h[m], 'function', m);
    }
  });

  for (const t of vec('md2')) {
    test(`vector: ${t.name}`, () => {
      const h = new Md2();
      h.update(t.input);
      assert.equal(wasmUsed(() => assert.equal(hex(h), t.hex)), 1);
    });
  }

  test('RFC 1319 test suite', () => {
    const rfc = {
      '': '8350e5a3e24c153df2275c9f80692773',
      a: '32ec01ec4a6dac72c0ab96fb34c0b5d1',
      abc: 'da853b0d3f88d99b30283a69e6ded6bb',
      'message digest': 'ab4f496bfb2a530b219ff33031fe06b0',
      abcdefghijklmnopqrstuvwxyz: '4e8ddff3650292ab5a4108c3aa47940b',
      ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789: 'da33def2a42df13975352846c30338cd',
      [('1234567890').repeat(8)]: 'd5976f79d83d3a0dc9806c3c66f3efd8'
    };
    for (const [input, digest] of Object.entries(rfc)) {
      const h = new Md2();
      h.update(input);
      assert.equal(hex(h), digest, input);
    }
  });

  test('differential: random messages split across random update() calls, every option set', () => {
    const rand = rng(2);
    const lengths = [0, 1, 14, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 257];
    for (const options of [...INSIDE, ...OUTSIDE]) {
      for (let it = 0; it < Math.max(20, FUZZ_ITERS / 4); it++) {
        const len = it < lengths.length ? lengths[it] : (rand() * 300) | 0;
        const msg = binString(rand, len);
        const label = `${JSON.stringify(options)} iter ${it} len ${len}`;
        const a = new Md2(opts(options));
        const b = new LegacyMd2(opts(options));
        for (let pos = 0; pos < len;) {
          const n = (rand() * 40) | 0;
          const chunk = msg.substr(pos, n);
          a.update(chunk);
          b.update(chunk);
          pos += n;
          assert.equal(json(a), json(b), `${label} pos ${pos}`);
        }
        assert.equal(hex(a), hex(b), label);
        assert.equal(json(a), json(b), `${label} state after finalize`);
        assert.deepEqual(a.options, b.options, `${label} options`);
      }
    }
  });

  test('options inside the envelope run in wasm, others in the original', () => {
    for (const options of INSIDE) {
      assert.equal(wasmUsed(() => {
        const h = new Md2(opts(options));
        h.update('x'.repeat(2 * B + 2));
        h.finalize();
      }), 2, JSON.stringify(options));
    }
    for (const options of OUTSIDE) {
      const used = wasmUsed(() => {
        const a = new Md2(opts(options));
        attempt(() => {
          a.update('x'.repeat(2 * B + 2));
          a.finalize();
        });
      });
      assert.equal(used, 0, `${JSON.stringify(options)} must not use wasm`);
    }
  });

  test('options changed after construction are honored on the next call', () => {
    const a = new Md2();
    const b = new LegacyMd2();
    a.update('a'.repeat(B + 6));
    b.update('a'.repeat(B + 6));
    for (const rounds of [17, 5, 2.5, 1, 300, '3', 0, 19]) {
      a.options.rounds = rounds;
      b.options.rounds = rounds;
      assert.deepEqual(attempt(() => (a.update('b'.repeat(B + 6)), json(a))), attempt(() => (b.update('b'.repeat(B + 6)), json(b))), `rounds ${rounds}`);
    }
    assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
  });

  test('options that are not an object behave like the original', () => {
    for (const options of [null, 5, 'x', undefined]) {
      const a = new Md2();
      const b = new LegacyMd2();
      a.options = options;
      b.options = options;
      assert.deepEqual(attempt(() => (a.update('x'.repeat(40)), json(a))), attempt(() => (b.update('x'.repeat(40)), json(b))), String(options));
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)), String(options));
    }
  });

  test('finalize() twice and update() after finalize() match the original', () => {
    same([update('abc'), finalize(), finalize(), finalize()], 'finalize x3');
    same([update('abc'), finalize(), update('abc'), finalize()], 'update after finalize');
    same([update('x'.repeat(B + 6)), finalize(), update('y'.repeat(B + 6)), finalize()], 'blocks after finalize');
    same([finalize(), update(''), finalize()], 'finalize before any update');
  });

  test('inputs larger than one wasm chunk (64 KiB), including exact multiples', () => {
    const rand = rng(3);
    for (const len of [65535, 65536, 65537, 131072, 200001, 1 << 20]) {
      const s = binString(rand, len);
      const a = new Md2();
      const b = new LegacyMd2();
      a.update(s);
      b.update(s);
      assert.equal(a.getState().length, len);
      assert.equal(hex(a), hex(b), `len ${len}`);
      assert.equal(json(a), json(b), `len ${len}`);
    }
  });

  test('reset() reuses the hasher', () => {
    const h = new Md2();
    h.update('abc');
    const first = h.finalize();
    h.reset();
    assert.equal(json(h), pristine());
    h.update('abc');
    assert.equal(h.finalize(), first);
  });

  test('getState() is the original JSON: nulls before the first block, bytes after, key order included', () => {
    const { a, b } = same([(h) => h.getState()], 'pristine');
    assert.equal(json(a), json(b));
    assert.equal(json(a), pristine());
    a.update('abc');
    b.update('abc');
    assert.equal(json(a), json(b), 'below one block nothing is processed');
    assert.equal(json(a), pristine().replace('"message":""', '"message":"abc"').replace('"length":0', '"length":3'));
    a.update('d'.repeat(B));
    b.update('d'.repeat(B));
    const s = a.getState();
    assert.deepEqual(Object.keys(s), ['message', 'length', 'hash', 'checksum']);
    assert.equal(s.message, 'ddd');
    assert.ok(s.hash.every((x) => Number.isInteger(x) && x >= 0 && x <= 255));
    assert.ok(s.checksum.every((x) => Number.isInteger(x) && x >= 0 && x <= 255));
    assert.equal(json(a), json(b));
    s.message = 'zzz';
    s.hash[0] = 7;
    assert.notEqual(a.getState().message, 'zzz');
  });

  test('getState()/finalize()/setState() per slice (the hasher-file pattern)', () => {
    const rand = rng(4);
    const data = binString(rand, 10000);
    const a = new Md2();
    const b = new LegacyMd2();
    let sa = null;
    let sb = null;
    for (let pos = 0; pos < data.length; pos += 4096) {
      const slice = data.substr(pos, 4096);
      if (sa) {
        a.setState(sa);
        b.setState(sb);
      }
      a.update(slice);
      b.update(slice);
      sa = a.getState();
      sb = b.getState();
      assert.deepEqual(sa, sb);
      assert.equal(hex(a), hex(b));
    }
  });

  test('setState() accepts what the original produced (nulls included) and keeps using wasm', () => {
    for (const prefix of ['', 'abc', 'q'.repeat(150)]) {
      const src = new LegacyMd2();
      src.update(prefix);
      const h = new Md2();
      h.setState(src.getState());
      h.update('tail'.repeat(5));
      src.update('tail'.repeat(5));
      assert.equal(wasmUsed(() => assert.equal(hex(h), hex(src))), 1);
    }
  });

  test('setState() keeps a live reference to the object, like the original', () => {
    const fresh = () => ({ message: '', length: 0, hash: new Array(48), checksum: new Array(16) });
    const oa = fresh();
    const ob = fresh();
    const a = new Md2();
    const b = new LegacyMd2();
    a.setState(oa);
    b.setState(ob);
    assert.equal(a.state, oa);
    a.update('z'.repeat(B + 6));
    b.update('z'.repeat(B + 6));
    assert.deepEqual(oa, ob);
    assert.equal(hex(a), hex(b));
    assert.deepEqual(oa, ob);
  });

  test('odd states take the original code path and stay faithful', () => {
    const bytes = (n, f) => Array.from({ length: n }, (_, i) => f(i));
    const h48 = bytes(48, (i) => (i * 7) & 255);
    const c16 = bytes(16, (i) => (i * 13 + 1) & 255);
    const odd = {
      'valid bytes': { message: 'abc', length: 3, hash: h48, checksum: c16 },
      'holes in hash': { message: 'abc', length: 3, hash: new Array(48), checksum: c16 },
      'some holes': { message: 'abc', length: 3, hash: h48.map((x, i) => (i % 3 ? x : undefined)), checksum: c16 },
      'nulls': { message: 'abc', length: 3, hash: new Array(48).fill(null), checksum: new Array(16).fill(null) },
      'reordered keys': { checksum: c16, hash: h48, length: 3, message: 'abc' },
      'extra key': { message: 'abc', length: 3, hash: h48, checksum: c16, extra: 1 },
      'missing checksum': { message: 'abc', length: 3, hash: h48 },
      'missing hash': { message: 'abc', length: 3, checksum: c16 },
      'word above 255': { message: 'abc', length: 3, hash: h48.map((x, i) => (i === 5 ? 256 + 7 : x)), checksum: c16 },
      'checksum above 255': { message: 'abc', length: 3, hash: h48, checksum: c16.map((x, i) => (i === 15 ? 300 : x)) },
      'negative word': { message: 'abc', length: 3, hash: h48.map((x, i) => (i === 40 ? -1 : x)), checksum: c16 },
      'fractional word': { message: 'abc', length: 3, hash: h48.map((x, i) => (i === 2 ? 1.5 : x)), checksum: c16 },
      'string word': { message: 'abc', length: 3, hash: h48.map((x, i) => (i === 0 ? '9' : x)), checksum: c16 },
      'NaN word': { message: 'abc', length: 3, hash: h48.map((x, i) => (i === 17 ? NaN : x)), checksum: c16 },
      'true word': { message: 'abc', length: 3, hash: h48.map((x, i) => (i === 3 ? true : x)), checksum: c16 },
      'short hash': { message: 'abc', length: 3, hash: h48.slice(0, 40), checksum: c16 },
      'long hash': { message: 'abc', length: 3, hash: [...h48, 1, 2], checksum: c16 },
      'short checksum': { message: 'abc', length: 3, hash: h48, checksum: c16.slice(0, 10) },
      'long checksum': { message: 'abc', length: 3, hash: h48, checksum: [...c16, 9] },
      'hash not an array': { message: 'abc', length: 3, hash: { 0: 1 }, checksum: c16 },
      'full block in message': { message: 'a'.repeat(B), length: B, hash: h48, checksum: c16 },
      'long message': { message: 'a'.repeat(200), length: 200, hash: h48, checksum: c16 },
      'wide message': { message: 'aĀb', length: 3, hash: h48, checksum: c16 },
      'wide block': { message: 'a'.repeat(B - 1) + 'Ā' + 'b'.repeat(B + 6), length: 2 * B + 6, hash: h48, checksum: c16 },
      'negative length': { message: '', length: -5, hash: h48, checksum: c16 },
      'NaN length': { message: '', length: NaN, hash: h48, checksum: c16 },
      'missing length': { message: 'abc', hash: h48, checksum: c16 },
      'array message': { message: ['a', 'b'], length: 2, hash: h48, checksum: c16 },
      'null': null,
      'string': 'abc',
      'number': 5,
      'empty object': {}
    };
    for (const [name, state] of Object.entries(odd)) {
      const steps = [
        (h) => h.setState(structuredClone(state)),
        (h) => h.getState(),
        update('more data'),
        (h) => h.getState(),
        finalize(),
        (h) => h.getState(),
        update('x'.repeat(2 * B + 2)),
        finalize()
      ];
      const a = new Md2();
      const b = new LegacyMd2();
      steps.forEach((step, i) => {
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
        assert.deepEqual(attempt(() => json(a)), attempt(() => json(b)), `${name}: step ${i} state`);
      });
    }
  });

  test('a state with bytes, holes or nulls is computed by wasm, identically', () => {
    const h48 = Array.from({ length: 48 }, (_, i) => (i * 5 + 3) & 255);
    const c16 = Array.from({ length: 16 }, (_, i) => (i * 11 + 2) & 255);
    for (const state of [
      { message: 'abc', length: 3, hash: h48, checksum: c16 },
      { message: 'abc', length: 3, hash: new Array(48), checksum: c16 },
      { message: 'abc', length: 3, hash: h48, checksum: new Array(16) },
      { message: 'abc', length: 3, hash: new Array(48).fill(null), checksum: new Array(16).fill(null) }
    ]) {
      const a = new Md2();
      const b = new LegacyMd2();
      a.setState(structuredClone(state));
      b.setState(structuredClone(state));
      assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b))), 1);
      assert.equal(json(a), json(b));
    }
  });

  test('state.length does not matter to MD2 (even when it is not a number)', () => {
    for (const length of [0, 3, 2 ** 31, 2 ** 53, -1, NaN, '7', null, undefined]) {
      const a = new Md2();
      const b = new LegacyMd2();
      const state = { message: 'abc', length, hash: new Array(48), checksum: new Array(16) };
      a.setState(structuredClone(state));
      b.setState(structuredClone(state));
      assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b), String(length))), 1);
      assert.equal(json(a), json(b));
    }
  });

  test('wide code units are handled by the original code, garbage included', () => {
    const cases = {
      cyrillic: 'Привет, мир',
      'single wide': 'Ā',
      'boundary 0xFF/0x100': 'ÿĀ',
      'max code unit': '￿',
      'lone surrogate': 'a\ud800b',
      emoji: 'x\u{1f600}y',
      'wide after a full block': 'a'.repeat(B) + 'ā' + 'b'.repeat(10),
      'wide in the first block': 'a'.repeat(10) + 'ā' + 'b'.repeat(B + 6),
      'wide in a later 64 KiB chunk': 'q'.repeat(70000) + 'Ω' + 'r'.repeat(5000),
      'wide exactly at a chunk boundary': 'q'.repeat(65536) + 'Ω' + 'r'.repeat(100),
      'wide only in the unprocessed tail': 'q'.repeat(B) + 'abcĀ'
    };
    for (const [name, wide] of Object.entries(cases)) {
      same([update('prefix'), update(wide), update('suffix'), finalize(), update(wide), finalize()], name);
      same([update(wide), finalize()], `${name} (fresh)`);
      same([update('a'.repeat(3 * B)), update(wide), update('b'.repeat(B + 1)), finalize()], `${name} (after wasm blocks)`);
    }
  });

  test('non-string input is coerced exactly like the original', () => {
    const inputs = {
      Uint8Array: new Uint8Array([1, 2]),
      number: 12345,
      array: ['a', 'b', 'c'],
      null: null,
      undefined,
      boolean: true,
      object: { toString: () => 'obj' },
      'String object': new String('boxed'),
      ArrayBuffer: new ArrayBuffer(4),
      symbol: Symbol('s')
    };
    for (const [name, input] of Object.entries(inputs)) {
      const steps = [update('abc'), (h) => h.update(input), update('d'.repeat(B + 6)), finalize(), (h) => h.getState()];
      const a = new Md2();
      const b = new LegacyMd2();
      for (const [i, step] of steps.entries()) {
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
      }
    }
  });

  test('.state is the live original-format object and direct mutation is honored', () => {
    const a = new Md2();
    const b = new LegacyMd2();
    a.update('abc');
    b.update('abc');
    assert.deepEqual(a.state, b.state);
    assert.ok(Object.hasOwn(a, 'state'), 'own data property, like the original');
    a.state.length = 1000;
    b.state.length = 1000;
    a.state.message = 'r'.repeat(B + 6);
    b.state.message = 'r'.repeat(B + 6);
    assert.equal(wasmUsed(() => a.process()), 1);
    b.process();
    assert.equal(json(a), json(b));
    a.state.hash[2] = 42;
    b.state.hash[2] = 42;
    a.state.checksum[5] = 77;
    b.state.checksum[5] = 77;
    assert.equal(hex(a), hex(b));
    const obj = { message: 'zz', length: 2, hash: new Array(48), checksum: new Array(16) };
    a.state = obj;
    assert.equal(a.state, obj);
    b.state = structuredClone(obj);
    assert.equal(hex(a), hex(b));
    assert.equal(obj.message, '', 'finalize wrote into the caller\'s object');
  });

  test('the state object and both arrays are updated in place', () => {
    const a = new Md2();
    const state = a.state;
    const { hash, checksum } = state;
    a.update('m'.repeat(200));
    a.finalize();
    assert.equal(a.state, state);
    assert.equal(a.state.hash, hash);
    assert.equal(a.state.checksum, checksum);
    const l = new LegacyMd2();
    l.update('m'.repeat(200));
    l.finalize();
    assert.deepEqual(hash, l.state.hash);
    assert.deepEqual(checksum, l.state.checksum);
  });

  test('subclasses that override internals keep the original behavior', () => {
    const seenA = [];
    const seenB = [];
    class FacadeSub extends Md2 {
      processBlock(block) {
        seenA.push(block[0]);
        super.processBlock(block);
      }
    }
    class LegacySub extends LegacyMd2 {
      processBlock(block) {
        seenB.push(block[0]);
        super.processBlock(block);
      }
    }
    const msg = 'The quick brown fox jumps over the lazy dog'.repeat(5);
    const a = new FacadeSub();
    const b = new LegacySub();
    assert.equal(wasmUsed(() => {
      a.update(msg);
      b.update(msg);
      assert.equal(hex(a), hex(b));
    }), 0, 'no wasm when processBlock is overridden');
    assert.ok(seenA.length > 0);
    assert.deepEqual(seenA, seenB);

    for (const name of ['addPaddingPKCS7', 'getStateHash', 'process']) {
      const body = {
        addPaddingPKCS7(n) { this.state.message += new Array(n + 1).join('\x03'); },
        getStateHash(size) { return 'custom-' + LegacyMd2.prototype.getStateHash.call(this, size); },
        process() { this.processed = (this.processed || 0) + 1; return LegacyMd2.prototype.process.call(this); }
      }[name];
      const FS = class extends Md2 {};
      const LS = class extends LegacyMd2 {};
      FS.prototype[name] = body;
      LS.prototype[name] = body;
      const x = new FS();
      const y = new LS();
      x.update('hello world'.repeat(10));
      y.update('hello world'.repeat(10));
      assert.equal(x.finalize(), y.finalize(), name);
      assert.equal(json(x), json(y), name);
      assert.equal(x.processed, y.processed, name);
    }

    class Plain extends Md2 {}
    assert.equal(wasmUsed(() => {
      const p = new Plain();
      p.update('a'.repeat(B));
      p.finalize();
    }), 2);
  });

  test('patching an internal on an instance is honored', () => {
    const a = new Md2();
    const b = new LegacyMd2();
    let calls = 0;
    for (const h of [a, b]) {
      const original = h.processBlock;
      h.processBlock = function (block) {
        calls++;
        return original.call(this, block);
      };
      h.update('x'.repeat(2 * B + 2));
    }
    assert.equal(calls, 4);
    assert.equal(hex(a), hex(b));
  });

  test('a changed blockSizeInBytes is honored by the original code', () => {
    same([(h) => { h.blockSizeInBytes = 8; }, update('x'.repeat(B + 6)), finalize()], 'blockSizeInBytes 8');
    same([(h) => { h.blockSizeInBytes = 32; }, update('x'.repeat(B + 36)), finalize()], 'blockSizeInBytes 32');
  });

  test('falls back to the original when WebAssembly is unavailable', () => {
    _internal.reset(true);
    try {
      assert.equal(wasmUsed(() => {
        for (const t of vec('md2')) {
          const x = new Md2();
          x.update(t.input);
          assert.equal(hex(x), t.hex);
        }
      }), 0);
    } finally {
      _internal.reset(false);
    }
    assert.equal(wasmUsed(() => {
      const h = new Md2();
      h.update('a');
      h.finalize();
    }), 1);
  });

  test('falls back when WebAssembly.Module throws (CSP, Workers) and remembers it', () => {
    const RealModule = WebAssembly.Module;
    _internal.reset(false);
    WebAssembly.Module = function () {
      throw new WebAssembly.CompileError('blocked by test');
    };
    try {
      const run = () => {
        const h = new Md2();
        h.update('abc'.repeat(30));
        const l = new LegacyMd2();
        l.update('abc'.repeat(30));
        assert.equal(hex(h), hex(l));
      };
      assert.equal(wasmUsed(run), 0);
      WebAssembly.Module = RealModule;
      assert.equal(wasmUsed(run), 0, 'failure is remembered, not retried');
    } finally {
      WebAssembly.Module = RealModule;
      _internal.reset(false);
    }
  });

  test('falls back when the WebAssembly global is missing (IE11, some embedded engines)', () => {
    const real = globalThis.WebAssembly;
    _internal.reset(false);
    delete globalThis.WebAssembly;
    try {
      const h = new Md2();
      h.update('abc'.repeat(30));
      const l = new LegacyMd2();
      l.update('abc'.repeat(30));
      assert.equal(hex(h), hex(l));
    } finally {
      globalThis.WebAssembly = real;
      _internal.reset(false);
    }
  });

  test('many hashers do not grow wasm memory or leak', () => {
    const rt = _internal.runtime();
    const before = rt.ex.memory.buffer.byteLength;
    assert.throws(() => rt.ex.memory.grow(1), 'memory is fixed size');
    const msg = 'm'.repeat(200);
    for (let i = 0; i < 5000; i++) {
      const h = new Md2();
      h.update(msg);
      h.finalize();
    }
    assert.equal(rt.ex.memory.buffer.byteLength, before);
    assert.equal(rt.u8.buffer, rt.ex.memory.buffer, 'cached view is still attached');
  });

  test('interleaved hashers do not share state', () => {
    const rand = rng(5);
    const hs = Array.from({ length: 8 }, () => ({ a: new Md2(), b: new LegacyMd2() }));
    for (let step = 0; step < 400; step++) {
      const { a, b } = hs[(rand() * hs.length) | 0];
      const chunk = binString(rand, (rand() * 100) | 0);
      a.update(chunk);
      b.update(chunk);
    }
    for (const { a, b } of hs) {
      assert.equal(json(a), json(b));
      assert.equal(hex(a), hex(b));
    }
  });

  test('Hmac works over the facade, including mutation of the hasher it is given', () => {
    const rand = rng(6);
    for (let it = 0; it < 50; it++) {
      const key = binString(rand, (rand() * 40) | 0);
      const msg = binString(rand, (rand() * 120) | 0);
      const a = new Md2();
      const b = new LegacyMd2();
      const ha = new Hmac(key, a);
      const hb = new Hmac(key, b);
      ha.update(msg);
      hb.update(msg);
      assert.equal(json(a), json(b), `key ${key.length} msg ${msg.length}`);
      assert.equal(toHex(ha.finalize()), toHex(hb.finalize()));
      assert.equal(json(a), json(b));
    }
  });

  test('rounds: every count 1..40 and a few large ones match the original', () => {
    for (let rounds = 1; rounds <= 40; rounds++) {
      for (const len of [0, 5, 16, 40]) {
        const msg = 'm'.repeat(len);
        const a = new Md2({ rounds });
        const b = new LegacyMd2({ rounds });
        a.update(msg);
        b.update(msg);
        assert.equal(hex(a), hex(b), `rounds ${rounds} len ${len}`);
        assert.equal(json(a), json(b));
      }
    }
    for (const rounds of [255, 256, 257, 511, 512, 1000, 4096]) {
      const a = new Md2({ rounds });
      const b = new LegacyMd2({ rounds });
      a.update('abc'.repeat(7));
      b.update('abc'.repeat(7));
      assert.equal(hex(a), hex(b), `rounds ${rounds}`);
    }
    // The round counter's low byte feeds the round function: 256 rounds differs from 0 (= 18).
    const run = (rounds) => {
      const h = new Md2({ rounds });
      h.update('abc');
      return hex(h);
    };
    assert.notEqual(run(256), run(1));
    assert.notEqual(run(18), run(19));
  });
});
