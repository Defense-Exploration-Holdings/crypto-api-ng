// MD5 facade tests: wasm-accelerated Md5 vs the untouched crypto-api 0.8.5 class.
//
// The oracle is packages/crypto-api/legacy/hasher/md5.mjs, a verbatim copy of
// the original (only import specifiers differ). Everything is compared through
// the public surface: digests, getState() JSON, thrown errors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import Md5, { _internal } from '../packages/crypto-api/src/hasher/md5.mjs';
import LegacyMd5 from '../packages/crypto-api/legacy/hasher/md5.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hasher32le from '../packages/crypto-api/src/hasher/hasher32le.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { ABI_VERSION } from '../packages/crypto-api/src/wasm/family.mjs';
import { EXPECTED_ABI_VERSION } from '../js/index.js';

const vectors = JSON.parse(readFileSync(new URL('./vectors/md5.json', import.meta.url), 'utf8'));
const hmacVectors = JSON.parse(readFileSync(new URL('./vectors/hmac-md5.json', import.meta.url), 'utf8'));
const FUZZ_ITERS = Number(process.env.FUZZ_ITERS || 200);

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

/** How many calls ran in wasm while `fn` ran. */
function wasmUsed(fn) {
  const before = _internal.wasmCalls();
  fn();
  return _internal.wasmCalls() - before;
}

/** Run `fn`, returning its value or the error it threw as `{error: 'Type: msg'}`. */
function attempt(fn) {
  try {
    return { value: fn() };
  } catch (e) {
    return { error: `${e.constructor.name}: ${e.message}` };
  }
}

/** Apply the same steps to a fresh facade and a fresh original and compare every observation. */
function same(steps, label) {
  const a = new Md5();
  const b = new LegacyMd5();
  steps.forEach((step, i) => {
    const ra = attempt(() => step(a));
    const rb = attempt(() => step(b));
    assert.deepEqual(ra, rb, `${label}: step ${i} result differs`);
    assert.equal(json(a), json(b), `${label}: step ${i} getState() differs`);
  });
  return { a, b };
}

const update = (s) => (h) => h.update(s);
const finalize = () => (h) => h.finalize();

test('facade uses wasm in a normal environment', () => {
  assert.ok(_internal.runtime(), 'wasm failed to instantiate; run `zig build js` first');
  assert.equal(wasmUsed(() => {
    const h = new Md5();
    h.update('x'.repeat(100));
    h.finalize();
  }), 2, 'one process() call and one finalize() call');
});

test('family ABI version matches the loader ABI version', () => {
  assert.equal(ABI_VERSION, EXPECTED_ABI_VERSION);
});

test('is a Hasher32le and an original Md5 shape', () => {
  const h = new Md5();
  assert.ok(h instanceof Hasher);
  assert.ok(h instanceof Hasher32le);
  assert.ok(h instanceof LegacyMd5);
  assert.equal(h.unitSize, 4);
  assert.equal(h.unitOrder, 0);
  assert.equal(h.blockSize, 16);
  assert.equal(h.blockSizeInBytes, 64);
  assert.deepEqual(h.options, {});
  const opts = {};
  assert.equal(new Md5(opts).options, opts, 'options object is kept by reference');
  for (const m of ['reset', 'update', 'finalize', 'getState', 'setState', 'process', 'processBlock']) {
    assert.equal(typeof h[m], 'function', m);
  }
});

for (const v of vectors) {
  test(`vector: ${v.name}`, () => {
    const h = new Md5();
    h.update(v.input);
    assert.equal(wasmUsed(() => assert.equal(hex(h), v.hex)), 1);
  });
}

for (const v of hmacVectors) {
  test(`vector: ${v.name}`, () => {
    for (const Class of [Md5, LegacyMd5]) {
      const hmac = new Hmac(v.key, new Class());
      hmac.update(v.input);
      assert.equal(toHex(hmac.finalize()), v.hex);
    }
  });
}

test('digest matches node:crypto for every length 0..300', () => {
  const rand = rng(1);
  for (let len = 0; len <= 300; len++) {
    const s = binString(rand, len);
    const h = new Md5();
    h.update(s);
    assert.equal(hex(h), createHash('md5').update(s, 'latin1').digest('hex'), `len ${len}`);
  }
});

test('differential: random messages split across random update() calls', () => {
  const rand = rng(2);
  const lengths = [0, 1, 15, 16, 17, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129];
  for (let it = 0; it < FUZZ_ITERS; it++) {
    const len = it < lengths.length ? lengths[it] : (rand() * 300) | 0;
    const msg = binString(rand, len);
    const a = new Md5();
    const b = new LegacyMd5();
    for (let pos = 0; pos < len;) {
      const n = (rand() * 80) | 0;
      const chunk = msg.substr(pos, n);
      a.update(chunk);
      b.update(chunk);
      pos += n;
      assert.equal(json(a), json(b), `iter ${it} len ${len} pos ${pos}`);
    }
    assert.equal(hex(a), hex(b), `iter ${it} len ${len}`);
    assert.equal(json(a), json(b), `iter ${it} state after finalize`);
  }
});

test('finalize() twice and update() after finalize() match the original', () => {
  same([update('abc'), finalize(), finalize(), finalize()], 'finalize x3');
  same([update('abc'), finalize(), update('abc'), finalize()], 'update after finalize');
  same([update('x'.repeat(100)), finalize(), update('y'.repeat(70)), finalize()], 'blocks after finalize');
  same([finalize(), update(''), finalize()], 'finalize before any update');
});

test('inputs larger than one wasm chunk (64 KiB), including exact multiples', () => {
  const rand = rng(3);
  for (const len of [65535, 65536, 65537, 131072, 200001, 1 << 20]) {
    const s = binString(rand, len);
    const h = new Md5();
    h.update(s);
    assert.equal(h.getState().length, len);
    assert.equal(hex(h), createHash('md5').update(s, 'latin1').digest('hex'), `len ${len}`);
  }
});

test('reset() reuses the hasher', () => {
  const h = new Md5();
  h.update('abc');
  h.finalize();
  h.reset();
  h.update('abc');
  assert.equal(hex(h), '900150983cd24fb0d6963f7d28e17f72');
});

test('getState() is the original JSON, key order included', () => {
  const { a, b } = same([(h) => h.getState()], 'pristine');
  assert.equal(json(a), '{"message":"","length":0,"hash":[1732584193,-271733879,-1732584194,271733878]}');
  assert.equal(json(b), json(a));
  a.update('abc');
  assert.equal(json(a), '{"message":"abc","length":3,"hash":[1732584193,-271733879,-1732584194,271733878]}');
  a.update('d'.repeat(62));
  assert.equal(JSON.parse(json(a)).message, 'd');
  assert.deepEqual(Object.keys(a.getState()), ['message', 'length', 'hash']);
  // getState() returns a copy: changing it does not change the hasher
  const s = a.getState();
  s.message = 'zzz';
  s.hash[0] = 7;
  assert.equal(JSON.parse(json(a)).message, 'd');
});

test('getState()/finalize()/setState() per slice (the hasher-file pattern)', () => {
  const rand = rng(4);
  const data = binString(rand, 10000);
  const a = new Md5();
  const b = new LegacyMd5();
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

test('setState() accepts what the original produced and keeps using wasm', () => {
  const src = new LegacyMd5();
  src.update('q'.repeat(150));
  const h = new Md5();
  h.setState(src.getState());
  h.update('tail');
  src.update('tail');
  assert.equal(wasmUsed(() => assert.equal(hex(h), hex(src))), 1);
});

test('setState() keeps a live reference to the object, like the original', () => {
  const iv = [1732584193, -271733879, -1732584194, 271733878];
  const oa = { message: '', length: 0, hash: [...iv] };
  const ob = { message: '', length: 0, hash: [...iv] };
  const a = new Md5();
  const b = new LegacyMd5();
  a.setState(oa);
  b.setState(ob);
  assert.equal(a.state, oa);
  a.update('z'.repeat(100));
  b.update('z'.repeat(100));
  assert.deepEqual(oa, ob, 'the caller\'s object follows the hasher');
  assert.equal(hex(a), hex(b));
  assert.deepEqual(oa, ob);
});

test('odd states take the original code path and stay faithful', () => {
  const iv = [1732584193, -271733879, -1732584194, 271733878];
  const odd = {
    'reordered keys': { hash: iv, length: 3, message: 'abc' },
    'extra key': { message: 'abc', length: 3, hash: iv, extra: 1 },
    'unsigned words': { message: 'abc', length: 3, hash: [4023233417, 1, 2, 3] },
    'huge words': { message: 'abc', length: 3, hash: [2 ** 40 + 5, -(2 ** 33), 2, 3] },
    'fractional word': { message: 'abc', length: 3, hash: [1.5, 1, 2, 3] },
    'string word': { message: 'abc', length: 3, hash: ['1', 1, 2, 3] },
    'word near 2^53 (double sum rounds)': { message: 'x'.repeat(130), length: 130, hash: [2 ** 53 - 1, -(2 ** 53 - 1), 2 ** 53 - 3, 2 ** 52 + 1] },
    'NaN word': { message: 'abc', length: 3, hash: [NaN, 1, 2, 3] },
    'short hash': { message: 'abc', length: 3, hash: [1, 2, 3] },
    'long hash': { message: 'abc', length: 3, hash: [1, 2, 3, 4, 5] },
    'full block in message': { message: 'a'.repeat(64), length: 64, hash: iv },
    'long message': { message: 'a'.repeat(200), length: 200, hash: iv },
    'wide message': { message: 'aĀb', length: 3, hash: iv },
    'wide block': { message: 'a'.repeat(63) + 'Ā' + 'b'.repeat(70), length: 134, hash: iv },
    'negative length': { message: '', length: -5, hash: iv },
    'fractional length': { message: '', length: 2.5, hash: iv },
    'string length': { message: '', length: '7', hash: iv },
    'NaN length': { message: '', length: NaN, hash: iv },
    'missing length': { message: 'abc', hash: iv },
    'missing hash': { message: 'abc', length: 3 },
    'array message': { message: ['a', 'b'], length: 2, hash: iv },
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
      update('x'.repeat(130)),
      finalize()
    ];
    const a = new Md5();
    const b = new LegacyMd5();
    steps.forEach((step, i) => {
      assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
      assert.deepEqual(attempt(() => json(a)), attempt(() => json(b)), `${name}: step ${i} state`);
    });
  }
});

test('integer hash words outside int32 are still computed by wasm, identically', () => {
  const state = { message: 'abc', length: 3, hash: [4023233417, 1, 2 ** 40 + 5, -(2 ** 52)] };
  const a = new Md5();
  const b = new LegacyMd5();
  a.setState(structuredClone(state));
  b.setState(structuredClone(state));
  assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b))), 1);
  assert.equal(json(a), json(b));
});

test('the 2^31-byte length bug is kept (setState with huge lengths)', () => {
  const iv = [1732584193, -271733879, -1732584194, 271733878];
  const lengths = [(2 ** 31) - 1, 2 ** 31, 2 ** 31 + 5, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 7, 3 * 2 ** 31 + 9, 2 ** 40 + 3, Number.MAX_SAFE_INTEGER, -1, -(2 ** 31), -(2 ** 33) - 5];
  for (const length of lengths) {
    for (const message of ['', 'abc', 'x'.repeat(55), 'y'.repeat(56), 'z'.repeat(63)]) {
      const a = new Md5();
      const b = new LegacyMd5();
      a.setState({ message, length, hash: [...iv] });
      b.setState({ message, length, hash: [...iv] });
      assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b), `length ${length} message ${message.length}`)), 1);
      assert.equal(json(a), json(b));
    }
  }
});

test('lengths beyond 2^32 stay exact through update() bookkeeping', () => {
  const a = new Md5();
  a.setState({ message: '', length: 2 ** 32 - 3, hash: [1732584193, -271733879, -1732584194, 271733878] });
  a.update('abcdef');
  assert.equal(a.getState().length, 2 ** 32 + 3);
});

test('wide code units are handled by the original code, garbage included', () => {
  const cases = {
    'cyrillic': 'Привет, мир',
    'single wide': 'Ā',
    'boundary 0xFF/0x100': 'ÿĀ',
    'max code unit': '￿',
    'lone surrogate': 'a\ud800b',
    'emoji': 'x\u{1f600}y',
    'wide after a full block': 'a'.repeat(64) + 'ā' + 'b'.repeat(10),
    'wide in the first block': 'a'.repeat(30) + 'ā' + 'b'.repeat(100),
    'wide in a later 64 KiB chunk': 'q'.repeat(70000) + 'Ω' + 'r'.repeat(5000),
    'wide exactly at a chunk boundary': 'q'.repeat(65536) + 'Ω' + 'r'.repeat(100),
    'wide only in the unprocessed tail': 'q'.repeat(64) + 'abcĀ'
  };
  for (const [name, wide] of Object.entries(cases)) {
    same([update('prefix'), update(wide), update('suffix'), finalize(), update(wide), finalize()], name);
    same([update(wide), finalize()], `${name} (fresh)`);
  }
});

test('non-string input is coerced exactly like the original', () => {
  const inputs = {
    'Uint8Array': new Uint8Array([1, 2]),
    'number': 12345,
    'array': ['a', 'b', 'c'],
    'array of numbers': [104, 105],
    'null': null,
    'undefined': undefined,
    'boolean': true,
    'object': { toString: () => 'obj' },
    'String object': new String('boxed'),
    'ArrayBuffer': new ArrayBuffer(4),
    'symbol': Symbol('s')
  };
  for (const [name, input] of Object.entries(inputs)) {
    const steps = [update('abc'), (h) => h.update(input), update('d'.repeat(70)), finalize(), (h) => h.getState()];
    const a = new Md5();
    const b = new LegacyMd5();
    for (const [i, step] of steps.entries()) {
      assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
    }
  }
});

test('.state is the live original-format object and direct mutation is honored', () => {
  const a = new Md5();
  const b = new LegacyMd5();
  a.update('abc');
  b.update('abc');
  assert.deepEqual(a.state, b.state);
  assert.equal(a.state, a.state);
  assert.ok(Object.hasOwn(a, 'state'), 'own data property, like the original');
  assert.deepEqual(Object.keys(a), Object.keys(b));
  a.state.length = 1000;
  b.state.length = 1000;
  a.state.hash[2] = 42;
  b.state.hash[2] = 42;
  a.state.message = 'r'.repeat(70);
  b.state.message = 'r'.repeat(70);
  assert.equal(wasmUsed(() => a.process()), 1);
  b.process();
  assert.equal(json(a), json(b));
  assert.equal(hex(a), hex(b));
  const obj = { message: 'zz', length: 2, hash: [1, 2, 3, 4] };
  a.state = obj;
  assert.equal(a.state, obj);
  b.state = structuredClone(obj);
  assert.equal(hex(a), hex(b));
  assert.equal(obj.message, '', 'finalize wrote into the caller\'s object');
});

test('the hash array and state object are updated in place', () => {
  const a = new Md5();
  const state = a.state;
  const hash = a.state.hash;
  a.update('m'.repeat(200));
  a.finalize();
  assert.equal(a.state, state);
  assert.equal(a.state.hash, hash);
  const l = new LegacyMd5();
  l.update('m'.repeat(200));
  l.finalize();
  assert.deepEqual(hash, l.state.hash);
});

test('subclasses that override internals keep the original behavior', () => {
  const seenA = [];
  const seenB = [];
  class FacadeSub extends Md5 {
    processBlock(block) {
      seenA.push(block[0]);
      super.processBlock(block);
    }
  }
  class LegacySub extends LegacyMd5 {
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

  for (const name of ['addLengthBits', 'addPaddingISO7816', 'getStateHash', 'process']) {
    const body = {
      addLengthBits() { this.state.message += '\x01\x02\x03\x04\x05\x06\x07\x08'; },
      addPaddingISO7816(n) { this.state.message += '\x80' + new Array(n).join('\x01'); },
      getStateHash() { return 'custom-' + LegacyMd5.prototype.getStateHash.call(this); },
      process() { this.processed = (this.processed || 0) + 1; return LegacyMd5.prototype.process.call(this); }
    }[name];
    const F = class extends Md5 {};
    const L = class extends LegacyMd5 {};
    F.prototype[name] = body;
    L.prototype[name] = body;
    const x = new F();
    const y = new L();
    x.update('hello world'.repeat(10));
    y.update('hello world'.repeat(10));
    assert.equal(x.finalize(), y.finalize(), name);
    assert.equal(json(x), json(y), name);
    assert.equal(x.processed, y.processed, name);
  }

  // an empty subclass keeps the fast path
  class Plain extends Md5 {}
  assert.equal(wasmUsed(() => {
    const p = new Plain();
    p.update('a'.repeat(64));
    p.finalize();
  }), 2);
});

test('patching an internal on an instance is honored', () => {
  const a = new Md5();
  const b = new LegacyMd5();
  let calls = 0;
  for (const h of [a, b]) {
    const original = h.processBlock;
    h.processBlock = function (block) {
      calls++;
      return original.call(this, block);
    };
    h.update('x'.repeat(130));
  }
  assert.equal(calls, 4);
  assert.equal(hex(a), hex(b));
});

test('falls back to the original when WebAssembly is unavailable', () => {
  _internal.reset(true);
  try {
    assert.equal(wasmUsed(() => {
      for (const v of vectors) {
        const x = new Md5();
        x.update(v.input);
        assert.equal(hex(x), v.hex);
      }
    }), 0);
    const h = new Md5();
    h.update('abc'.repeat(50));
    const l = new LegacyMd5();
    l.update('abc'.repeat(50));
    assert.equal(json(h), json(l));
  } finally {
    _internal.reset(false);
  }
  assert.equal(wasmUsed(() => {
    const h = new Md5();
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
    assert.equal(wasmUsed(() => {
      const h = new Md5();
      h.update('abc');
      assert.equal(hex(h), '900150983cd24fb0d6963f7d28e17f72');
    }), 0);
    // the failure is remembered, not retried
    WebAssembly.Module = RealModule;
    assert.equal(wasmUsed(() => {
      const h = new Md5();
      h.update('abc');
      h.finalize();
    }), 0);
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
    const h = new Md5();
    h.update('abc'.repeat(30));
    const l = new LegacyMd5();
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
  const msg = 'm'.repeat(1000);
  for (let i = 0; i < 20000; i++) {
    const h = new Md5();
    h.update(msg);
    h.finalize();
  }
  assert.equal(rt.ex.memory.buffer.byteLength, before);
  assert.equal(rt.u8.buffer, rt.ex.memory.buffer, 'cached view is still attached');
});

test('interleaved hashers do not share state', () => {
  const rand = rng(5);
  const hs = Array.from({ length: 8 }, () => ({ a: new Md5(), b: new LegacyMd5() }));
  for (let step = 0; step < 400; step++) {
    const { a, b } = hs[(rand() * hs.length) | 0];
    const chunk = binString(rand, (rand() * 200) | 0);
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
    const key = binString(rand, (rand() * 140) | 0);
    const msg = binString(rand, (rand() * 200) | 0);
    const a = new Md5();
    const b = new LegacyMd5();
    const ha = new Hmac(key, a);
    const hb = new Hmac(key, b);
    ha.update(msg);
    hb.update(msg);
    assert.equal(json(a), json(b), `key ${key.length} msg ${msg.length}`);
    assert.equal(toHex(ha.finalize()), toHex(hb.finalize()));
    assert.equal(json(a), json(b));
  }
});
