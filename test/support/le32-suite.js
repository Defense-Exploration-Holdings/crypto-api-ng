// Differential test suite for the wasm-accelerated Hasher32le facades that
// share packages/crypto-api/src/wasm/le32.mjs (MD4, HAS-160, RIPEMD). It is the
// checklist of test/md5.test.js, run for one "case" (an algorithm with one
// option set) at a time:
//
//   defineSuite({name, Facade, Legacy, internal, options, vectors, ...})
//
// The oracle is the verbatim 0.8.5 class under packages/crypto-api/legacy/.
// Everything is compared through the public surface plus the live `.state`
// object: digests, getState() JSON, thrown errors, array identity.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import Hasher from '../../packages/crypto-api/src/hasher/hasher.mjs';
import Hasher32le from '../../packages/crypto-api/src/hasher/hasher32le.mjs';
import Hmac from '../../packages/crypto-api/src/mac/hmac.mjs';
import { toHex } from '../../packages/crypto-api/src/encoder/hex.mjs';

export const FUZZ_ITERS = Number(process.env.FUZZ_ITERS || 200);

export const readVectors = (file) => JSON.parse(readFileSync(new URL(`../vectors/${file}.json`, import.meta.url), 'utf8'));

const hex = (h) => toHex(h.finalize());
const json = (h) => JSON.stringify(h.getState());

/** Deterministic PRNG (mulberry32) so failures reproduce. */
export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function binString(rand, len) {
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

/**
 * @param {Object} c
 * @param {string} c.name - label, e.g. 'md4' or 'ripemd160'
 * @param {Function} c.Facade
 * @param {Function} c.Legacy
 * @param {Object} c.internal - the facade's `_internal` hooks
 * @param {Object} [c.options] - constructor options for this case
 * @param {number} c.words - hash words
 * @param {string} [c.vectors] - file under test/vectors
 * @param {string} [c.hmacVectors]
 * @param {string} [c.node] - node:crypto algorithm name, when OpenSSL has it
 * @param {boolean} [c.shadowedProcessBlock] - reset() puts processBlock on the instance (RIPEMD)
 * @param {boolean} c.replacesHash - the original assigns a new `state.hash` array per block (MD4)
 */
export function defineSuite(c) {
  const { Facade, Legacy, internal, words } = c;
  const label = (s) => `${c.name}: ${s}`;
  const opts = () => (c.options ? structuredClone(c.options) : undefined);
  const mk = (Class) => new Class(opts());
  const mkFacade = () => mk(Facade);
  const mkLegacy = () => mk(Legacy);
  const iv = mkLegacy().getState().hash;

  /** How many calls ran in wasm while `fn` ran. */
  const wasmUsed = (fn) => {
    const before = internal.wasmCalls();
    fn();
    return internal.wasmCalls() - before;
  };

  /** Apply the same steps to a fresh facade and a fresh original and compare every observation. */
  function same(steps, name, make = [mkFacade, mkLegacy]) {
    const a = make[0]();
    const b = make[1]();
    steps.forEach((step, i) => {
      const ra = attempt(() => step(a));
      const rb = attempt(() => step(b));
      assert.deepEqual(ra, rb, `${name}: step ${i} result differs`);
      assert.equal(attempt(() => json(a)).value ?? attempt(() => json(a)).error,
        attempt(() => json(b)).value ?? attempt(() => json(b)).error, `${name}: step ${i} getState() differs`);
    });
    return { a, b };
  }

  test(label('facade uses wasm in a normal environment'), () => {
    assert.ok(internal.runtime(), 'wasm failed to instantiate; run `zig build js` first');
    assert.equal(wasmUsed(() => {
      const h = mkFacade();
      h.update('x'.repeat(100));
      h.finalize();
    }), 2, 'one process() call and one finalize() call');
  });

  test(label('class shape matches the original'), () => {
    const h = mkFacade();
    assert.ok(h instanceof Hasher);
    assert.ok(h instanceof Hasher32le);
    assert.ok(h instanceof Legacy);
    assert.equal(Facade.name, Legacy.name);
    assert.equal(Facade.length, Legacy.length, 'constructor arity');
    assert.equal(h.unitSize, 4);
    assert.equal(h.blockSizeInBytes, 64);
    assert.deepEqual(Object.keys(h), Object.keys(mkLegacy()));
    assert.deepEqual(h.options, mkLegacy().options);
    const o = opts() ?? {};
    assert.equal(new Facade(o).options, o, 'options object is kept by reference');
    for (const m of ['reset', 'update', 'finalize', 'getState', 'setState', 'process', 'processBlock']) {
      assert.equal(typeof h[m], 'function', m);
    }
  });

  if (c.vectors) {
    for (const v of readVectors(c.vectors)) {
      test(label(`vector ${v.name}`), () => {
        const h = mkFacade();
        h.update(v.input);
        assert.equal(wasmUsed(() => assert.equal(hex(h), v.hex)), 1);
      });
    }
  }

  if (c.hmacVectors) {
    for (const v of readVectors(c.hmacVectors)) {
      test(label(`vector ${v.name}`), () => {
        for (const make of [mkFacade, mkLegacy]) {
          const hmac = new Hmac(v.key, make());
          hmac.update(v.input);
          assert.equal(toHex(hmac.finalize()), v.hex);
        }
      });
    }
  }

  if (c.node) {
    test(label(`digest matches node:crypto for every length 0..300`), () => {
      const rand = rng(1);
      for (let len = 0; len <= 300; len++) {
        const s = binString(rand, len);
        const h = mkFacade();
        h.update(s);
        assert.equal(hex(h), createHash(c.node).update(s, 'latin1').digest('hex'), `len ${len}`);
      }
    });
  }

  test(label('differential: random messages split across random update() calls'), () => {
    const rand = rng(2);
    const lengths = [0, 1, 15, 16, 17, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129];
    for (let it = 0; it < FUZZ_ITERS; it++) {
      const len = it < lengths.length ? lengths[it] : (rand() * 300) | 0;
      const msg = binString(rand, len);
      const a = mkFacade();
      const b = mkLegacy();
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

  test(label('finalize() twice and update() after finalize() match the original'), () => {
    same([update('abc'), finalize(), finalize(), finalize()], 'finalize x3');
    same([update('abc'), finalize(), update('abc'), finalize()], 'update after finalize');
    same([update('x'.repeat(100)), finalize(), update('y'.repeat(70)), finalize()], 'blocks after finalize');
    same([finalize(), update(''), finalize()], 'finalize before any update');
  });

  test(label('inputs larger than one wasm chunk (64 KiB), including exact multiples'), () => {
    const rand = rng(3);
    for (const len of [65535, 65536, 65537, 131072, 200001]) {
      const s = binString(rand, len);
      const a = mkFacade();
      const b = mkLegacy();
      a.update(s);
      b.update(s);
      assert.equal(a.getState().length, len);
      assert.equal(hex(a), hex(b), `len ${len}`);
    }
  });

  test(label('reset() reuses the hasher'), () => {
    const h = mkFacade();
    h.update('abc');
    h.finalize();
    h.reset();
    h.update('abc');
    const l = mkLegacy();
    l.update('abc');
    assert.equal(hex(h), hex(l));
  });

  test(label('getState() is the original JSON, key order included'), () => {
    const { a, b } = same([(h) => h.getState()], 'pristine');
    assert.equal(json(a), json(b));
    a.update('abc');
    b.update('abc');
    assert.equal(json(a), json(b));
    a.update('d'.repeat(62));
    b.update('d'.repeat(62));
    assert.equal(json(a), json(b));
    assert.equal(JSON.parse(json(a)).message, 'd');
    assert.deepEqual(Object.keys(a.getState()), ['message', 'length', 'hash']);
    const s = a.getState();
    s.message = 'zzz';
    s.hash[0] = 7;
    assert.equal(JSON.parse(json(a)).message, 'd', 'getState() returns a copy');
  });

  test(label('getState()/finalize()/setState() per slice (the hasher-file pattern)'), () => {
    const rand = rng(4);
    const data = binString(rand, 10000);
    const a = mkFacade();
    const b = mkLegacy();
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

  test(label('setState() accepts what the original produced and keeps using wasm'), () => {
    const src = mkLegacy();
    src.update('q'.repeat(150));
    const h = mkFacade();
    h.setState(src.getState());
    h.update('tail');
    src.update('tail');
    assert.equal(wasmUsed(() => assert.equal(hex(h), hex(src))), 1);
  });

  test(label('setState() keeps a live reference to the object, like the original'), () => {
    const oa = { message: '', length: 0, hash: [...iv] };
    const ob = { message: '', length: 0, hash: [...iv] };
    const a = mkFacade();
    const b = mkLegacy();
    a.setState(oa);
    b.setState(ob);
    assert.equal(a.state, oa);
    a.update('z'.repeat(100));
    b.update('z'.repeat(100));
    assert.deepEqual(oa, ob, 'the caller\'s object follows the hasher');
    assert.equal(hex(a), hex(b));
    assert.deepEqual(oa, ob);
  });

  test(label('odd states take the original code path and stay faithful'), () => {
    const w = (...head) => [...head, ...iv.slice(head.length)];
    const odd = {
      'reordered keys': { hash: [...iv], length: 3, message: 'abc' },
      'extra key': { message: 'abc', length: 3, hash: [...iv], extra: 1 },
      'unsigned words': { message: 'abc', length: 3, hash: w(4023233417, 1, 2, 3) },
      'huge words': { message: 'abc', length: 3, hash: w(2 ** 40 + 5, -(2 ** 33), 2, 3) },
      'words near 2^52': { message: 'x'.repeat(130), length: 130, hash: w(2 ** 52, -(2 ** 52), 2 ** 52 - 1, 3) },
      'words near 2^53 (the double sum rounds)': { message: 'x'.repeat(130), length: 130, hash: w(2 ** 53 - 1, -(2 ** 53 - 1), 2 ** 53 - 3, 2 ** 52 + 1) },
      'words beyond 2^53': { message: 'x'.repeat(130), length: 130, hash: w(2 ** 60, -(2 ** 70), 1e21, 3) },
      'fractional word': { message: 'abc', length: 3, hash: w(1.5, 1, 2, 3) },
      'string word': { message: 'abc', length: 3, hash: w('1', 1, 2, 3) },
      'NaN word': { message: 'abc', length: 3, hash: w(NaN, 1, 2, 3) },
      'Infinity word': { message: 'abc', length: 3, hash: w(Infinity, 1, 2, 3) },
      'short hash': { message: 'abc', length: 3, hash: [1, 2, 3] },
      'long hash': { message: 'abc', length: 3, hash: [...iv, 1, 2, 3] },
      'sparse hash': { message: 'abc', length: 3, hash: new Array(words) },
      'full block in message': { message: 'a'.repeat(64), length: 64, hash: [...iv] },
      'long message': { message: 'a'.repeat(200), length: 200, hash: [...iv] },
      'wide message': { message: 'aĀb', length: 3, hash: [...iv] },
      'wide block': { message: 'a'.repeat(63) + 'Ā' + 'b'.repeat(70), length: 134, hash: [...iv] },
      'negative length': { message: '', length: -5, hash: [...iv] },
      'fractional length': { message: '', length: 2.5, hash: [...iv] },
      'string length': { message: '', length: '7', hash: [...iv] },
      'NaN length': { message: '', length: NaN, hash: [...iv] },
      'missing length': { message: 'abc', hash: [...iv] },
      'missing hash': { message: 'abc', length: 3 },
      'array message': { message: ['a', 'b'], length: 2, hash: [...iv] },
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
      const a = mkFacade();
      const b = mkLegacy();
      steps.forEach((step, i) => {
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
        assert.deepEqual(attempt(() => json(a)), attempt(() => json(b)), `${name}: step ${i} state`);
      });
    }
  });

  test(label('integer hash words outside int32 are still computed by wasm, identically'), () => {
    const state = { message: 'abc', length: 3, hash: [4023233417, 1, 2 ** 40 + 5, -(2 ** 33), ...iv.slice(4)] };
    const a = mkFacade();
    const b = mkLegacy();
    a.setState(structuredClone(state));
    b.setState(structuredClone(state));
    assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b))), 1);
    assert.equal(json(a), json(b));
  });

  test(label('huge lengths give the 64-bit length field (setState), wasm and JS alike'), () => {
    const lengths = [(2 ** 31) - 1, 2 ** 31, 2 ** 31 + 5, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 7, 3 * 2 ** 31 + 9, 2 ** 40 + 3, Number.MAX_SAFE_INTEGER, -1, -(2 ** 31), -(2 ** 33) - 5];
    for (const length of lengths) {
      for (const message of ['', 'abc', 'x'.repeat(55), 'y'.repeat(56), 'z'.repeat(63)]) {
        const a = mkFacade();
        const b = mkLegacy();
        a.setState({ message, length, hash: [...iv] });
        b.setState({ message, length, hash: [...iv] });
        assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b), `length ${length} message ${message.length}`)), 1);
        assert.equal(json(a), json(b));
      }
    }
  });

  test(label('lengths beyond 2^32 stay exact through update() bookkeeping'), () => {
    const a = mkFacade();
    a.setState({ message: '', length: 2 ** 32 - 3, hash: [...iv] });
    a.update('abcdef');
    assert.equal(a.getState().length, 2 ** 32 + 3);
  });

  test(label('wide code units are handled by the original code, garbage included'), () => {
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

  test(label('non-string input is coerced exactly like the original'), () => {
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
      const a = mkFacade();
      const b = mkLegacy();
      for (const [i, step] of steps.entries()) {
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
      }
    }
  });

  test(label('.state is the live original-format object and direct mutation is honored'), () => {
    const a = mkFacade();
    const b = mkLegacy();
    a.update('abc');
    b.update('abc');
    assert.deepEqual(a.state, b.state);
    assert.ok(Object.hasOwn(a, 'state'), 'own data property, like the original');
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
    const obj = { message: 'zz', length: 2, hash: [...iv] };
    a.state = obj;
    assert.equal(a.state, obj);
    b.state = structuredClone(obj);
    assert.equal(hex(a), hex(b));
    assert.equal(obj.message, '', 'finalize wrote into the caller\'s object');
  });

  test(label(c.replacesHash
    ? 'state.hash is replaced by a new array per block, like the original'
    : 'the hash array and state object are updated in place, like the original'), () => {
    for (const make of [mkFacade, mkLegacy]) {
      const a = make();
      const state = a.state;
      const hash = a.state.hash;
      a.update('m'.repeat(200));
      assert.equal(a.state, state);
      assert.equal(a.state.hash === hash, !c.replacesHash, `after update (${make === mkFacade ? 'facade' : 'original'})`);
      const mid = a.state.hash;
      a.update('n'.repeat(10));
      assert.equal(a.state.hash === mid, true, 'no block processed, same array');
      a.finalize();
      assert.equal(a.state.hash === mid, !c.replacesHash, 'after finalize');
    }
    // An alias taken before a block is processed sees the same values in both implementations.
    const a = mkFacade();
    const b = mkLegacy();
    const ha = a.state.hash;
    const hb = b.state.hash;
    a.update('m'.repeat(64));
    b.update('m'.repeat(64));
    assert.deepEqual(ha, hb);
  });

  test(label('subclasses that override internals keep the original behavior'), () => {
    const seenA = [];
    const seenB = [];
    class FacadeSub extends Facade {
      processBlock(block) {
        seenA.push(block[0]);
        super.processBlock(block);
      }
    }
    class LegacySub extends Legacy {
      processBlock(block) {
        seenB.push(block[0]);
        super.processBlock(block);
      }
    }
    const msg = 'The quick brown fox jumps over the lazy dog'.repeat(5);
    const a = new FacadeSub(opts());
    const b = new LegacySub(opts());
    const used = wasmUsed(() => {
      a.update(msg);
      b.update(msg);
      assert.equal(hex(a), hex(b));
    });
    if (c.shadowedProcessBlock) {
      // RIPEMD's reset() stores processBlock128/160/256/320 on the instance, which
      // shadows a subclass's `processBlock`: the original never calls it either.
      assert.deepEqual(seenA, []);
      assert.deepEqual(seenB, []);
    } else {
      assert.equal(used, 0, 'no wasm when processBlock is overridden');
      assert.ok(seenA.length > 0);
    }
    assert.deepEqual(seenA, seenB);

    for (const name of ['addLengthBits', 'addPaddingISO7816', 'getStateHash', 'process']) {
      const body = {
        addLengthBits() { this.state.message += '\x01\x02\x03\x04\x05\x06\x07\x08'; },
        addPaddingISO7816(n) { this.state.message += '\x80' + new Array(n).join('\x01'); },
        getStateHash() { return 'custom-' + Legacy.prototype.getStateHash.call(this); },
        process() { this.processed = (this.processed || 0) + 1; return Legacy.prototype.process.call(this); }
      }[name];
      const F = class extends Facade {};
      const L = class extends Legacy {};
      F.prototype[name] = body;
      L.prototype[name] = body;
      const x = new F(opts());
      const y = new L(opts());
      x.update('hello world'.repeat(10));
      y.update('hello world'.repeat(10));
      assert.equal(x.finalize(), y.finalize(), name);
      assert.equal(json(x), json(y), name);
      assert.equal(x.processed, y.processed, name);
    }

    // a subclass that overrides `update` and calls super still accelerates
    class Plain extends Facade {
      update(m) { return super.update(m); }
    }
    assert.equal(wasmUsed(() => {
      const p = new Plain(opts());
      p.update('a'.repeat(64));
      p.finalize();
    }), 2);
  });

  test(label('patching an internal on an instance is honored'), () => {
    const a = mkFacade();
    const b = mkLegacy();
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
    assert.equal(json(a), json(b));
  });

  test(label('a changed blockSizeInBytes is the original code'), () => {
    for (const size of [32, 128, '64', 64.5, 63]) {
      const a = mkFacade();
      const b = mkLegacy();
      a.blockSizeInBytes = size;
      b.blockSizeInBytes = size;
      const ra = attempt(() => { a.update('x'.repeat(200)); return hex(a); });
      const rb = attempt(() => { b.update('x'.repeat(200)); return hex(b); });
      assert.deepEqual(ra, rb, `blockSizeInBytes ${size}`);
      assert.equal(attempt(() => json(a)).value, attempt(() => json(b)).value);
    }
  });

  test(label('falls back to the original when WebAssembly is unavailable'), () => {
    internal.reset(true);
    try {
      assert.equal(wasmUsed(() => {
        const x = mkFacade();
        x.update('abc'.repeat(50));
        const l = mkLegacy();
        l.update('abc'.repeat(50));
        assert.equal(hex(x), hex(l));
      }), 0);
    } finally {
      internal.reset(false);
    }
    assert.equal(wasmUsed(() => {
      const h = mkFacade();
      h.update('a');
      h.finalize();
    }), 1);
  });

  test(label('falls back when WebAssembly.Module throws (CSP, Workers) and remembers it'), () => {
    const RealModule = WebAssembly.Module;
    internal.reset(false);
    WebAssembly.Module = function () {
      throw new WebAssembly.CompileError('blocked by test');
    };
    try {
      assert.equal(wasmUsed(() => {
        const h = mkFacade();
        h.update('abc');
        const l = mkLegacy();
        l.update('abc');
        assert.equal(hex(h), hex(l));
      }), 0);
      WebAssembly.Module = RealModule;
      assert.equal(wasmUsed(() => {
        const h = mkFacade();
        h.update('abc'.repeat(30));
        h.finalize();
      }), 0, 'the failure is remembered, not retried');
    } finally {
      WebAssembly.Module = RealModule;
      internal.reset(false);
    }
  });

  test(label('falls back when the WebAssembly global is missing (IE11, some embedded engines)'), () => {
    const real = globalThis.WebAssembly;
    internal.reset(false);
    delete globalThis.WebAssembly;
    try {
      const h = mkFacade();
      h.update('abc'.repeat(30));
      const l = mkLegacy();
      l.update('abc'.repeat(30));
      assert.equal(hex(h), hex(l));
    } finally {
      globalThis.WebAssembly = real;
      internal.reset(false);
    }
  });

  test(label('many hashers do not grow wasm memory or leak'), () => {
    const rt = internal.runtime();
    const before = rt.ex.memory.buffer.byteLength;
    assert.throws(() => rt.ex.memory.grow(1), 'memory is fixed size');
    const msg = 'm'.repeat(1000);
    for (let i = 0; i < 5000; i++) {
      const h = mkFacade();
      h.update(msg);
      h.finalize();
    }
    assert.equal(rt.ex.memory.buffer.byteLength, before);
    assert.equal(rt.u8.buffer, rt.ex.memory.buffer, 'cached view is still attached');
  });

  test(label('interleaved hashers do not share state'), () => {
    const rand = rng(5);
    const hs = Array.from({ length: 8 }, () => ({ a: mkFacade(), b: mkLegacy() }));
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

  test(label('Hmac works over the facade, including mutation of the hasher it is given'), () => {
    const rand = rng(6);
    for (let it = 0; it < 50; it++) {
      const key = binString(rand, (rand() * 140) | 0);
      const msg = binString(rand, (rand() * 200) | 0);
      const a = mkFacade();
      const b = mkLegacy();
      const ha = new Hmac(key, a);
      const hb = new Hmac(key, b);
      ha.update(msg);
      hb.update(msg);
      assert.equal(json(a), json(b), `key ${key.length} msg ${msg.length}`);
      assert.equal(toHex(ha.finalize()), toHex(hb.finalize()));
      assert.equal(json(a), json(b));
    }
  });

  return { same, mkFacade, mkLegacy, wasmUsed, iv };
}

export { hex, json, attempt, update, finalize };
