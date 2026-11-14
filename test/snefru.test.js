// Snefru facade tests: wasm-accelerated Snefru vs the untouched crypto-api 0.8.5
// class (packages/crypto-api/legacy/hasher/snefru.mjs). The checklist of
// test/md5.test.js, adapted to a hasher whose block size depends on the
// `length` option (block = 16 - length/32 words) and whose `rounds` option is
// read at every block.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import Snefru, { _internal } from '../packages/crypto-api/src/hasher/snefru.mjs';
import LegacySnefru from '../packages/crypto-api/legacy/hasher/snefru.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hasher32be from '../packages/crypto-api/src/hasher/hasher32be.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { FUZZ_ITERS, readVectors, rng, binString, hex, json, attempt, update, finalize } from './support/le32-suite.js';

const wasmUsed = (fn) => {
  const before = _internal.wasmCalls();
  fn();
  return _internal.wasmCalls() - before;
};

/** Apply the same steps to a fresh facade and a fresh original and compare every observation. */
function same(mkA, mkB, steps, name) {
  const a = mkA();
  const b = mkB();
  steps.forEach((step, i) => {
    assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i} result differs`);
    assert.deepEqual(attempt(() => json(a)), attempt(() => json(b)), `${name}: step ${i} getState() differs`);
  });
  return { a, b };
}

/**
 * One option set, run through the whole checklist.
 * @param {string} name
 * @param {Object|undefined} options
 */
function defineCase(name, options, extra = {}) {
  const label = (s) => `snefru ${name}: ${s}`;
  const opts = () => (options ? structuredClone(options) : undefined);
  const mkFacade = () => new Snefru(opts());
  const mkLegacy = () => new LegacySnefru(opts());
  const sameHere = (steps, what) => same(mkFacade, mkLegacy, steps, what);
  const ref = mkLegacy();
  const iv = ref.getState().hash;
  const words = iv.length;
  const B = ref.blockSizeInBytes;
  /** finalize() runs in wasm unless the digest has 15 words (the original cannot finalize those). */
  const finalizeWasm = words <= 14 ? 1 : 0;

  test(label('facade uses wasm in a normal environment'), () => {
    assert.ok(_internal.runtime(), 'wasm failed to instantiate; run `zig build js` first');
    const calls = wasmUsed(() => {
      const h = mkFacade();
      h.update('x'.repeat(100));
      if (words <= 14) h.finalize();
    });
    assert.equal(calls, 1 + finalizeWasm);
  });

  test(label('class shape matches the original'), () => {
    const h = mkFacade();
    assert.ok(h instanceof Hasher);
    assert.ok(h instanceof Hasher32be);
    assert.ok(h instanceof LegacySnefru);
    assert.equal(Snefru.name, LegacySnefru.name);
    assert.equal(Snefru.length, LegacySnefru.length, 'constructor arity');
    assert.equal(h.unitSize, 4);
    assert.equal(h.blockSizeInBytes, B);
    assert.equal(h.blockSizeInBytes, 4 * (16 - words));
    assert.deepEqual(Object.keys(h), Object.keys(mkLegacy()));
    assert.deepEqual(h.options, mkLegacy().options);
    const o = opts() ?? {};
    const made = new Snefru(o);
    assert.equal(made.options, o, 'options object is kept by reference');
    const o2 = opts() ?? {};
    new LegacySnefru(o2);
    assert.deepEqual(o, o2, 'the constructor completes the caller\'s options the same way');
    for (const m of ['reset', 'update', 'finalize', 'getState', 'setState', 'process', 'processBlock']) {
      assert.equal(typeof h[m], 'function', m);
    }
  });

  if (extra.vectors) {
    for (const v of readVectors(extra.vectors)) {
      test(label(`vector ${v.name}`), () => {
        const h = mkFacade();
        h.update(v.input);
        assert.equal(wasmUsed(() => assert.equal(hex(h), v.hex)), 1);
      });
    }
  }

  test(label('differential: random messages split across random update() calls'), () => {
    const rand = rng(2 + words);
    const lengths = [0, 1, 3, 4, 7, 8, 9, B - 1, B, B + 1, 2 * B - 1, 2 * B, 2 * B + 1, 63, 64, 65, 127, 128, 129];
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
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)), `iter ${it} len ${len}`);
      assert.equal(json(a), json(b), `iter ${it} state after finalize`);
    }
  });

  test(label('finalize() twice and update() after finalize() match the original'), () => {
    sameHere([update('abc'), finalize(), finalize(), finalize()], 'finalize x3');
    sameHere([update('abc'), finalize(), update('abc'), finalize()], 'update after finalize');
    sameHere([update('x'.repeat(100)), finalize(), update('y'.repeat(70)), finalize()], 'blocks after finalize');
    sameHere([finalize(), update(''), finalize()], 'finalize before any update');
    sameHere([update('x'.repeat(B)), finalize()], 'exactly one block');
    sameHere([update('x'.repeat(B - 1)), finalize()], 'one block minus one');
  });

  test(label('inputs larger than one wasm chunk (64 KiB), including exact multiples of the block'), () => {
    const rand = rng(3);
    // The chunk is the largest multiple of the block size that fits; probe around it and around 64 KiB.
    const chunk = 65536 - (65536 % B);
    for (const len of [65535, 65536, 65537, chunk - 1, chunk, chunk + 1, 2 * chunk, 2 * chunk + B, 200001]) {
      const s = binString(rand, len);
      const a = mkFacade();
      const b = mkLegacy();
      a.update(s);
      b.update(s);
      assert.equal(a.getState().length, len);
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)), `len ${len}`);
      assert.equal(json(a), json(b), `len ${len} state`);
    }
  });

  test(label('reset() reuses the hasher'), () => {
    const a = mkFacade();
    const b = mkLegacy();
    for (const m of ['one', 'x'.repeat(200), '']) {
      a.update(m);
      b.update(m);
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
      a.reset();
      b.reset();
      assert.equal(json(a), json(b));
    }
    assert.deepEqual(a.getState().hash, iv);
  });

  test(label('getState()/finalize()/setState() per slice (the hasher-file pattern)'), () => {
    const rand = rng(4);
    const msg = binString(rand, 900);
    let sa = mkFacade().getState();
    let sb = sa;
    for (let pos = 0; pos < msg.length; pos += 130) {
      const a = mkFacade();
      const b = mkLegacy();
      a.setState(sa);
      b.setState(sb);
      a.update(msg.substr(pos, 130));
      b.update(msg.substr(pos, 130));
      sa = a.getState();
      sb = b.getState();
      assert.deepEqual(sa, sb);
    }
  });

  test(label('setState() accepts what the original produced and keeps using wasm'), () => {
    const src = mkLegacy();
    src.update('q'.repeat(150));
    const h = mkFacade();
    h.setState(src.getState());
    h.update('tail');
    src.update('tail');
    assert.equal(wasmUsed(() => assert.deepEqual(attempt(() => hex(h)), attempt(() => hex(src)))), finalizeWasm);
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
    assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    assert.deepEqual(oa, ob);
  });

  test(label('odd states take the original code path and stay faithful'), () => {
    const w = (...head) => [...head, ...iv.slice(head.length)];
    const odd = {
      'reordered keys': { hash: [...iv], length: 3, message: 'abc' },
      'extra key': { message: 'abc', length: 3, hash: [...iv], extra: 1 },
      'unsigned words': { message: 'x'.repeat(130), length: 130, hash: w(4023233417, 1, 2, 3) },
      'huge words': { message: 'x'.repeat(130), length: 130, hash: w(2 ** 40 + 5, -(2 ** 33), 2, 3) },
      'words near 2^53': { message: 'x'.repeat(130), length: 130, hash: w(2 ** 53 - 1, -(2 ** 53 - 1), 2 ** 53 - 3, 2 ** 52 + 1) },
      'words beyond 2^53': { message: 'x'.repeat(130), length: 130, hash: w(2 ** 60, -(2 ** 70), 1e21, 3) },
      'fractional word': { message: 'x'.repeat(130), length: 130, hash: w(1.5, -2.5, 2, 3) },
      'string word': { message: 'x'.repeat(130), length: 130, hash: w('1', 1, 2, 3) },
      'null word': { message: 'x'.repeat(130), length: 130, hash: w(null, 1, 2, 3) },
      'NaN word': { message: 'x'.repeat(130), length: 130, hash: w(NaN, 1, 2, 3) },
      'Infinity word': { message: 'x'.repeat(130), length: 130, hash: w(Infinity, -Infinity, 2, 3) },
      'short hash': { message: 'x'.repeat(130), length: 130, hash: [1, 2, 3] },
      'empty hash': { message: 'x'.repeat(130), length: 130, hash: [] },
      'long hash': { message: 'x'.repeat(130), length: 130, hash: [...iv, 1, 2, 3] },
      'sixteen words': { message: 'x'.repeat(130), length: 130, hash: Array.from({ length: 16 }, (_, i) => i) },
      'sparse hash': { message: 'x'.repeat(130), length: 130, hash: new Array(words) },
      'full block in message': { message: 'a'.repeat(B), length: B, hash: [...iv] },
      'long message': { message: 'a'.repeat(200), length: 200, hash: [...iv] },
      'wide message': { message: 'aĀb', length: 3, hash: [...iv] },
      'wide block': { message: 'a'.repeat(B - 1) + 'Ā' + 'b'.repeat(70), length: B + 70, hash: [...iv] },
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
    for (const [oddName, state] of Object.entries(odd)) {
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
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${oddName}: step ${i}`);
        assert.deepEqual(attempt(() => json(a)), attempt(() => json(b)), `${oddName}: step ${i} state`);
      });
    }
  });

  test(label('any number as a hash word is computed by wasm, identically (the original only xors them)'), () => {
    const w = (...head) => [...head, ...iv.slice(head.length)];
    const variants = [
      w(4023233417, 1, 2 ** 40 + 5, -(2 ** 33)),
      w(2 ** 53 - 1, -(2 ** 53 - 1), 2 ** 53 - 3, 2 ** 52 + 1),
      w(1.5, -2.5, 2 ** 60, 1e21),
      w(NaN, Infinity, -Infinity, -0)
    ].map((hash) => hash.slice(0, words));
    for (const hash of variants) {
      const a = mkFacade();
      const b = mkLegacy();
      const state = { message: 'x'.repeat(B + 5), length: B + 5, hash };
      a.setState(structuredClone(state));
      b.setState(structuredClone(state));
      assert.equal(wasmUsed(() => a.process()), 1, `words ${hash}`);
      b.process();
      assert.equal(json(a), json(b), `words ${hash}`);
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    }
  });

  test(label('the 2^31-byte length bug is kept (setState with huge lengths)'), () => {
    const lengths = [(2 ** 31) - 1, 2 ** 31, 2 ** 31 + 5, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 7, 3 * 2 ** 31 + 9, 2 ** 40 + 3,
      Number.MAX_SAFE_INTEGER, -1, -(2 ** 31), -(2 ** 33) - 5, 2.5, NaN, Infinity, 1e300];
    for (const length of lengths) {
      for (const message of ['', 'abc', 'x'.repeat(B - 1)]) {
        const a = mkFacade();
        const b = mkLegacy();
        a.setState({ message, length, hash: [...iv] });
        b.setState({ message, length, hash: [...iv] });
        assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)), `length ${length} message ${message.length}`);
        assert.equal(json(a), json(b));
        if (words <= 14) {
          const c = mkFacade();
          c.setState({ message, length, hash: [...iv] });
          assert.equal(wasmUsed(() => c.finalize()), 1, `length ${length} runs in wasm`);
        }
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
      'wide after a full block': 'a'.repeat(B) + 'ā' + 'b'.repeat(10),
      'wide in the first block': 'a'.repeat(B - 3) + 'ā' + 'b'.repeat(100),
      'wide in a later 64 KiB chunk': 'q'.repeat(70000) + 'Ω' + 'r'.repeat(5000),
      'wide exactly at a chunk boundary': 'q'.repeat(65536) + 'Ω' + 'r'.repeat(100),
      'wide only in the unprocessed tail': 'q'.repeat(B) + 'abcĀ'
    };
    for (const [wideName, wide] of Object.entries(cases)) {
      sameHere([update('prefix'), update(wide), update('suffix'), finalize(), update(wide), finalize()], wideName);
      sameHere([update(wide), finalize()], `${wideName} (fresh)`);
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
    for (const [inName, input] of Object.entries(inputs)) {
      const steps = [update('abc'), (h) => h.update(input), update('d'.repeat(70)), finalize(), (h) => h.getState()];
      const a = mkFacade();
      const b = mkLegacy();
      for (const [i, step] of steps.entries()) {
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${inName}: step ${i}`);
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
    a.state.hash[0] = 42;
    b.state.hash[0] = 42;
    a.state.message = 'r'.repeat(B + 20);
    b.state.message = 'r'.repeat(B + 20);
    assert.equal(wasmUsed(() => a.process()), 1);
    b.process();
    assert.equal(json(a), json(b));
    assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    const obj = { message: 'zz', length: 2, hash: [...iv] };
    a.state = obj;
    assert.equal(a.state, obj);
    b.state = structuredClone(obj);
    assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    if (words <= 14) assert.equal(obj.message, '', 'finalize wrote into the caller\'s object');
  });

  test(label('the hash array and state object are updated in place, like the original'), () => {
    for (const make of [mkFacade, mkLegacy]) {
      const a = make();
      const state = a.state;
      const hash = a.state.hash;
      a.update('m'.repeat(200));
      assert.equal(a.state, state);
      assert.equal(a.state.hash, hash, `after update (${make === mkFacade ? 'facade' : 'original'})`);
      a.update('n'.repeat(1));
      assert.equal(a.state.hash, hash, 'no block processed');
      if (words <= 14) {
        a.finalize();
        assert.equal(a.state.hash, hash, 'after finalize');
      }
    }
    const a = mkFacade();
    const b = mkLegacy();
    const ha = a.state.hash;
    const hb = b.state.hash;
    a.update('m'.repeat(B));
    b.update('m'.repeat(B));
    assert.deepEqual(ha, hb);
  });

  test(label('subclasses that override internals keep the original behavior'), () => {
    const seenA = [];
    const seenB = [];
    class FacadeSub extends Snefru {
      processBlock(block) {
        seenA.push(block[0]);
        super.processBlock(block);
      }
    }
    class LegacySub extends LegacySnefru {
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
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    });
    assert.equal(used, 0, 'no wasm when processBlock is overridden');
    assert.ok(seenA.length > 0);
    assert.deepEqual(seenA, seenB);

    for (const hook of ['addLengthBits', 'addPaddingZero', 'getStateHash', 'process']) {
      const body = {
        addLengthBits() { this.state.message += '\x01\x02\x03\x04\x05\x06\x07\x08'; },
        addPaddingZero(n) { this.state.message += '\x01' + new Array(Math.max(n, 0)).join('\x01'); },
        getStateHash() { return 'custom-' + LegacySnefru.prototype.getStateHash.call(this); },
        process() { this.processed = (this.processed || 0) + 1; return LegacySnefru.prototype.process.call(this); }
      }[hook];
      const F = class extends Snefru {};
      const L = class extends LegacySnefru {};
      F.prototype[hook] = body;
      L.prototype[hook] = body;
      const x = new F(opts());
      const y = new L(opts());
      x.update('hello world'.repeat(10));
      y.update('hello world'.repeat(10));
      assert.deepEqual(attempt(() => x.finalize()), attempt(() => y.finalize()), hook);
      assert.equal(json(x), json(y), hook);
      assert.equal(x.processed, y.processed, hook);
    }

    // a subclass that overrides `update` and calls super still accelerates
    class Plain extends Snefru {
      update(m) { return super.update(m); }
    }
    assert.equal(wasmUsed(() => {
      const p = new Plain(opts());
      p.update('a'.repeat(B));
      if (words <= 14) p.finalize();
    }), 1 + finalizeWasm);
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
      h.update('x'.repeat(2 * B + 3));
    }
    assert.equal(calls, 4);
    assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    assert.equal(json(a), json(b));
  });

  test(label('a changed blockSizeInBytes or options.rounds is read like the original reads it'), () => {
    for (const size of [8, B / 2, 2 * B, '48', B + 0.5, B - 1, 4]) {
      const a = mkFacade();
      const b = mkLegacy();
      a.blockSizeInBytes = size;
      b.blockSizeInBytes = size;
      const ra = attempt(() => { a.update('x'.repeat(200)); return hex(a); });
      const rb = attempt(() => { b.update('x'.repeat(200)); return hex(b); });
      assert.deepEqual(ra, rb, `blockSizeInBytes ${size}`);
      assert.equal(attempt(() => json(a)).value, attempt(() => json(b)).value);
    }
    // `options.rounds` is read for every block, so changing it mid-stream matters.
    for (const rounds of [1, 2, 3, 4, 5, 6, 7, 8]) {
      const a = mkFacade();
      const b = mkLegacy();
      for (const h of [a, b]) {
        h.update('p'.repeat(100));
        h.options.rounds = rounds;
        h.update('q'.repeat(100));
      }
      assert.equal(json(a), json(b), `rounds ${rounds}`);
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    }
  });

  test(label('falls back to the original when WebAssembly is unavailable'), () => {
    _internal.reset(true);
    try {
      assert.equal(wasmUsed(() => {
        const x = mkFacade();
        x.update('abc'.repeat(50));
        const l = mkLegacy();
        l.update('abc'.repeat(50));
        assert.deepEqual(attempt(() => hex(x)), attempt(() => hex(l)));
      }), 0);
    } finally {
      _internal.reset(false);
    }
    assert.equal(wasmUsed(() => {
      const h = mkFacade();
      h.update('a'.repeat(B));
    }), 1);
  });

  test(label('falls back when WebAssembly.Module throws (CSP, Workers) and remembers it'), () => {
    const RealModule = WebAssembly.Module;
    _internal.reset(false);
    WebAssembly.Module = function () {
      throw new WebAssembly.CompileError('blocked by test');
    };
    try {
      assert.equal(wasmUsed(() => {
        const h = mkFacade();
        h.update('abc'.repeat(B));
        const l = mkLegacy();
        l.update('abc'.repeat(B));
        assert.deepEqual(attempt(() => hex(h)), attempt(() => hex(l)));
      }), 0);
      WebAssembly.Module = RealModule;
      assert.equal(wasmUsed(() => {
        const h = mkFacade();
        h.update('abc'.repeat(30));
        if (words <= 14) h.finalize();
      }), 0, 'the failure is remembered, not retried');
    } finally {
      WebAssembly.Module = RealModule;
      _internal.reset(false);
    }
  });

  test(label('falls back when the WebAssembly global is missing (IE11, some embedded engines)'), () => {
    const real = globalThis.WebAssembly;
    _internal.reset(false);
    delete globalThis.WebAssembly;
    try {
      const h = mkFacade();
      h.update('abc'.repeat(30));
      const l = mkLegacy();
      l.update('abc'.repeat(30));
      assert.deepEqual(attempt(() => hex(h)), attempt(() => hex(l)));
    } finally {
      globalThis.WebAssembly = real;
      _internal.reset(false);
    }
  });

  test(label('many hashers do not grow wasm memory or leak'), () => {
    const rt = _internal.runtime();
    const before = rt.ex.memory.buffer.byteLength;
    assert.throws(() => rt.ex.memory.grow(1), 'memory is fixed size');
    const msg = 'm'.repeat(1000);
    for (let i = 0; i < 2000; i++) {
      const h = mkFacade();
      h.update(msg);
      if (words <= 14) h.finalize();
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
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
    }
  });

  test(label('Hmac works over the facade, including mutation of the hasher it is given'), () => {
    const rand = rng(6);
    for (let it = 0; it < 30; it++) {
      const key = binString(rand, (rand() * 140) | 0);
      const msg = binString(rand, (rand() * 200) | 0);
      const a = mkFacade();
      const b = mkLegacy();
      const attemptMac = (h) => attempt(() => {
        const mac = new Hmac(key, h);
        mac.update(msg);
        return toHex(mac.finalize());
      });
      assert.deepEqual(attemptMac(a), attemptMac(b), `key ${key.length} msg ${msg.length}`);
      assert.equal(json(a), json(b));
    }
  });
}

// ---- the four named variants (vectors from the original suite) and other lengths ----

defineCase('128/8 (default)', undefined, { vectors: 'snefru128-8' });
defineCase('128/2', { length: 128, rounds: 2 }, { vectors: 'snefru128-2' });
defineCase('256/4', { length: 256, rounds: 4 }, { vectors: 'snefru256-4' });
defineCase('256/8', { length: 256, rounds: 8 }, { vectors: 'snefru256-8' });
defineCase('rounds 1', { rounds: 1 });
defineCase('rounds 5, length 224', { length: 224, rounds: 5 });
defineCase('length 32', { length: 32, rounds: 3 });
defineCase('length 64', { length: 64 });
defineCase('length 448 (block of 8 bytes)', { length: 448 });
defineCase('length 480 (block of 4 bytes; the original cannot finalize)', { length: 480 });

// ---- options ----

test('snefru: every length 32..480 and rounds 1..8 equals the original', () => {
  const rand = rng(11);
  for (let length = 32; length <= 480; length += 32) {
    for (let rounds = 1; rounds <= 8; rounds++) {
      const msg = binString(rand, (rand() * 200) | 0);
      const a = new Snefru({ length, rounds });
      const b = new LegacySnefru({ length, rounds });
      a.update(msg);
      b.update(msg);
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)), `length ${length} rounds ${rounds}`);
      assert.equal(json(a), json(b));
    }
  }
});

test('snefru: options the wasm code does not model behave exactly like the original', () => {
  const odd = {
    length: [0, 1, 31, 33, 100, 129, 1.5, NaN, Infinity, -1, -32, -64, '128', '256', ' 256', true, null, undefined, [], [256], {}, 32.9],
    rounds: [0, 9, 10, 100, 2.5, 1.2, -1, -5, NaN, Infinity, '4', '8', true, null, undefined, [], [3], {}, 1e10]
  };
  for (const [key, values] of Object.entries(odd)) {
    for (const value of values) {
      const mk = (Class) => {
        try {
          return new Class({ [key]: value });
        } catch (e) {
          return `${e.constructor.name}: ${e.message}`;
        }
      };
      const a = mk(Snefru);
      const b = mk(LegacySnefru);
      const what = `${key} ${typeof value === 'bigint' ? value + 'n' : JSON.stringify(value) ?? String(value)}`;
      if (typeof a === 'string' || typeof b === 'string') {
        assert.equal(a, b, `ctor ${what}`);
        continue;
      }
      assert.deepEqual(a.options, b.options, what);
      assert.equal(a.blockSizeInBytes, b.blockSizeInBytes, what);
      // 512 and up never return in the original (see below), so only probe block sizes > 0.
      if (a.blockSizeInBytes <= 0) continue;
      const steps = [(h) => h.getState(), (h) => h.update('abc'), (h) => h.update('d'.repeat(130)), (h) => h.getState(),
        (h) => hex(h), (h) => h.getState(), (h) => h.options];
      steps.forEach((step, i) => {
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${what} step ${i}`);
      });
    }
  }
});

test('snefru: the options object is completed the same way (length and rounds defaults)', () => {
  for (const given of [undefined, null, {}, { length: 0 }, { rounds: 0 }, { length: 256 }, { rounds: 4 }, { length: 0, rounds: 0 }, { other: 1 }]) {
    const oa = given && structuredClone(given);
    const ob = given && structuredClone(given);
    const a = new Snefru(oa);
    const b = new LegacySnefru(ob);
    assert.deepEqual(a.options, b.options);
    if (oa) assert.deepEqual(oa, ob);
    assert.deepEqual(a.getState(), b.getState());
  }
});

test('snefru: changing options.length after construction does nothing until reset(), like the original', () => {
  for (const [from, to] of [[128, 256], [256, 128], [128, 480], [224, 64]]) {
    const a = new Snefru({ length: from });
    const b = new LegacySnefru({ length: from });
    for (const h of [a, b]) {
      h.options.length = to;
      h.update('x'.repeat(100));
    }
    assert.equal(json(a), json(b));
    for (const h of [a, b]) h.reset();
    assert.equal(json(a), json(b));
    // After reset() the hash has `to / 32` words but blockSizeInBytes still belongs to `from`.
    for (const h of [a, b]) h.update('y'.repeat(200));
    assert.equal(json(a), json(b));
    assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
  }
});

test('snefru: one fixed-size state, two instances with different options do not interfere', () => {
  const a1 = new Snefru({ length: 128, rounds: 8 });
  const a2 = new Snefru({ length: 256, rounds: 4 });
  const b1 = new LegacySnefru({ length: 128, rounds: 8 });
  const b2 = new LegacySnefru({ length: 256, rounds: 4 });
  for (let i = 0; i < 20; i++) {
    const s = 'chunk-' + i + 'z'.repeat(i * 7);
    a1.update(s);
    b1.update(s);
    a2.update(s);
    b2.update(s);
  }
  assert.equal(hex(a1), hex(b1));
  assert.equal(hex(a2), hex(b2));
});

// ---- divergence 1: configurations where the original never returns ----

test('snefru: lengths of 512 and up throw RangeError where the original loops forever', () => {
  for (const length of [512, 544, 1000, 1024, 5000]) {
    for (const input of ['abc', '', 'x'.repeat(200)]) {
      const h = new Snefru({ length });
      assert.throws(() => h.update(input), RangeError, `length ${length} update(${input.length})`);
    }
    // finalize() with nothing buffered already throws RangeError in the original (negative padding).
    assert.deepEqual(attempt(() => new Snefru({ length }).finalize()), attempt(() => new LegacySnefru({ length }).finalize()));
    assert.match(attempt(() => new Snefru({ length }).finalize()).error, /^RangeError/);
    // Construction, getState(), setState() and reset() still work as before.
    const h = new Snefru({ length });
    assert.deepEqual(h.getState(), new LegacySnefru({ length }).getState());
    h.reset();
    assert.equal(h.blockSizeInBytes, new LegacySnefru({ length }).blockSizeInBytes);
  }
  // process() is what loops in the original, whichever way it is reached.
  const h = new Snefru({ length: 512 });
  h.state.message = 'abc';
  assert.throws(() => h.process(), RangeError);
  // The rounds that make the original throw TypeError first still do.
  for (const rounds of [9, 12]) {
    const a = attempt(() => new Snefru({ length: 512, rounds }).update('abc'));
    const b = attempt(() => new LegacySnefru({ length: 512, rounds }).update('abc'));
    assert.deepEqual(a, b, `rounds ${rounds}`);
    assert.match(a.error, /^TypeError/);
  }
});

test('snefru: rounds the original rejects with TypeError, and zero or negative rounds, are the original code', () => {
  for (const rounds of [9, 10, 100]) {
    const a = new Snefru({ rounds });
    const b = new LegacySnefru({ rounds });
    for (const h of [a, b]) {
      assert.throws(() => h.update('x'.repeat(100)), TypeError);
    }
    assert.equal(json(a), json(b), 'state left behind by the failed block');
  }
  for (const rounds of [0, -1, -8, 2.5, 7.9]) {
    const a = new Snefru();
    const b = new LegacySnefru();
    a.options.rounds = rounds;
    b.options.rounds = rounds;
    a.update('x'.repeat(100));
    b.update('x'.repeat(100));
    assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)), `rounds ${rounds}`);
    assert.equal(json(a), json(b));
  }
});

// ---- wasm internals ----

test('snefru: the wasm exports reject a bad State instead of reading out of range', () => {
  const rt = _internal.runtime();
  assert.ok(rt);
  const { ex, base, u8 } = rt;
  const st = base;
  const dv = new DataView(u8.buffer);
  const put = (words, rounds, buffered) => {
    u8[st + 60] = words;
    u8[st + 61] = rounds;
    u8[st + 62] = buffered;
  };
  assert.equal(ex.snefru_state_size(), 128);
  assert.equal(ex.snefru_init(st, 4, 8), 0);
  assert.equal(ex.snefru_init(st, 0, 8), 1);
  assert.equal(ex.snefru_init(st, 16, 8), 1);
  assert.equal(ex.snefru_init(st, 4, 0), 1);
  assert.equal(ex.snefru_init(st, 4, 9), 1);
  const input = base + 256;
  for (const [words, rounds, buffered] of [[0, 8, 0], [16, 8, 0], [255, 8, 0], [4, 0, 0], [4, 9, 0], [4, 255, 0], [4, 8, 48], [4, 8, 255]]) {
    put(words, rounds, buffered);
    assert.equal(ex.snefru_blocks(st, input, 0), 3, `blocks ${words}/${rounds}/${buffered}`);
    assert.equal(ex.snefru_update(st, input, 0), 3);
    assert.equal(ex.snefru_final(st, base + 128), 3);
  }
  put(4, 8, 0);
  assert.equal(ex.snefru_blocks(st, input, 47), 1, 'not a multiple of the block size');
  put(15, 8, 0);
  assert.equal(ex.snefru_final(st, base + 128), 3, 'words = 15 cannot be finalized, like the original');
  assert.equal(dv.getUint32(st + 64, true) >= 0, true);
});
