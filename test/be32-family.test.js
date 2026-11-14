// Facade tests for the 32-bit big-endian family (SHA-0, SHA-1, SHA-224/256, SM3):
// wasm-accelerated classes vs the untouched crypto-api 0.8.5 classes.
//
// The oracle is packages/crypto-api/legacy/hasher/<algo>.mjs, a verbatim copy of
// the original (only import specifiers differ). Everything is compared through
// the public surface: digests, getState() JSON, thrown errors. Modeled on
// test/md5.test.js; the cross-family harness (test/compat) fuzzes these classes too.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import Sha0, { _internal as sha0Internal } from '../packages/crypto-api/src/hasher/sha0.mjs';
import Sha1, { _internal as sha1Internal } from '../packages/crypto-api/src/hasher/sha1.mjs';
import Sha256, { _internal as sha256Internal } from '../packages/crypto-api/src/hasher/sha256.mjs';
import Sm3, { _internal as sm3Internal } from '../packages/crypto-api/src/hasher/sm3.mjs';
import LegacySha0 from '../packages/crypto-api/legacy/hasher/sha0.mjs';
import LegacySha1 from '../packages/crypto-api/legacy/hasher/sha1.mjs';
import LegacySha256 from '../packages/crypto-api/legacy/hasher/sha256.mjs';
import LegacySm3 from '../packages/crypto-api/legacy/hasher/sm3.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hasher32be from '../packages/crypto-api/src/hasher/hasher32be.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';

const vec = (name) => JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url), 'utf8'));
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
 * One entry per class. `variants` are the option sets whose vectors exist;
 * `inside` are option sets the wasm engine serves, `outside` ones it must hand
 * to the original code (and still match it).
 */
const ALGOS = [
  {
    id: 'sha0', Facade: Sha0, Legacy: LegacySha0, internal: sha0Internal, words: 5, maxRounds: 80,
    variants: [{ file: 'sha0', options: {} }], hmac: [],
    inside: [{}, { rounds: 1 }, { rounds: 16 }, { rounds: 40 }, { rounds: 79 }, { rounds: 80 }, { rounds: 0 }, { rounds: NaN }],
    outside: [{ rounds: 81 }, { rounds: 160 }, { rounds: 2.5 }, { rounds: '40' }, { rounds: -1 }, { rounds: true }]
  },
  {
    id: 'sha1', Facade: Sha1, Legacy: LegacySha1, internal: sha1Internal, words: 5, maxRounds: 80,
    variants: [{ file: 'sha1', options: {} }], hmac: ['sha1'], node: 'sha1',
    inside: [{}, { rounds: 1 }, { rounds: 16 }, { rounds: 40 }, { rounds: 79 }, { rounds: 80 }, { rounds: 0 }, { rounds: NaN }],
    outside: [{ rounds: 81 }, { rounds: 160 }, { rounds: 2.5 }, { rounds: '40' }, { rounds: -1 }, { rounds: true }]
  },
  {
    id: 'sha256', Facade: Sha256, Legacy: LegacySha256, internal: sha256Internal, words: 8, maxRounds: 64,
    variants: [{ file: 'sha256', options: {}, node: 'sha256' }, { file: 'sha224', options: { length: 224 }, node: 'sha224' }],
    hmac: ['sha224', 'sha256'],
    inside: [{}, { length: 224 }, { length: 256 }, { rounds: 1 }, { rounds: 33, length: 224 }, { rounds: 63 }, { rounds: 64 }],
    processOnly: [{ length: 160 }, { length: 128 }, { length: 384 }, { length: '224' }, { length: 224.5 }],
    outside: [{ rounds: 65 }, { rounds: 80 }, { rounds: 2.5 }, { rounds: '40' }, { rounds: -3 }]
  },
  {
    id: 'sm3', Facade: Sm3, Legacy: LegacySm3, internal: sm3Internal, words: 8, maxRounds: 64,
    variants: [{ file: 'sm3', options: {}, node: 'sm3' }], hmac: [],
    inside: [{}, { length: 256 }, { rounds: 1 }, { rounds: 16 }, { rounds: 17 }, { rounds: 63 }, { rounds: 64 }],
    processOnly: [{ length: 128 }, { length: 224 }, { length: '256' }],
    outside: [{ rounds: 65 }, { rounds: 100 }, { rounds: 2.5 }, { rounds: '40' }, { rounds: -1 }]
  }
];

const nodeHas = (alg) => {
  try {
    createHash(alg);
    return true;
  } catch (e) {
    return false;
  }
};

for (const A of ALGOS) {
  const { Facade: F, Legacy: L, internal, words } = A;
  const wasmUsed = (fn) => {
    const before = internal.wasmCalls();
    fn();
    return internal.wasmCalls() - before;
  };
  const opts = (o) => structuredClone(o);

  /** Apply the same steps to a fresh facade and a fresh original and compare every observation. */
  function same(steps, label, options = {}) {
    const a = new F(opts(options));
    const b = new L(opts(options));
    steps.forEach((step, i) => {
      const ra = attempt(() => step(a));
      const rb = attempt(() => step(b));
      assert.deepEqual(ra, rb, `${label}: step ${i} result differs`);
      assert.equal(json(a), json(b), `${label}: step ${i} getState() differs`);
    });
    assert.deepEqual(a.options, b.options, `${label}: options differ`);
    return { a, b };
  }

  const iv = () => new L(opts(A.inside[0])).getState().hash;

  describe(A.id, () => {
    test('uses wasm in a normal environment', () => {
      assert.ok(internal.runtime(), 'wasm failed to instantiate; run `zig build js` first');
      assert.equal(wasmUsed(() => {
        const h = new F();
        h.update('x'.repeat(100));
        h.finalize();
      }), 2, 'one process() call and one finalize() call');
    });

    test('is a Hasher32be and an original-shaped hasher', () => {
      const h = new F();
      assert.ok(h instanceof Hasher);
      assert.ok(h instanceof Hasher32be);
      assert.ok(h instanceof L);
      assert.equal(F.length, L.length);
      assert.equal(h.unitSize, 4);
      assert.equal(h.unitOrder, 1);
      assert.equal(h.blockSize, 16);
      assert.equal(h.blockSizeInBytes, 64);
      const o = {};
      assert.equal(new F(o).options, o, 'options object is kept by reference');
      assert.deepEqual(new F().options, new L().options);
      for (const m of ['reset', 'update', 'finalize', 'getState', 'setState', 'process', 'processBlock']) {
        assert.equal(typeof h[m], 'function', m);
      }
    });

    for (const v of A.variants) {
      for (const t of vec(v.file)) {
        test(`vector: ${t.name}`, () => {
          const h = new F(opts(v.options));
          h.update(t.input);
          assert.equal(wasmUsed(() => assert.equal(hex(h), t.hex)), 1);
        });
      }
    }

    for (const name of A.hmac) {
      const options = name === 'sha224' ? { length: 224 } : {};
      for (const t of vec(`hmac-${name}`)) {
        test(`vector: ${t.name}`, () => {
          for (const Class of [F, L]) {
            const hmac = new Hmac(t.key, new Class(opts(options)));
            hmac.update(t.input);
            assert.equal(toHex(hmac.finalize()), t.hex);
          }
        });
      }
    }

    for (const v of A.variants.filter((x) => x.node && nodeHas(x.node))) {
      test(`${v.node}: digest matches node:crypto for every length 0..300`, () => {
        const rand = rng(1);
        for (let len = 0; len <= 300; len++) {
          const s = binString(rand, len);
          const h = new F(opts(v.options));
          h.update(s);
          assert.equal(hex(h), createHash(v.node).update(s, 'latin1').digest('hex'), `len ${len}`);
        }
      });
    }

    test('differential: random messages split across random update() calls, every option set', () => {
      const rand = rng(2);
      const lengths = [0, 1, 15, 16, 17, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129];
      const optionSets = [...A.inside, ...(A.processOnly || []), ...A.outside];
      for (const options of optionSets) {
        for (let it = 0; it < Math.max(20, FUZZ_ITERS / 4); it++) {
          const len = it < lengths.length ? lengths[it] : (rand() * 300) | 0;
          const msg = binString(rand, len);
          const label = `${JSON.stringify(options)} iter ${it} len ${len}`;
          const a = new F(opts(options));
          const b = new L(opts(options));
          for (let pos = 0; pos < len;) {
            const n = (rand() * 80) | 0;
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
      for (const options of A.inside) {
        assert.equal(wasmUsed(() => {
          const h = new F(opts(options));
          h.update('x'.repeat(130));
          h.finalize();
        }), 2, JSON.stringify(options));
      }
      // A `length` the wasm code does not serve still lets process() use it (length
      // only picks the IV and the output size); finalize() runs the original code.
      for (const options of A.processOnly || []) {
        assert.equal(wasmUsed(() => {
          const h = new F(opts(options));
          h.update('x'.repeat(130));
          attempt(() => h.finalize());
        }), 2, JSON.stringify(options)); // update() and the original finalize() both call process()
      }
      for (const options of A.outside) {
        // Some of these throw or hang in the original for the whole message; compare only what is safe.
        const a = new F(opts(options));
        const used = wasmUsed(() => {
          attempt(() => {
            a.update('x'.repeat(130));
            a.finalize();
          });
        });
        assert.equal(used, 0, `${JSON.stringify(options)} must not use wasm`);
      }
    });

    test('options changed after construction are honored on the next call', () => {
      const a = new F();
      const b = new L();
      a.update('a'.repeat(100));
      b.update('a'.repeat(100));
      for (const rounds of [A.maxRounds - 1, 5, A.maxRounds + 1, 2.5, A.maxRounds]) {
        a.options.rounds = rounds;
        b.options.rounds = rounds;
        assert.deepEqual(attempt(() => (a.update('b'.repeat(70)), json(a))), attempt(() => (b.update('b'.repeat(70)), json(b))), `rounds ${rounds}`);
      }
      assert.deepEqual(attempt(() => hex(a)), attempt(() => hex(b)));
      if (A.id === 'sha256') {
        for (const length of [224, 256, 160, 224]) {
          const x = new F();
          const y = new L();
          x.update('abc');
          y.update('abc');
          x.options.length = length;
          y.options.length = length;
          assert.equal(hex(x), hex(y), `length ${length} set after construction`);
        }
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
        const a = new F();
        const b = new L();
        a.update(s);
        b.update(s);
        assert.equal(a.getState().length, len);
        assert.equal(hex(a), hex(b), `len ${len}`);
        assert.equal(json(a), json(b), `len ${len}`);
      }
    });

    test('reset() reuses the hasher', () => {
      const h = new F();
      h.update('abc');
      const first = h.finalize();
      h.reset();
      h.update('abc');
      assert.equal(h.finalize(), first);
    });

    test('getState() is the original JSON, key order included', () => {
      const { a, b } = same([(h) => h.getState()], 'pristine');
      assert.equal(json(a), json(b));
      assert.equal(json(a), JSON.stringify({ message: '', length: 0, hash: iv() }));
      a.update('abc');
      assert.equal(JSON.parse(json(a)).message, 'abc');
      a.update('d'.repeat(62));
      assert.equal(JSON.parse(json(a)).message, 'd');
      assert.deepEqual(Object.keys(a.getState()), ['message', 'length', 'hash']);
      const s = a.getState();
      s.message = 'zzz';
      s.hash[0] = 7;
      assert.equal(JSON.parse(json(a)).message, 'd');
    });

    test('getState()/finalize()/setState() per slice (the hasher-file pattern)', () => {
      const rand = rng(4);
      const data = binString(rand, 10000);
      const a = new F();
      const b = new L();
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
      const src = new L();
      src.update('q'.repeat(150));
      const h = new F();
      h.setState(src.getState());
      h.update('tail');
      src.update('tail');
      assert.equal(wasmUsed(() => assert.equal(hex(h), hex(src))), 1);
    });

    test('setState() keeps a live reference to the object, like the original', () => {
      const oa = { message: '', length: 0, hash: [...iv()] };
      const ob = { message: '', length: 0, hash: [...iv()] };
      const a = new F();
      const b = new L();
      a.setState(oa);
      b.setState(ob);
      assert.equal(a.state, oa);
      a.update('z'.repeat(100));
      b.update('z'.repeat(100));
      assert.deepEqual(oa, ob);
      assert.equal(hex(a), hex(b));
      assert.deepEqual(oa, ob);
    });

    test('odd states take the original code path and stay faithful', () => {
      const h0 = iv();
      const odd = {
        'reordered keys': { hash: h0, length: 3, message: 'abc' },
        'extra key': { message: 'abc', length: 3, hash: h0, extra: 1 },
        'unsigned words': { message: 'abc', length: 3, hash: h0.map((x) => x >>> 0) },
        'huge words': { message: 'abc', length: 3, hash: h0.map((x, i) => (i % 2 ? -(2 ** 33) : 2 ** 40 + 5)) },
        'fractional word': { message: 'abc', length: 3, hash: h0.map((x, i) => (i ? x : 1.5)) },
        'string word': { message: 'abc', length: 3, hash: h0.map((x, i) => (i ? x : '1')) },
        'NaN word': { message: 'abc', length: 3, hash: h0.map((x, i) => (i ? x : NaN)) },
        'short hash': { message: 'abc', length: 3, hash: h0.slice(0, 3) },
        'long hash': { message: 'abc', length: 3, hash: [...h0, 1, 2] },
        'full block in message': { message: 'a'.repeat(64), length: 64, hash: h0 },
        'long message': { message: 'a'.repeat(200), length: 200, hash: h0 },
        'wide message': { message: 'aĀb', length: 3, hash: h0 },
        'wide block': { message: 'a'.repeat(63) + 'Ā' + 'b'.repeat(70), length: 134, hash: h0 },
        'negative length': { message: '', length: -5, hash: h0 },
        'fractional length': { message: '', length: 2.5, hash: h0 },
        'string length': { message: '', length: '7', hash: h0 },
        'NaN length': { message: '', length: NaN, hash: h0 },
        'missing length': { message: 'abc', hash: h0 },
        'missing hash': { message: 'abc', length: 3 },
        'array message': { message: ['a', 'b'], length: 2, hash: h0 },
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
        const a = new F();
        const b = new L();
        steps.forEach((step, i) => {
          assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
          assert.deepEqual(attempt(() => json(a)), attempt(() => json(b)), `${name}: step ${i} state`);
        });
      }
    });

    test('integer hash words outside int32 are still computed by wasm, identically', () => {
      const hash = iv().map((x, i) => (i % 3 === 0 ? x >>> 0 : i % 3 === 1 ? 2 ** 40 + 5 : -(2 ** 33)));
      const a = new F();
      const b = new L();
      a.setState({ message: 'abc', length: 3, hash: [...hash] });
      b.setState({ message: 'abc', length: 3, hash: [...hash] });
      assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b))), 1);
      assert.equal(json(a), json(b));
    });

    test('the 2^31-byte length bug is kept (setState with huge lengths)', () => {
      const lengths = [(2 ** 31) - 1, 2 ** 31, 2 ** 31 + 5, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 7, 3 * 2 ** 31 + 9, 2 ** 40 + 3, Number.MAX_SAFE_INTEGER, -1, -(2 ** 31), -(2 ** 33) - 5];
      for (const length of lengths) {
        for (const message of ['', 'abc', 'x'.repeat(55), 'y'.repeat(56), 'z'.repeat(63)]) {
          const a = new F();
          const b = new L();
          a.setState({ message, length, hash: [...iv()] });
          b.setState({ message, length, hash: [...iv()] });
          assert.equal(wasmUsed(() => assert.equal(hex(a), hex(b), `length ${length} message ${message.length}`)), 1);
          assert.equal(json(a), json(b));
        }
      }
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
        const a = new F();
        const b = new L();
        for (const [i, step] of steps.entries()) {
          assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `${name}: step ${i}`);
        }
      }
    });

    test('.state is the live original-format object and direct mutation is honored', () => {
      const a = new F();
      const b = new L();
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
      const obj = { message: 'zz', length: 2, hash: [...iv()] };
      a.state = obj;
      assert.equal(a.state, obj);
      b.state = structuredClone(obj);
      assert.equal(hex(a), hex(b));
      assert.equal(obj.message, '', 'finalize wrote into the caller\'s object');
    });

    test('the hash array and state object are updated in place', () => {
      const a = new F();
      const state = a.state;
      const hash = a.state.hash;
      a.update('m'.repeat(200));
      a.finalize();
      assert.equal(a.state, state);
      assert.equal(a.state.hash, hash);
      const l = new L();
      l.update('m'.repeat(200));
      l.finalize();
      assert.deepEqual(hash, l.state.hash);
    });

    test('subclasses that override internals keep the original behavior', () => {
      const seenA = [];
      const seenB = [];
      class FacadeSub extends F {
        processBlock(block) {
          seenA.push(block[0]);
          super.processBlock(block);
        }
      }
      class LegacySub extends L {
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
          getStateHash() { return 'custom-' + L.prototype.getStateHash.call(this); },
          process() { this.processed = (this.processed || 0) + 1; return L.prototype.process.call(this); }
        }[name];
        const FS = class extends F {};
        const LS = class extends L {};
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

      class Plain extends F {}
      assert.equal(wasmUsed(() => {
        const p = new Plain();
        p.update('a'.repeat(64));
        p.finalize();
      }), 2);
    });

    test('patching an internal on an instance is honored', () => {
      const a = new F();
      const b = new L();
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

    test('a changed blockSizeInBytes is honored by the original code', () => {
      same([(h) => { h.blockSizeInBytes = 32; }, update('x'.repeat(100)), finalize()], 'blockSizeInBytes 32');
    });

    test('falls back to the original when WebAssembly is unavailable', () => {
      internal.reset(true);
      try {
        assert.equal(wasmUsed(() => {
          for (const v of A.variants) {
            for (const t of vec(v.file)) {
              const x = new F(opts(v.options));
              x.update(t.input);
              assert.equal(hex(x), t.hex);
            }
          }
        }), 0);
      } finally {
        internal.reset(false);
      }
      assert.equal(wasmUsed(() => {
        const h = new F();
        h.update('a');
        h.finalize();
      }), 1);
    });

    test('falls back when WebAssembly.Module throws (CSP, Workers) and remembers it', () => {
      const RealModule = WebAssembly.Module;
      internal.reset(false);
      WebAssembly.Module = function () {
        throw new WebAssembly.CompileError('blocked by test');
      };
      try {
        const run = () => {
          const h = new F();
          h.update('abc'.repeat(30));
          const l = new L();
          l.update('abc'.repeat(30));
          assert.equal(hex(h), hex(l));
        };
        assert.equal(wasmUsed(run), 0);
        WebAssembly.Module = RealModule;
        assert.equal(wasmUsed(run), 0, 'failure is remembered, not retried');
      } finally {
        WebAssembly.Module = RealModule;
        internal.reset(false);
      }
    });

    test('falls back when the WebAssembly global is missing (IE11, some embedded engines)', () => {
      const real = globalThis.WebAssembly;
      internal.reset(false);
      delete globalThis.WebAssembly;
      try {
        const h = new F();
        h.update('abc'.repeat(30));
        const l = new L();
        l.update('abc'.repeat(30));
        assert.equal(hex(h), hex(l));
      } finally {
        globalThis.WebAssembly = real;
        internal.reset(false);
      }
    });

    test('many hashers do not grow wasm memory or leak', () => {
      const rt = internal.runtime();
      const before = rt.ex.memory.buffer.byteLength;
      assert.throws(() => rt.ex.memory.grow(1), 'memory is fixed size');
      const msg = 'm'.repeat(1000);
      for (let i = 0; i < 20000; i++) {
        const h = new F();
        h.update(msg);
        h.finalize();
      }
      assert.equal(rt.ex.memory.buffer.byteLength, before);
      assert.equal(rt.u8.buffer, rt.ex.memory.buffer, 'cached view is still attached');
    });

    test('interleaved hashers do not share state', () => {
      const rand = rng(5);
      const hs = Array.from({ length: 8 }, () => ({ a: new F(), b: new L() }));
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
        const a = new F();
        const b = new L();
        const ha = new Hmac(key, a);
        const hb = new Hmac(key, b);
        ha.update(msg);
        hb.update(msg);
        assert.equal(json(a), json(b), `key ${key.length} msg ${msg.length}`);
        assert.equal(toHex(ha.finalize()), toHex(hb.finalize()));
        assert.equal(json(a), json(b));
      }
    });
  });
}

test('SHA-0 and SHA-1 share one wasm instance', () => {
  assert.equal(sha0Internal.runtime(), sha1Internal.runtime());
});

test('SHA-0 differs from SHA-1 (the rotation is the only difference)', () => {
  const a = new Sha0();
  const b = new Sha1();
  a.update('abc');
  b.update('abc');
  assert.notEqual(hex(a), hex(b));
});
