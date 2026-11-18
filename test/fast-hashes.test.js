// XXH3-64, XXH3-128, SipHash-2-4, SipHash-1-3 and MurmurHash3 x86_32 / x64_128 (crypto-api 0.8.5 has
// none of them, so there is no original to compare with).
//
// References that share nothing with the code under test:
//   - test/vectors/fast/xxh3.json: the XXH3 and XXH128 values of the xxHash sanity suite
//     (tests/sanity_test_vectors.h) for the sanity buffer, written by scripts/gen-fast-vectors.mjs,
//   - test/vectors/fast/siphash.json: the vectors of the SipHash reference implementation (2-4) and of
//     the Rust standard library (1-3),
//   - the verification values of SMHasher for MurmurHash3, which cover every tail length and many seeds,
//   - `std.hash.XxHash3`, `std.crypto.auth.siphash` and `std.hash.Murmur3_32` in the Zig tests of the cores.
// Every test that exercises a hasher runs twice: with the wasm engine, and with the plain-JavaScript
// engine that environments without WebAssembly use.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import XxHash3, { _internal as xxh3Internal } from '../packages/crypto-api/src/hasher/xxhash3.mjs';
import XxHash128, { _internal as xxh128Internal } from '../packages/crypto-api/src/hasher/xxhash128.mjs';
import SipHash, { _internal as sip24Internal } from '../packages/crypto-api/src/hasher/siphash.mjs';
import SipHash13, { _internal as sip13Internal } from '../packages/crypto-api/src/hasher/siphash13.mjs';
import Murmur3, { _internal as m32Internal } from '../packages/crypto-api/src/hasher/murmur3.mjs';
import Murmur3x64, { _internal as m128Internal } from '../packages/crypto-api/src/hasher/murmur3x64.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import CryptoApi from '../packages/crypto-api/src/crypto-api.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';

const vectors = (name) => JSON.parse(readFileSync(new URL(`./vectors/fast/${name}`, import.meta.url), 'utf8'));

const KEY = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');

/** Deterministic pseudo-random bytes. */
function bytes(length, seed) {
  const out = Buffer.alloc(length);
  let x = (Math.imul(seed, 2654435761) + 12345) >>> 0;
  for (let i = 0; i < length; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out[i] = x >>> 24;
  }
  return out;
}

/** The sanity buffer of the xxHash test suite. */
function sanityBuffer(n) {
  const out = Buffer.alloc(n);
  let gen = 2654435761n;
  for (let i = 0; i < n; i++) {
    out[i] = Number(gen >> 56n);
    gen = (gen * 11400714785074694797n) & 0xffffffffffffffffn;
  }
  return out;
}

const ALGOS = {
  xxh3: { C: XxHash3, internal: xxh3Internal, options: {}, block: 1024, keep: 64, digest: 8, hashInts: 18 },
  xxh128: { C: XxHash128, internal: xxh128Internal, options: {}, block: 1024, keep: 64, digest: 16, hashInts: 18 },
  siphash24: { C: SipHash, internal: sip24Internal, options: { key: KEY }, block: 8, keep: 1, digest: 8, hashInts: 8 },
  siphash13: { C: SipHash13, internal: sip13Internal, options: { key: KEY }, block: 8, keep: 1, digest: 8, hashInts: 8 },
  murmur3: { C: Murmur3, internal: m32Internal, options: {}, block: 4, keep: 1, digest: 4, hashInts: 1 },
  murmur3x64: { C: Murmur3x64, internal: m128Internal, options: {}, block: 16, keep: 1, digest: 16, hashInts: 4 },
};
const INTERNALS = Object.values(ALGOS).map((a) => a.internal);
const ENGINES = [['wasm', false], ['js', true]];

function perEngine(name, body) {
  for (const [label, disable] of ENGINES) {
    describe(`${name} (${label} engine)`, () => {
      before(() => INTERNALS.forEach((i) => i.reset(disable)));
      after(() => INTERNALS.forEach((i) => i.reset(false)));
      body(label);
    });
  }
}

function withJs(fn) {
  INTERNALS.forEach((i) => i.reset(true));
  try {
    return fn();
  } finally {
    INTERNALS.forEach((i) => i.reset(false));
  }
}

/** Feed `message` to `hasher` in pieces of pseudo-random size 1..maxPiece. */
function feed(hasher, message, seed, maxPiece = 200) {
  let pos = 0;
  let x = seed;
  while (pos < message.length) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    const n = 1 + ((x >>> 8) % maxPiece);
    hasher.update(message.subarray(pos, pos + n));
    pos += n;
  }
}

const hexOf = (C, options, message) => {
  const h = new C(options);
  h.update(message);
  return toHex(h.finalize());
};

/** An XXH3 hasher with a full 64-bit seed (the `seed` option stops at 2^53 - 1): the seed is part of the state. */
function seeded(C, seedHex) {
  const seed = BigInt('0x' + seedHex);
  const h = new C();
  const state = h.getState();
  state.hash[16] = Number(seed & 0xffffffffn) | 0;
  state.hash[17] = Number(seed >> 32n) | 0;
  h.setState(state);
  return h;
}

// ---- published answers ------------------------------------------------------------------------

perEngine('XXH3 and XXH128: the xxHash sanity values', () => {
  const rows = vectors('xxh3.json');
  const buf = sanityBuffer(4096 + 64 + 1);
  it(`${rows.length} lengths and seeds, in one update and in pieces`, () => {
    let checked = 0;
    for (const row of rows) {
      const message = buf.subarray(0, row.length);
      for (const [C, field] of [[XxHash3, 'xxh3'], [XxHash128, 'xxh128']]) {
        if (!row[field]) continue;
        const one = seeded(C, row.seed);
        one.update(message);
        assert.equal(one.digest('hex'), row[field], `${field} length ${row.length} seed ${row.seed}`);
        const pieces = seeded(C, row.seed);
        feed(pieces, message, row.length + 3, 300);
        assert.equal(pieces.digest('hex'), row[field], `${field} length ${row.length} seed ${row.seed}, pieces`);
        checked++;
      }
    }
    assert.ok(checked > 2000);
  });
  it('a seed below 2^53 can be given as the seed option', () => {
    for (const row of rows.filter((r) => r.seed === '000000009e3779b1').slice(0, 200)) {
      assert.equal(hexOf(XxHash128, { seed: 0x9E3779B1 }, buf.subarray(0, row.length)), row.xxh128, `length ${row.length}`);
    }
  });
  it('the values everyone prints', () => {
    assert.equal(hexOf(XxHash3, {}, ''), '2d06800538d394c2');
    assert.equal(hexOf(XxHash3, {}, 'abc'), '78af5f94892f3950');
    assert.equal(hexOf(XxHash128, {}, ''), '99aa06d3014798d86001c324468d497f');
    assert.equal(hexOf(XxHash128, {}, 'abc'), '06b05ab6733a618578af5f94892f3950');
  });
});

perEngine('SipHash: the reference vectors', () => {
  const rows = vectors('siphash.json');
  it('SipHash-2-4 and SipHash-1-3 of 00, 00 01, ... with the key 00..0f', () => {
    for (const row of rows) {
      const message = Buffer.from(Array.from({ length: row.length }, (_, i) => i));
      assert.equal(hexOf(SipHash, { key: KEY }, message), row.siphash24, `2-4 length ${row.length}`);
      assert.equal(hexOf(SipHash13, { key: KEY }, message), row.siphash13, `1-3 length ${row.length}`);
      const h = new SipHash({ key: KEY.toString('latin1') });
      for (const b of message) h.update(String.fromCharCode(b));
      assert.equal(toHex(h.finalize()), row.siphash24, `2-4 length ${row.length}, byte by byte`);
    }
  });
  it('the example of the SipHash paper', () => {
    // Appendix A: the 15-byte message 00..0e gives a129ca6149be45e5, written least significant byte first.
    assert.equal(hexOf(SipHash, { key: KEY }, KEY.subarray(0, 15)), 'e545be4961ca29a1');
  });
});

/**
 * The verification value of SMHasher: hash {}, {0}, {0, 1}, .. {0, .., 254} with the seeds 256, 255, .., 1, hash
 * the concatenated results with seed 0, and read the first four bytes as a little-endian number. The reference
 * writes x86_32 least significant byte first, so those digests are reversed here.
 */
function verification(C, reverse) {
  const key = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  const parts = [];
  for (let i = 0; i < 256; i++) {
    const d = Buffer.from(hexOf(C, { seed: 256 - i }, key.subarray(0, i)), 'hex');
    parts.push(reverse ? d.reverse() : d);
  }
  const all = Buffer.from(hexOf(C, { seed: 0 }, Buffer.concat(parts)), 'hex');
  return (reverse ? all.reverse() : all).readUInt32LE(0);
}

perEngine('MurmurHash3: SMHasher verification and published values', () => {
  it('the verification values', () => {
    assert.equal(verification(Murmur3, true), 0xB0F57EE3);
    assert.equal(verification(Murmur3x64, false), 0x6384BA69);
  });
  it('published x86_32 values', () => {
    assert.equal(hexOf(Murmur3, {}, ''), '00000000');
    assert.equal(hexOf(Murmur3, { seed: 1 }, ''), '514e28b7');
    assert.equal(hexOf(Murmur3, { seed: 0xffffffff }, ''), '81f16f39');
    assert.equal(hexOf(Murmur3, { seed: 0x9747b28c }, 'Hello, world!'), '24884cba');
    assert.equal(hexOf(Murmur3, { seed: 0x9747b28c }, 'The quick brown fox jumps over the lazy dog'), '2fa826cd');
    assert.equal(hexOf(Murmur3x64, {}, ''), '00000000000000000000000000000000');
  });
});

// ---- engines against each other ----------------------------------------------------------------------

describe('the wasm and the JavaScript engines agree', () => {
  const cases = [
    ['xxh3', [{}, { seed: 1 }, { seed: 0x1fffffffffffff }]],
    ['xxh128', [{}, { seed: 0x123456789ab }]],
    ['siphash24', [{ key: KEY }, { key: bytes(16, 9) }]],
    ['siphash13', [{ key: bytes(16, 10) }]],
    ['murmur3', [{}, { seed: 0xffffffff }]],
    ['murmur3x64', [{}, { seed: 0x9747b28c }]],
  ];
  for (const [name, optionSets] of cases) {
    const a = ALGOS[name];
    const top = Math.max(4 * a.block + 3, 300);
    it(`${name}: every length 0 to ${top}, then long messages`, () => {
      const lengths = [];
      for (let n = 0; n <= top; n++) lengths.push(n);
      lengths.push(1087, 1088, 2111, 2112, 4096, 4097, 70000, 70001);
      for (const options of optionSets) {
        for (const n of lengths) {
          const message = bytes(n, n + 1);
          assert.equal(withJs(() => hexOf(a.C, options, message)), hexOf(a.C, options, message), `${JSON.stringify(options)} length ${n}`);
        }
      }
      assert.ok(a.internal.wasmCalls() > 0, 'wasm ran');
    });
  }
});

// ---- behavior of the hasher interface ------------------------------------------------------------------

perEngine('the hasher interface', (label) => {
  for (const [name, a] of Object.entries(ALGOS)) {
    describe(name, () => {
      it('uses the engine under test', () => {
        const before = a.internal.wasmCalls();
        const h = new a.C(a.options);
        h.update(bytes(5 * a.block + 3, 1));
        h.finalize();
        assert.equal(a.internal.wasmCalls() > before, label === 'wasm');
      });

      it('finalize() is repeatable and update() continues the message', () => {
        const h = new a.C(a.options);
        const m = bytes(3 * a.block + 5, 2);
        h.update(m.subarray(0, a.block + 1));
        const first = toHex(h.finalize());
        assert.equal(toHex(h.finalize()), first);
        assert.equal(first, hexOf(a.C, a.options, m.subarray(0, a.block + 1)));
        h.update(m.subarray(a.block + 1));
        assert.equal(toHex(h.finalize()), hexOf(a.C, a.options, m));
      });

      it('reset() starts over, with the same options', () => {
        const h = new a.C(a.options);
        h.update('discard me');
        h.finalize();
        h.reset();
        h.update('abc');
        assert.equal(toHex(h.finalize()), hexOf(a.C, a.options, 'abc'));
      });

      it('getState() is JSON, and setState() resumes at any offset', () => {
        const m = bytes(4 * a.block + a.keep + 7, 3);
        for (const cut of [0, 1, a.block - 1, a.block, a.block + 1, a.block + a.keep, 2 * a.block, 3 * a.block + 2, m.length]) {
          const x = new a.C(a.options);
          x.update(m.subarray(0, cut));
          const state = JSON.parse(JSON.stringify(x.getState()));
          const y = new a.C(a.options);
          y.setState(state);
          y.update(m.subarray(cut));
          assert.equal(toHex(y.finalize()), hexOf(a.C, a.options, m), `cut ${cut}`);
        }
      });

      it('keeps the end of the message in state.message and the counts consistent', () => {
        const h = new a.C(a.options);
        h.update(bytes(5 * a.block, 4));
        let s = h.getState();
        assert.equal(s.length, 5 * a.block);
        assert.equal(s.message.length, a.block);
        assert.equal(s.counter, 4 * a.block);
        // At least `keep` bytes stay behind the compressed blocks.
        h.update(bytes(a.keep - 1, 5));
        s = h.getState();
        assert.equal(s.counter, 4 * a.block);
        assert.equal(s.message.length, a.block + a.keep - 1);
        h.update('x');
        s = h.getState();
        assert.equal(s.counter, 5 * a.block);
        assert.equal(s.message.length, a.keep);
        assert.equal(s.hash.length, a.hashInts);
        assert.ok(s.hash.every(Number.isInteger));
      });

      it('accepts typed arrays and ArrayBuffers like binary strings, and refuses wide characters', () => {
        const m = bytes(100, 5);
        const want = hexOf(a.C, a.options, m);
        assert.equal(hexOf(a.C, a.options, m.toString('latin1')), want);
        assert.equal(hexOf(a.C, a.options, new Uint8Array(m)), want);
        assert.equal(hexOf(a.C, a.options, new Uint8Array(m).buffer), want);
        assert.equal(new a.C(a.options).digest().length, a.digest);
        assert.throws(() => new a.C(a.options).update('Ā'), TypeError);
        assert.throws(() => new a.C(a.options).update(5), TypeError);
      });

      it('is a Hasher with its block size, and works with Hmac', () => {
        const h = new a.C(a.options);
        assert.ok(h instanceof Hasher);
        assert.equal(h.blockSizeInBytes, a.block);
        const key = Buffer.from('a key');
        const message = Buffer.from('the message');
        const hash = (data) => Buffer.from(hexOf(a.C, a.options, data), 'hex');
        const k = Buffer.concat([key, Buffer.alloc(a.block - key.length > 0 ? a.block - key.length : 0)]);
        const kk = key.length > a.block ? Buffer.concat([hash(key), Buffer.alloc(a.block - a.digest)]) : k;
        const ipad = Buffer.from(kk.map((b) => b ^ 0x36));
        const opad = Buffer.from(kk.map((b) => b ^ 0x5c));
        const want = hash(Buffer.concat([opad, hash(Buffer.concat([ipad, message]))])).toString('hex');
        const mac = new Hmac(key, new a.C(a.options));
        mac.update(message);
        assert.equal(toHex(mac.finalize()), want);
      });

      it('refuses states that no engine can work on, the same way in both engines', () => {
        const state = () => new a.C(a.options).getState();
        const bad = [
          [(s) => { s.hash = 'x'; }, TypeError],
          [(s) => { s.hash.pop(); }, TypeError],
          [(s) => { s.hash[0] = 1.5; }, TypeError],
          [(s) => { s.counter = 'a'; }, TypeError],
          [(s) => { s.counter = 1; }, RangeError],
          [(s) => { s.counter = -a.block; }, RangeError],
          [(s) => { s.counter = a.block; s.message = ''; }, RangeError],
          [(s) => { s.counter = a.block; s.message = 'x'.repeat(a.keep - 1); }, RangeError],
          [(s) => { s.counter = a.block; s.message = 'x'.repeat(a.block + a.keep); s.hash = 'x'; }, TypeError],
          [(s) => { s.message = 5; }, TypeError],
        ];
        for (const [mutate, Err] of bad) {
          const s = state();
          mutate(s);
          const h = new a.C(a.options);
          h.setState(s);
          assert.throws(() => h.finalize(), Err);
          const before = JSON.stringify(h.getState());
          assert.throws(() => h.finalize(), Err);
          assert.equal(JSON.stringify(h.getState()), before, 'a refused call leaves the state alone');
        }
      });
    });
  }
});

// ---- options ---------------------------------------------------------------------------------------------

describe('options', () => {
  const bad = [
    [XxHash3, { seed: -1 }, RangeError], [XxHash3, { seed: 2 ** 53 }, RangeError], [XxHash3, { seed: 1.5 }, RangeError],
    [XxHash3, { seed: '1' }, TypeError], [XxHash128, { seed: NaN }, RangeError], [XxHash128, { seed: 1n }, TypeError],
    [Murmur3, { seed: 2 ** 32 }, RangeError], [Murmur3, { seed: -1 }, RangeError], [Murmur3x64, { seed: 'x' }, TypeError],
    [Murmur3x64, { seed: 2 ** 40 }, RangeError],
    [SipHash, undefined, TypeError], [SipHash, {}, TypeError], [SipHash, { key: 'short' }, RangeError],
    [SipHash, { key: 'k'.repeat(17) }, RangeError], [SipHash, { key: 'Ā'.repeat(16) }, TypeError],
    [SipHash, { key: 16 }, TypeError], [SipHash13, { key: new Uint8Array(15) }, RangeError], [SipHash13, null, TypeError],
    [XxHash3, 5, TypeError], [Murmur3, 'x', TypeError], [SipHash, true, TypeError],
  ];
  for (const [C, options, Err] of bad) {
    it(`${C.name} ${typeof options === 'object' && options !== null ? JSON.stringify(options, (k, v) => (typeof v === 'bigint' ? `${v}n` : v)) : String(options)} is refused with ${Err.name}`, () => {
      assert.throws(() => new C(options), Err);
    });
  }

  it('defaults, and the options object is not modified', () => {
    const options = {};
    new XxHash3(options);
    new Murmur3(options);
    assert.deepEqual(options, {});
    const keyed = { key: KEY };
    new SipHash(keyed);
    assert.deepEqual(Object.keys(keyed), ['key']);
    assert.equal(new XxHash128().options.seed, 0);
    assert.equal(new Murmur3x64().options.seed, 0);
    for (const C of [XxHash3, XxHash128, Murmur3, Murmur3x64]) {
      assert.equal(hexOf(C, undefined, 'abc'), hexOf(C, {}, 'abc'));
      assert.equal(hexOf(C, null, 'abc'), hexOf(C, { seed: 0 }, 'abc'));
    }
  });

  it('a seed or key changes the digest; key strings and bytes are the same key', () => {
    assert.notEqual(hexOf(XxHash3, { seed: 1 }, 'abc'), hexOf(XxHash3, {}, 'abc'));
    assert.notEqual(hexOf(XxHash128, { seed: 1 }, 'x'.repeat(500)), hexOf(XxHash128, {}, 'x'.repeat(500)));
    assert.notEqual(hexOf(Murmur3, { seed: 1 }, 'abc'), hexOf(Murmur3, {}, 'abc'));
    assert.notEqual(hexOf(SipHash, { key: bytes(16, 1) }, 'abc'), hexOf(SipHash, { key: KEY }, 'abc'));
    assert.equal(hexOf(SipHash, { key: KEY.toString('latin1') }, 'abc'), hexOf(SipHash, { key: KEY.buffer.slice(KEY.byteOffset, KEY.byteOffset + 16) }, 'abc'));
  });

  it('options inherited from the prototype are ignored', () => {
    const options = Object.create({ seed: 5, key: KEY });
    assert.equal(hexOf(XxHash3, options, 'abc'), hexOf(XxHash3, {}, 'abc'));
    assert.throws(() => new SipHash(options), TypeError);
  });
});

// ---- CryptoApi -----------------------------------------------------------------------------------------------

describe('CryptoApi', () => {
  it('getHasher() and hash() know the names', () => {
    const names = {
      xxhash3: XxHash3, xxhash128: XxHash128,
      murmur3: Murmur3, 'murmur3-x86-32': Murmur3, 'murmur3-x64-128': Murmur3x64,
    };
    for (const [name, C] of Object.entries(names)) {
      assert.ok(CryptoApi.getHasher(name) instanceof C, name);
    }
    for (const [name, C] of [['siphash', SipHash], ['siphash-2-4', SipHash], ['siphash-1-3', SipHash13]]) {
      assert.ok(CryptoApi.getHasher(name, { key: KEY }) instanceof C, name);
      assert.throws(() => CryptoApi.getHasher(name), TypeError, `${name} without a key`);
    }
    assert.equal(CryptoApi.hash('xxhash3', 'abc'), '78af5f94892f3950');
    assert.equal(CryptoApi.hash('xxhash128', 'abc'), '06b05ab6733a618578af5f94892f3950');
    assert.equal(CryptoApi.hash('xxhash3', 'abc', { seed: 5 }), hexOf(XxHash3, { seed: 5 }, 'abc'));
    assert.equal(CryptoApi.hash('siphash', '', { key: KEY }), '310e0edd47db6f72');
    assert.equal(CryptoApi.hash('siphash-1-3', '', { key: KEY }), 'dcc40f055801acab');
    assert.equal(CryptoApi.hash('murmur3', '', { seed: 1 }), '514e28b7');
    assert.equal(CryptoApi.hash('murmur3-x64-128', 'é'), hexOf(Murmur3x64, {}, Buffer.from('é', 'utf8')));
    assert.deepEqual([...CryptoApi.hashBytes('xxhash3', '')], [...Buffer.from('2d06800538d394c2', 'hex')]);
  });
});
