// cSHAKE, KMAC, TupleHash, ParallelHash (NIST SP 800-185), TurboSHAKE and KangarooTwelve (RFC 9861):
// packages/crypto-api/src/hasher/{cshake,kmac,tuplehash,parallelhash,turboshake,kangarootwelve}.mjs.
//
// New in crypto-api-ng, so there is no 0.8.5 class to diff against. The oracles are the published
// answers in test/vectors/keccak-modes/ (written by scripts/gen-keccak-mode-vectors.mjs), node:crypto
// for the cases that reduce to SHAKE, and, in the Zig tests, std.crypto. Every check that matters runs
// with the wasm module and again with the pure-JavaScript fallback.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import CShake from '../packages/crypto-api/src/hasher/cshake.mjs';
import Kmac from '../packages/crypto-api/src/hasher/kmac.mjs';
import TupleHash from '../packages/crypto-api/src/hasher/tuplehash.mjs';
import ParallelHash from '../packages/crypto-api/src/hasher/parallelhash.mjs';
import TurboShake from '../packages/crypto-api/src/hasher/turboshake.mjs';
import KangarooTwelve from '../packages/crypto-api/src/hasher/kangarootwelve.mjs';
import Shake from '../packages/crypto-api/src/hasher/shake.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import CryptoApi from '../packages/crypto-api/src/index.mjs';
import { _internal } from '../packages/crypto-api/src/wasm/keccak.mjs';
import { leftEncode, rightEncode, encodeString, bytepad, lengthEncode } from '../packages/crypto-api/src/keccak/modes.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { readVectors, rng, binString } from './support/le32-suite.js';

const sp800 = readVectors('keccak-modes/sp800-185');
const rfc9861 = readVectors('keccak-modes/kangarootwelve');

const bin = (hex) => Buffer.from(hex, 'hex').toString('latin1');
const hexOf = (h) => toHex(h.finalize());

/** The RFC 9861 inputs: {pattern: n} is 00 01 .. FA repeated to n bytes, {ff: n} is n bytes FF. */
const patternCache = new Map();
function spec(s) {
  if ('ff' in s) return '\xff'.repeat(s.ff);
  if (!patternCache.has(s.pattern)) {
    let unit = '';
    for (let i = 0; i < 251; i++) unit += String.fromCharCode(i);
    patternCache.set(s.pattern, unit.repeat(Math.ceil(s.pattern / 251)).slice(0, s.pattern));
  }
  return patternCache.get(s.pattern);
}

/** Run `body` with the wasm module, then again with it disabled (the JavaScript fallback). */
function both(name, body) {
  test(`${name} (wasm)`, () => {
    _internal.reset(false);
    assert.ok(_internal.runtime(), 'wasm failed to instantiate; run `zig build js` first');
    body('wasm');
  });
  test(`${name} (JavaScript fallback)`, () => {
    _internal.reset(true);
    try {
      assert.equal(_internal.runtime(), null);
      body('js');
    } finally {
      _internal.reset(false);
    }
  });
}

/** A hasher for a row of sp800-185.json, and the input to give it. */
function fromSp800(v) {
  const common = { strength: v.strength, length: v.length, customization: v.customization };
  switch (v.algo) {
    case 'cshake': return [new CShake({ ...common, functionName: v.functionName }), [bin(v.input)]];
    case 'kmac': return [new Kmac({ ...common, key: bin(v.key), xof: v.xof }), [bin(v.input)]];
    case 'tuplehash': return [new TupleHash({ ...common, xof: v.xof }), v.tuple.map(bin)];
    case 'parallelhash': return [new ParallelHash({ ...common, blockSize: v.blockSize, xof: v.xof }), [bin(v.input)]];
    default: throw new Error(`unknown algorithm ${v.algo}`);
  }
}

both('NIST SP 800-185 samples', () => {
  assert.equal(sp800.length, 36);
  for (const v of sp800) {
    const [h, inputs] = fromSp800(v);
    for (const x of inputs) h.update(x);
    assert.equal(hexOf(h), v.output, `${v.algo}${v.strength}${v.xof ? ' XOF' : ''} ${v.customization}`);
  }
});

both('RFC 9861 vectors: TurboSHAKE, KT128 and KT256', (engine) => {
  assert.equal(rfc9861.length, 54);
  for (const v of rfc9861) {
    // The 17^6-byte (24 MB) messages take a while in plain JavaScript; 17^5 bytes covers the same paths.
    if (engine === 'js' && v.message.pattern > 2e6) continue;
    const strength = Number(v.algo.slice(-3));
    const length = v.length * 8;
    const h = v.algo.startsWith('kt') ?
      new KangarooTwelve({ strength, length, customization: spec(v.customization) }) :
      new TurboShake({ strength, length, domain: v.domain });
    h.update(spec(v.message));
    assert.equal(toHex(h.finalize().slice(v.skip)), v.output, `${v.algo} ${JSON.stringify(v.message)}`);
  }
});

test('the SP 800-185 and RFC 9861 encodings', () => {
  assert.equal(leftEncode(0), '\x01\x00');
  assert.equal(rightEncode(0), '\x00\x01');
  assert.equal(leftEncode(168), '\x01\xa8');
  assert.equal(leftEncode(256), '\x02\x01\x00');
  assert.equal(rightEncode(256), '\x01\x00\x02');
  assert.equal(leftEncode(2 ** 53 - 1), '\x07\x1f\xff\xff\xff\xff\xff\xff');
  assert.equal(encodeString(''), '\x01\x00');
  assert.equal(encodeString('ab'), '\x01\x10ab');
  assert.equal(bytepad('xyz', 8), '\x01\x08xyz\x00\x00\x00');
  assert.equal(bytepad('xyzuvw', 8), '\x01\x08xyzuvw');
  assert.equal(lengthEncode(0), '\x00');
  assert.equal(lengthEncode(12), '\x0c\x01');
  assert.equal(lengthEncode(65538), '\x01\x00\x02\x03');
  assert.throws(() => leftEncode(-1), RangeError);
  assert.throws(() => leftEncode(2 ** 53), RangeError);
});

both('cSHAKE with no function name or customization is SHAKE', () => {
  for (const strength of [128, 256]) {
    for (const len of [0, 1, 135, 136, 168, 500]) {
      const msg = binString(rng(len), len);
      const h = new CShake({ strength, length: 800 });
      h.update(msg);
      const want = createHash(`shake${strength}`, { outputLength: 100 }).update(Buffer.from(msg, 'latin1')).digest('hex');
      assert.equal(hexOf(h), want);
      const s = new Shake({ strength, length: 800 });
      s.update(msg);
      assert.equal(hexOf(s), want);
    }
  }
});

/** Every class with a factory, for the checks that apply to all of them. */
const ALL = [
  ['CShake', (o) => new CShake({ customization: 'S', ...o })],
  ['Kmac', (o) => new Kmac({ key: 'key', ...o })],
  ['Kmac xof', (o) => new Kmac({ key: 'key', xof: true, ...o })],
  ['TupleHash', (o) => new TupleHash(o)],
  ['ParallelHash', (o) => new ParallelHash({ blockSize: 100, ...o })],
  ['ParallelHash xof', (o) => new ParallelHash({ blockSize: 1, xof: true, ...o })],
  ['TurboShake', (o) => new TurboShake(o)],
  ['KangarooTwelve', (o) => new KangarooTwelve({ customization: 'C', ...o })],
];

both('input in any split gives the one-shot result (TupleHash: the same elements)', () => {
  const rand = rng(0x185);
  const msg = binString(rand, 3 * 8192 + 400);
  for (const [name, make] of ALL) {
    for (const strength of [128, 256]) {
      for (const len of [0, 1, 167, 168, 169, 8191, 8192, 8193, 2 * 8192, 2 * 8192 + 1, msg.length]) {
        const m = msg.slice(0, len);
        const one = make({ strength });
        one.update(m);
        const pieces = make({ strength });
        if (name === 'TupleHash') {
          pieces.update(m);
        } else {
          for (let pos = 0; pos < len;) {
            const n = Math.min(len - pos, Math.floor(rand() * 3000));
            pieces.update(m.slice(pos, pos + n));
            pos += n;
          }
        }
        assert.equal(hexOf(pieces), hexOf(one), `${name} ${strength} ${len}`);
      }
    }
  }
});

both('bytes and binary strings give the same result', () => {
  const msg = binString(rng(0xb17e5), 5 * 8192 + 77);
  const bytes = Buffer.from(msg, 'latin1');
  for (const [name, make] of ALL) {
    for (const strength of [128, 256]) {
      const s = make({ strength });
      s.update(msg.slice(0, 5));
      s.update(msg.slice(5));
      const b = make({ strength });
      b.update(new Uint8Array(bytes.subarray(0, 5)));
      b.update(new Uint8Array(bytes.subarray(5)));
      assert.equal(hexOf(b), hexOf(s), `${name} ${strength}`);
    }
  }
});

both('finalize() can be repeated and update() continues the message; getState/setState round-trips', () => {
  for (const [name, make] of ALL) {
    const h = make({});
    h.update('first part of the message '.repeat(400));
    const state = h.getState();
    const a = hexOf(h);
    assert.equal(hexOf(h), a, name);
    h.update('second');
    const b = hexOf(h);
    assert.notEqual(b, a, name);
    const restored = make({});
    restored.setState(JSON.parse(JSON.stringify(state)));
    assert.equal(hexOf(restored), a, name);
    restored.update('second');
    assert.equal(hexOf(restored), b, name);
    h.reset();
    assert.equal(hexOf(h), hexOf(make({})), name);
  }
});

both('the wasm module and the JavaScript fallback agree', () => {
  // Checked by running the same inputs in both modes and comparing with the published vectors above;
  // here, ParallelHash and KangarooTwelve outputs that span several squeeze blocks.
  const msg = binString(rng(7), 20000);
  const p = new ParallelHash({ blockSize: 777, length: 8 * 1000, customization: 'x' });
  p.update(msg);
  const k = new KangarooTwelve({ strength: 256, length: 8 * 1000 });
  k.update(msg);
  assert.equal(createHash('sha256').update(p.digest()).digest('hex').length, 64);
  const outputs = [hexOf(p), hexOf(k)];
  _internal.reset(!_internal.runtime());
  try {
    assert.deepEqual([hexOf(p), hexOf(k)], outputs);
  } finally {
    _internal.reset(false);
  }
});

test('the length is part of KMAC, TupleHash and ParallelHash, not of their XOF forms', () => {
  for (const [C, base] of [[Kmac, { key: 'k' }], [TupleHash, {}], [ParallelHash, {}]]) {
    const short = new C({ ...base, length: 256 });
    const long = new C({ ...base, length: 512 });
    short.update('m');
    long.update('m');
    assert.notEqual(hexOf(long).slice(0, 64), hexOf(short));
    const xs = new C({ ...base, length: 256, xof: true });
    const xl = new C({ ...base, length: 512, xof: true });
    xs.update('m');
    xl.update('m');
    assert.equal(hexOf(xl).slice(0, 64), hexOf(xs));
  }
});

test('TupleHash: every update() is one element', () => {
  const one = new TupleHash();
  one.update('ab');
  const two = new TupleHash();
  two.update('a');
  two.update('b');
  const empty = new TupleHash();
  empty.update('');
  assert.notEqual(hexOf(one), hexOf(two));
  assert.notEqual(hexOf(empty), hexOf(new TupleHash()));
  const bytes = new TupleHash();
  bytes.update(new Uint8Array([0x61]));
  bytes.update(new Uint8Array([0x62]));
  assert.equal(hexOf(bytes), hexOf(two));
});

test('KangarooTwelve: the customization and the chunk boundary', () => {
  // M || C crosses 8192 bytes only through the customization: still one tree.
  const a = new KangarooTwelve({ customization: 'c'.repeat(100) });
  a.update('m'.repeat(8100));
  const b = new KangarooTwelve({ customization: 'c'.repeat(100) });
  for (let i = 0; i < 81; i++) b.update('m'.repeat(100));
  assert.equal(hexOf(a), hexOf(b));
  assert.notEqual(hexOf(new KangarooTwelve({ customization: 'x' })), hexOf(new KangarooTwelve()));
  // TurboSHAKE with 12 rounds is not SHAKE.
  assert.notEqual(hexOf(new TurboShake()), hexOf(new Shake()));
});

test('classes extend Hasher and keep their checked options', () => {
  for (const [name, make] of ALL) {
    const h = make({ strength: 256 });
    assert.ok(h instanceof Hasher, name);
    assert.equal(h.blockSizeInBytes, 136, name);
    assert.equal(h.options.strength, 256, name);
    assert.equal(h.options.length, 512, name);
    assert.equal(h.finalize().length, 64, name);
  }
  assert.equal(new ParallelHash().options.blockSize, 8192);
  assert.equal(new TurboShake().options.domain, 0x1f);
  assert.equal(new Kmac({ key: new Uint8Array([1, 2]) }).options.key, '\x01\x02');
});

test('options are validated at construction', () => {
  assert.throws(() => new Kmac(), TypeError);
  assert.throws(() => new Kmac({}), TypeError);
  assert.throws(() => new Kmac({ key: 5 }), TypeError);
  assert.throws(() => new Kmac({ key: 'k', xof: 1 }), TypeError);
  assert.throws(() => new CShake('x'), TypeError);
  assert.throws(() => new CShake({ strength: 192 }), RangeError);
  assert.throws(() => new CShake({ length: 7 }), RangeError);
  assert.throws(() => new CShake({ length: 2 ** 31 }), RangeError);
  assert.throws(() => new CShake({ customization: 'Ā' }), TypeError);
  assert.throws(() => new ParallelHash({ blockSize: 0 }), RangeError);
  assert.throws(() => new ParallelHash({ blockSize: 1.5 }), RangeError);
  assert.throws(() => new TurboShake({ domain: 0 }), RangeError);
  assert.throws(() => new TurboShake({ domain: 0x80 }), RangeError);
  assert.throws(() => new KangarooTwelve({ strength: '128' }), TypeError);
});

test('inherited values are not options', () => {
  Object.prototype.key = 'polluted';
  Object.prototype.customization = 'polluted';
  Object.prototype.strength = 256;
  try {
    assert.throws(() => new Kmac({}), TypeError);
    const h = new CShake({});
    assert.equal(h.options.strength, 128);
    assert.equal(h.options.customization, '');
  } finally {
    delete Object.prototype.key;
    delete Object.prototype.customization;
    delete Object.prototype.strength;
  }
});

test('a broken state from setState() is refused, not hashed', () => {
  const p = new ParallelHash({ blockSize: 10 });
  p.setState({ ...p.getState(), inner: [1, 2] });
  assert.throws(() => p.update('x'), TypeError);
  const p2 = new ParallelHash({ blockSize: 10 });
  p2.setState({ ...p2.getState(), filled: 10 });
  assert.throws(() => p2.finalize(), RangeError);
  const k = new KangarooTwelve();
  k.setState({ ...k.getState(), leaves: -1 });
  assert.throws(() => k.finalize(), TypeError);
});

test('CryptoApi.getHasher() and hash() know the new names', () => {
  const key = { key: bin('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f') };
  const kmac = sp800.find((v) => v.algo === 'kmac' && !v.xof && v.strength === 128 && v.customization === '');
  assert.equal(CryptoApi.hash('kmac128', bin(kmac.input), key), kmac.output);
  const kx = sp800.find((v) => v.algo === 'kmac' && v.xof && v.strength === 256 && v.input.length === 8);
  assert.equal(CryptoApi.hash('kmacxof256', bin(kx.input), { ...key, customization: kx.customization }), kx.output);
  assert.equal(CryptoApi.hash('kt128', ''), rfc9861[0].output);
  assert.equal(CryptoApi.hash('kangarootwelve', ''), rfc9861[0].output);
  assert.equal(CryptoApi.hash('kt256', '').length, 128);
  assert.equal(CryptoApi.hash('turboshake128', ''), rfc9861.find((v) => v.algo === 'turboshake128').output);
  for (const name of ['cshake128', 'cshake256', 'tuplehash128', 'tuplehash256', 'tuplehashxof128', 'tuplehashxof256',
    'parallelhash128', 'parallelhash256', 'parallelhashxof128', 'parallelhashxof256', 'turboshake256', 'kmac256', 'kmacxof128']) {
    const h = CryptoApi.getHasher(name, { key: 'k' });
    assert.ok(h instanceof Hasher, name);
    assert.equal(h.options.strength, Number(name.slice(-3)), name);
  }
  assert.equal(CryptoApi.getHasher('kmacxof128', { key: 'k' }).options.xof, true);
  assert.equal(CryptoApi.getHasher('parallelhash128').options.xof, false);
  assert.throws(() => CryptoApi.hash('kmac128', 'm'), TypeError);
});
