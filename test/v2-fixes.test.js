// The behaviors of crypto-api 0.8.5 that v2 fixes, each checked against an
// independent reference (node:crypto, BigInt arithmetic, the compression
// function of the original code fed a hand-built final block).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import CryptoApi from '../packages/crypto-api/src/crypto-api.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { fromUtf } from '../packages/crypto-api/src/encoder/utf.mjs';
import Has160 from '../packages/crypto-api/src/hasher/has160.mjs';
import Md2 from '../packages/crypto-api/src/hasher/md2.mjs';
import Md4 from '../packages/crypto-api/src/hasher/md4.mjs';
import Md5 from '../packages/crypto-api/src/hasher/md5.mjs';
import Ripemd from '../packages/crypto-api/src/hasher/ripemd.mjs';
import Sha0 from '../packages/crypto-api/src/hasher/sha0.mjs';
import Sha1 from '../packages/crypto-api/src/hasher/sha1.mjs';
import Sha256 from '../packages/crypto-api/src/hasher/sha256.mjs';
import Sha512 from '../packages/crypto-api/src/hasher/sha512.mjs';
import Sm3 from '../packages/crypto-api/src/hasher/sm3.mjs';
import Snefru from '../packages/crypto-api/src/hasher/snefru.mjs';
import Whirlpool from '../packages/crypto-api/src/hasher/whirlpool.mjs';
import LegacyMd5 from '../packages/crypto-api/legacy/hasher/md5.mjs';
import LegacyMd4 from '../packages/crypto-api/legacy/hasher/md4.mjs';
import LegacyHas160 from '../packages/crypto-api/legacy/hasher/has160.mjs';
import LegacyRipemd from '../packages/crypto-api/legacy/hasher/ripemd.mjs';
import LegacySha0 from '../packages/crypto-api/legacy/hasher/sha0.mjs';
import LegacySha1 from '../packages/crypto-api/legacy/hasher/sha1.mjs';
import LegacySha256 from '../packages/crypto-api/legacy/hasher/sha256.mjs';
import LegacySha512 from '../packages/crypto-api/legacy/hasher/sha512.mjs';
import LegacySm3 from '../packages/crypto-api/legacy/hasher/sm3.mjs';
import LegacyWhirlpool from '../packages/crypto-api/legacy/hasher/whirlpool.mjs';
import { V2_OPTIONS } from './harness/catalog.mjs';

const hex = (h) => toHex(h.finalize());
const json = (h) => JSON.stringify(h.getState());

const ALL = [
  ['has160', Has160], ['md2', Md2], ['md4', Md4], ['md5', Md5], ['ripemd', Ripemd], ['sha0', Sha0],
  ['sha1', Sha1], ['sha256', Sha256], ['sha512', Sha512], ['sm3', Sm3], ['snefru', Snefru], ['whirlpool', Whirlpool],
];

// ---- 1. text above \xFF ----------------------------------------------------

test('update() throws TypeError for code units above 0xFF and leaves the state untouched', () => {
  for (const [id, C] of ALL) {
    for (const wide of ['Привет', 'Ā', 'abcĀ', 'x\u{1F600}', '\ud800', 'a'.repeat(200) + 'Ā']) {
      const h = new C();
      h.update('abc');
      const before = json(h);
      assert.throws(() => h.update(wide), TypeError, `${id} ${JSON.stringify(wide)}`);
      assert.equal(json(h), before, `${id}: state unchanged`);
      const ref = new C();
      ref.update('abc');
      assert.equal(hex(h), hex(ref), `${id}: hasher still usable`);
    }
  }
  // Every byte value is accepted, and text goes through fromUtf().
  const all = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i)).join('');
  const h = new Sha256();
  h.update(all);
  assert.equal(hex(h), createHash('sha256').update(Buffer.from(all, 'latin1')).digest('hex'));
  const t = new Sha256();
  t.update(fromUtf('Привет'));
  assert.equal(hex(t), createHash('sha256').update('Привет', 'utf8').digest('hex'));
});

// ---- 2. bytes and other non-strings -------------------------------------------

test('update() hashes ArrayBuffer and ArrayBuffer views as bytes', () => {
  const bytes = Uint8Array.from({ length: 300 }, (_, i) => (i * 37 + 11) & 0xff);
  const want = createHash('sha256').update(bytes).digest('hex');
  const inputs = {
    Uint8Array: bytes,
    ArrayBuffer: bytes.slice().buffer,
    DataView: new DataView(bytes.slice().buffer),
    'subarray with offset': (() => { const big = new Uint8Array(310); big.set(bytes, 7); return big.subarray(7, 307); })(),
    Uint16Array: new Uint16Array(bytes.slice().buffer),
    Int8Array: new Int8Array(bytes.slice().buffer),
    Buffer: Buffer.from(bytes),
    SharedArrayBuffer: (() => { const sab = new SharedArrayBuffer(300); new Uint8Array(sab).set(bytes); return sab; })(),
  };
  for (const [name, input] of Object.entries(inputs)) {
    const h = new Sha256();
    h.update(input);
    assert.equal(hex(h), want, name);
  }
  // Mixed with binary strings, across block boundaries.
  const h = new Sha256();
  h.update(bytes.subarray(0, 70));
  h.update(String.fromCharCode(...bytes.subarray(70, 130)));
  h.update(bytes.subarray(130).buffer.slice(130));
  assert.equal(hex(h), want);
  // Large input (more than one conversion chunk and one wasm chunk).
  const large = Uint8Array.from({ length: 200000 }, (_, i) => (i * 7) & 0xff);
  const l = new Md5();
  l.update(large);
  assert.equal(hex(l), createHash('md5').update(large).digest('hex'));
  // Every family.
  for (const [id, C] of ALL) {
    const a = new C();
    const b = new C();
    a.update(bytes);
    b.update(String.fromCharCode(...bytes));
    assert.equal(hex(a), hex(b), id);
  }
});

test('update() throws TypeError for every other value', () => {
  for (const [id, C] of ALL) {
    for (const bad of [undefined, null, 12345, true, [97, 98], { toString: () => 'abc' }, Symbol('x'), 1n, () => 'abc']) {
      const h = new C();
      const before = json(h);
      assert.throws(() => h.update(bad), TypeError, `${id} ${typeof bad}`);
      assert.equal(json(h), before, id);
    }
  }
});

// ---- 3. 64-bit length field ---------------------------------------------------

/** Families with an 8-byte length field after ISO 7816 padding (0x80, zeros). */
const MD_STYLE = [
  { id: 'md4', Legacy: LegacyMd4, block: 64, le: true },
  { id: 'md5', Legacy: LegacyMd5, block: 64, le: true },
  { id: 'has160', Legacy: LegacyHas160, block: 64, le: true },
  ...[128, 160, 256, 320].map((length) => ({ id: `ripemd${length}`, Legacy: LegacyRipemd, options: { length }, block: 64, le: true })),
  { id: 'sha0', Legacy: LegacySha0, block: 64 },
  { id: 'sha1', Legacy: LegacySha1, block: 64 },
  { id: 'sha224', Legacy: LegacySha256, options: { length: 224 }, block: 64 },
  { id: 'sha256', Legacy: LegacySha256, block: 64 },
  ...[224, 256, 384, 512].map((length) => ({ id: `sha512/${length}`, Legacy: LegacySha512, options: { length }, block: 128 })),
  { id: 'sm3', Legacy: LegacySm3, block: 64 },
  // Whirlpool pads to a 256-bit field; the top 24 bytes are always zero.
  ...['', '0', 't'].map((type) => ({ id: `whirlpool${type}`, Legacy: LegacyWhirlpool, options: { type }, block: 64, padAt: 32 })),
];

const FACADES = { md4: Md4, md5: Md5, has160: Has160, ripemd: Ripemd, sha0: Sha0, sha1: Sha1, sha256: Sha256, sha512: Sha512, sm3: Sm3, whirlpool: Whirlpool };
const facadeOf = (c) => FACADES[c.Legacy.name.toLowerCase()];

function fieldBytes(length, le) {
  const bits = BigInt(length) * 8n;
  const out = [];
  for (let i = 7; i >= 0; i--) out.push(Number((bits >> BigInt(8 * i)) & 0xffn));
  return le ? out.reverse() : out;
}

/** The digest of "abc" as if `length` bytes had been hashed: the original compression of a hand-built last block. */
function reference(c, length) {
  const h = new c.Legacy(c.options && { ...c.options });
  const fieldAt = c.block - 8;
  let block = 'abc\x80';
  while (block.length < fieldAt) block += '\x00';
  block += String.fromCharCode(...fieldBytes(length, c.le));
  h.state.message = block;
  h.process();
  return toHex(h.getStateHash(c.id.startsWith('sha512') || c.id === 'sha224' ? (c.options.length / 32) | 0 : undefined));
}

const BIG = [2 ** 31 - 1, 2 ** 31, 2 ** 31 + 5, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 7, 3 * 2 ** 31 + 9, 2 ** 40 + 3, 2 ** 53 - 1];

test('the length field is the 64-bit bit count for messages of 2 GiB and more (wasm and JS)', () => {
  for (const c of MD_STYLE) {
    const F = facadeOf(c);
    for (const length of [3, ...BIG]) {
      const want = reference(c, length);
      for (const C of [F, c.Legacy]) {
        const h = new C(c.options && { ...c.options });
        h.update('abc');
        h.state.length = length;
        assert.equal(hex(h), want, `${c.id} ${C === F ? 'facade' : 'JS'} length ${length}`);
      }
    }
  }
});

test('the length field bytes, big- and little-endian, against BigInt', () => {
  for (const length of [0, 1, 55, 2 ** 29, ...BIG]) {
    for (const [C, le] of [[LegacySha1, false], [LegacyMd5, true]]) {
      const h = new C();
      h.state.message = '';
      h.state.length = length;
      h.addLengthBits();
      assert.deepEqual([...h.state.message].map((x) => x.charCodeAt(0)), fieldBytes(length, le), `${C.name} ${length}`);
    }
  }
});

test('snefru: length field fixed, wasm (below 2^32) and JS (above) agree', () => {
  for (const options of [{ length: 128 }, { length: 256, rounds: 4 }]) {
    for (const length of BIG) {
      const a = new Snefru(options);
      a.update('abc');
      a.state.length = length;
      const b = new Snefru(options);
      b.update('abc');
      b.state.length = length;
      // Force the JS code path for b.
      b.getStateHash = function getStateHash(size) { return Object.getPrototypeOf(Snefru.prototype).getStateHash.call(this, size); };
      assert.equal(hex(a), hex(b), `${JSON.stringify(options)} length ${length}`);
    }
    // And the field changes the digest at 2^31 the way the bit count says: 2^31 and 2^31 + 2^32 differ.
    const at = (len) => { const h = new Snefru(options); h.update('abc'); h.state.length = len; return hex(h); };
    assert.notEqual(at(2 ** 31), at(2 ** 31 + 2 ** 32));
  }
});

// ---- 4. getHasher('sm3') ------------------------------------------------------

test("getHasher('sm3') returns an Sm3 hasher; hash() and hmac() accept 'sm3'", () => {
  const h = CryptoApi.getHasher('sm3');
  assert.ok(h instanceof Sm3);
  h.update('abc');
  assert.equal(hex(h), createHash('sm3').update('abc').digest('hex'));
  assert.equal(CryptoApi.hash('sm3', 'Привет'), createHash('sm3').update('Привет').digest('hex'));
  assert.equal(CryptoApi.hmac('key', 'message', CryptoApi.getHasher('sm3')), createHmac('sm3', 'key').update('message').digest('hex'));
  assert.equal(CryptoApi.getHasher('sm3', { rounds: 32 }).options.rounds, 32);
});

// ---- 5. Hmac -----------------------------------------------------------------

const HMAC_CASES = [
  ['md5', () => new Md5()], ['sha1', () => new Sha1()], ['sha224', () => new Sha256({ length: 224 })],
  ['sha256', () => new Sha256()], ['sha384', () => new Sha512({ length: 384 })], ['sha512', () => new Sha512()],
  ['ripemd160', () => new Ripemd({ length: 160 })], ['sm3', () => new Sm3()],
];

test('Hmac does not touch the hasher it is given, and ignores data already in it', () => {
  for (const [name, make] of HMAC_CASES) {
    const hasher = make();
    hasher.update('already here');
    const before = json(hasher);
    const m = new Hmac('key', hasher);
    m.update('message');
    assert.equal(toHex(m.finalize()), createHmac(name, 'key').update('message').digest('hex'), name);
    assert.equal(json(hasher), before, `${name}: hasher untouched`);
    hasher.update(' and more');
    const ref = make();
    ref.update('already here and more');
    assert.equal(hex(hasher), hex(ref), `${name}: hasher still independent`);
  }
});

test('Hmac.finalize() is repeatable, update() continues the message, reset() restarts it', () => {
  for (const [name, make] of HMAC_CASES) {
    for (const key of ['', 'key', 'k'.repeat(64), 'k'.repeat(129)]) {
      const node = (msg) => createHmac(name, Buffer.from(key, 'latin1')).update(msg).digest('hex');
      const m = new Hmac(key, make());
      m.update('The quick brown fox ');
      const first = toHex(m.finalize());
      assert.equal(first, node('The quick brown fox '), `${name} key ${key.length}`);
      assert.equal(toHex(m.finalize()), first, `${name}: second finalize()`);
      m.update('jumps over the lazy dog');
      assert.equal(toHex(m.finalize()), node('The quick brown fox jumps over the lazy dog'), `${name}: update after finalize`);
      m.reset();
      m.update('abc');
      assert.equal(toHex(m.finalize()), node('abc'), `${name}: reset`);
      m.reset();
      assert.equal(toHex(m.finalize()), node(''), `${name}: reset, empty`);
    }
  }
});

test('Hmac keys and messages: binary strings and bytes; CryptoApi.hmac() UTF-8 encodes strings', () => {
  const key = Uint8Array.from({ length: 100 }, (_, i) => (i * 13) & 0xff);
  const msg = Uint8Array.from({ length: 150 }, (_, i) => (i * 29) & 0xff);
  const want = createHmac('sha256', key).update(msg).digest('hex');
  const m = new Hmac(key, new Sha256());
  m.update(msg);
  assert.equal(toHex(m.finalize()), want);
  const s = new Hmac(String.fromCharCode(...key), new Sha256());
  s.update(msg.buffer);
  assert.equal(toHex(s.finalize()), want);
  assert.equal(CryptoApi.hmac(key, msg, CryptoApi.getHasher('sha256')), want);
  assert.equal(CryptoApi.hmac('ключ', 'сообщение', CryptoApi.getHasher('sha256')),
    createHmac('sha256', 'ключ').update('сообщение').digest('hex'));
  assert.throws(() => new Hmac('Ā', new Sha256()), TypeError);
  assert.throws(() => new Hmac(5, new Sha256()), TypeError);
  assert.throws(() => new Hmac('key', null), TypeError);
});

test('Hmac works with a user-written hasher, including one whose constructor takes no options', () => {
  class Sum extends Hasher {
    constructor() { super(); this.blockSizeInBytes = 8; }
    finalize() { let s = 0; for (const c of this.state.message) s = (s * 31 + c.charCodeAt(0)) | 0; return String.fromCharCode(s & 255, (s >> 8) & 255); }
  }
  const mac = (msg) => { const m = new Hmac('key', new Sum()); m.update(msg); return toHex(m.finalize()); };
  const m = new Hmac('key', new Sum());
  m.update('hello');
  assert.equal(toHex(m.finalize()), mac('hello'));
  assert.equal(toHex(m.finalize()), mac('hello'));
  // Plain object hashers (no class) are copied.
  const plain = Object.assign(Object.create(Sum.prototype), new Sum());
  const p = new Hmac('key', plain);
  p.update('hello');
  assert.equal(toHex(p.finalize()), mac('hello'));
});

// ---- 6. rounds / length -------------------------------------------------------

test('rounds/length: every supported value is accepted, neighbours and odd values throw', () => {
  for (const [id, C] of ALL) {
    const rules = V2_OPTIONS[id];
    for (const [key, values] of Object.entries(rules)) {
      for (const v of values) assert.doesNotThrow(() => new C({ [key]: v }), `${id} ${key} ${v}`);
      const lo = Math.min(...values);
      const hi = Math.max(...values);
      for (const v of [lo - 1, hi + 1, 0, -1, 1.5, NaN, Infinity, -Infinity, 2 ** 53]) {
        if (values.includes(v)) continue;
        assert.throws(() => new C({ [key]: v }), RangeError, `${id} ${key} ${v}`);
      }
      for (const v of ['8', true, false, null, [], {}, 1n]) {
        assert.throws(() => new C({ [key]: v }), TypeError, `${id} ${key} ${String(v)}`);
      }
    }
    // An options object that is rejected is not modified.
    for (const key of Object.keys(rules)) {
      const o = { [key]: -1 };
      assert.throws(() => new C(o));
      assert.deepEqual(o, { [key]: -1 });
    }
    // undefined means the default.
    assert.equal(json(new C({ rounds: undefined, length: undefined })), json(new C()), id);
  }
  // Stepped and listed lengths.
  for (const length of [33, 100, 500, 1024]) assert.throws(() => new Sha512({ length }), RangeError);
  for (const length of [160, 192, 480]) assert.doesNotThrow(() => new Sha512({ length }));
  for (const length of [96, 160, 448]) assert.doesNotThrow(() => new Snefru({ length }));
  for (const length of [480, 512]) assert.throws(() => new Snefru({ length }), RangeError);
  // getHasher() checks the merged options.
  assert.throws(() => CryptoApi.getHasher('sha256', { length: 160 }), RangeError);
  assert.throws(() => CryptoApi.getHasher('snefru128/2', { rounds: 9 }), RangeError);
  assert.throws(() => CryptoApi.hash('sha1', 'x', { rounds: 81 }), RangeError);
});

// Opt-in (LARGE_TESTS=1): a real 2 GiB + 3 byte message, about a minute per algorithm.
test('real messages over 2 GiB match node:crypto (LARGE_TESTS=1)', { skip: !process.env.LARGE_TESTS }, () => {
  const total = 2 ** 31 + 3;
  const chunk = Uint8Array.from({ length: 1 << 24 }, (_, i) => (i * 31 + 7) & 0xff);
  for (const [name, C] of [['md5', Md5], ['sha256', Sha256], ['sha512', Sha512]]) {
    const h = new C();
    const n = createHash(name);
    for (let done = 0; done < total;) {
      const part = chunk.subarray(0, Math.min(chunk.length, total - done));
      h.update(part);
      n.update(part);
      done += part.length;
    }
    assert.equal(hex(h), n.digest('hex'), name);
  }
});
