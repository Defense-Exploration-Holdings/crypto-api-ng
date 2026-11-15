// SHA-3, SHAKE and Keccak (packages/crypto-api/src/hasher/{sha3,shake,keccak}.mjs).
//
// These algorithms are new in crypto-api-ng: there is no 0.8.5 class to diff against.
// The oracles are the published answers in test/vectors/sha3.json, node:crypto
// (OpenSSL: SHA-3, SHAKE, HMAC-SHA-3) and, for Keccak, the Zig tests, which compare
// the core with std.crypto. Every check that matters runs twice: with the wasm module
// and with the pure-JavaScript fallback that CSP and no-WebAssembly environments use.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import Sha3 from '../packages/crypto-api/src/hasher/sha3.mjs';
import Shake from '../packages/crypto-api/src/hasher/shake.mjs';
import Keccak from '../packages/crypto-api/src/hasher/keccak.mjs';
import Sponge from '../packages/crypto-api/src/hasher/sponge.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import CryptoApi from '../packages/crypto-api/src/index.mjs';
import { _internal } from '../packages/crypto-api/src/wasm/keccak.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { FUZZ_ITERS, readVectors, rng, binString } from './support/le32-suite.js';

const vectors = readVectors('sha3');

const OPENSSL = { 'sha3-224': 'sha3-224', 'sha3-256': 'sha3-256', 'sha3-384': 'sha3-384', 'sha3-512': 'sha3-512' };

/** Hasher for a vector's algorithm id. */
function make(algo, options) {
  switch (algo) {
    case 'sha3-224': return new Sha3({ length: 224, ...options });
    case 'sha3-256': return new Sha3({ length: 256, ...options });
    case 'sha3-384': return new Sha3({ length: 384, ...options });
    case 'sha3-512': return new Sha3({ length: 512, ...options });
    case 'shake128': return new Shake({ strength: 128, length: 256, ...options });
    case 'shake256': return new Shake({ strength: 256, length: 512, ...options });
    case 'keccak224': return new Keccak({ length: 224, ...options });
    case 'keccak256': return new Keccak({ length: 256, ...options });
    case 'keccak384': return new Keccak({ length: 384, ...options });
    case 'keccak512': return new Keccak({ length: 512, ...options });
    default: throw new Error(`unknown algorithm ${algo}`);
  }
}

const RATE = { 'sha3-224': 144, 'sha3-256': 136, 'sha3-384': 104, 'sha3-512': 72, shake128: 168, shake256: 136, keccak224: 144, keccak256: 136, keccak384: 104, keccak512: 72 };

const hex = (h) => toHex(h.finalize());
const json = (h) => JSON.stringify(h.getState());

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

const input = (v) => (v.inputHex !== undefined ? Buffer.from(v.inputHex, 'hex').toString('latin1') : String.fromCharCode(parseInt(v.repeatByte, 16)).repeat(v.count));

both('published answers: every vector, whole message and byte-by-byte updates', () => {
  for (const v of vectors) {
    const message = input(v);
    const whole = make(v.algo);
    whole.update(message);
    assert.equal(hex(whole), v.hex, `${v.algo} ${v.name}`);
    if (message.length <= 1600) {
      const bytes = make(v.algo);
      for (let i = 0; i < message.length; i++) bytes.update(message[i]);
      assert.equal(hex(bytes), v.hex, `${v.algo} ${v.name} byte by byte`);
    }
  }
});

test('the Keccak-256 values every Ethereum developer knows', () => {
  assert.equal(CryptoApi.hash('keccak256', ''), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(CryptoApi.hash('keccak256', 'abc'), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  assert.equal(CryptoApi.hash('sha3-256', ''), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
});

test('the JavaScript permutation reproduces the Keccak-f[1600] test vector', () => {
  // Keccak team, KeccakF-1600-IntermediateValues: first lanes after one and two permutations of the zero state.
  const s = new Int32Array(50);
  _internal.permute(s);
  assert.equal((BigInt(s[1] >>> 0) << 32n | BigInt(s[0] >>> 0)).toString(16), 'f1258f7940e1dde7');
  assert.equal((BigInt(s[3] >>> 0) << 32n | BigInt(s[2] >>> 0)).toString(16), '84d5ccf933c0478a');
  _internal.permute(s);
  assert.equal((BigInt(s[1] >>> 0) << 32n | BigInt(s[0] >>> 0)).toString(16), '2d5c954df96ecb3c');
});

both('matches node:crypto at every length 0..600 and across the block boundaries', () => {
  const rand = rng(0x5a3);
  const data = binString(rand, 600);
  for (let len = 0; len <= 600; len++) {
    const message = data.slice(0, len);
    for (const [id, name] of Object.entries(OPENSSL)) {
      const h = make(id);
      h.update(message);
      assert.equal(hex(h), createHash(name).update(message, 'latin1').digest('hex'), `${id} ${len}`);
    }
    for (const [id, bytes] of [['shake128', 17], ['shake128', 168], ['shake128', 169], ['shake256', 64], ['shake256', 300]]) {
      const h = make(id, { length: bytes * 8 });
      h.update(message);
      assert.equal(hex(h), createHash(id, { outputLength: bytes }).update(message, 'latin1').digest('hex'), `${id}/${bytes} ${len}`);
    }
  }
});

both('random splits of one message give one digest', () => {
  const rand = rng(0x5117);
  for (let i = 0; i < FUZZ_ITERS; i++) {
    const id = Object.keys(RATE)[(rand() * 10) | 0];
    const len = (rand() * 700) | 0;
    const message = binString(rand, len);
    const whole = make(id);
    whole.update(message);
    const expected = hex(whole);
    const h = make(id);
    for (let pos = 0; pos < len;) {
      const n = (rand() * 250) | 0;
      h.update(message.slice(pos, pos + n));
      pos += n;
    }
    assert.equal(hex(h), expected, `${id} ${len}`);
  }
});

both('inputs spanning several wasm chunks, and outputs longer than one', () => {
  const rand = rng(77);
  const message = binString(rand, 200000);
  for (const id of ['sha3-256', 'sha3-512', 'shake128', 'shake256']) {
    const h = make(id, id.startsWith('shake') ? { length: 100000 * 8 } : {});
    h.update(message);
    const want = createHash(id, id.startsWith('shake') ? { outputLength: 100000 } : {}).update(message, 'latin1').digest('hex');
    assert.equal(hex(h), want, id);
  }
  const exact = binString(rand, 136 * 482);
  const h = new Sha3({ length: 256 });
  h.update(exact);
  assert.equal(hex(h), createHash('sha3-256').update(exact, 'latin1').digest('hex'));
});

test('wasm is used in a normal environment and not after it failed to load', () => {
  _internal.reset(false);
  assert.ok(_internal.runtime());
  const before = _internal.wasmCalls();
  new Sha3().update('x'.repeat(500));
  const h = new Sha3({ length: 256 });
  h.update('abc');
  h.finalize();
  assert.ok(_internal.wasmCalls() >= before + 2);
  _internal.reset(true);
  try {
    const calls = _internal.wasmCalls();
    const g = new Sha3({ length: 256 });
    g.update('x'.repeat(500));
    assert.equal(toHex(g.finalize()), createHash('sha3-256').update('x'.repeat(500)).digest('hex'));
    assert.equal(_internal.wasmCalls(), calls);
    assert.equal(_internal.runtime(), null, 'the failure is remembered');
  } finally {
    _internal.reset(false);
  }
});

both('finalize() leaves the state alone: repeatable, and update() continues', () => {
  for (const id of Object.keys(RATE)) {
    const h = make(id);
    h.update('hello ');
    const state = json(h);
    const first = hex(h);
    assert.equal(json(h), state, `${id}: state unchanged by finalize`);
    assert.equal(hex(h), first, `${id}: second finalize`);
    h.update('world');
    const whole = make(id);
    whole.update('hello world');
    assert.equal(hex(h), hex(whole), `${id}: update after finalize`);
    h.reset();
    assert.equal(hex(h), hex(make(id)), `${id}: reset`);
  }
});

both('getState() and setState() resume a hash', () => {
  const rand = rng(5);
  for (const id of Object.keys(RATE)) {
    const message = binString(rand, 777);
    const a = make(id);
    a.update(message.slice(0, 400));
    const saved = a.getState();
    assert.deepEqual(saved, JSON.parse(JSON.stringify(saved)), 'plain JSON');
    assert.equal(saved.hash.length, 50);
    assert.equal(saved.length, 400);
    a.update(message.slice(400));
    const b = make(id);
    b.setState(JSON.parse(JSON.stringify(saved)));
    b.update(message.slice(400));
    assert.equal(hex(b), hex(a), id);
  }
});

both('a state with unabsorbed whole blocks (setState) still finalizes correctly', () => {
  const message = 'q'.repeat(1000);
  const h = new Sha3({ length: 256 });
  h.setState({ message, length: 1000, hash: new Array(50).fill(0) });
  assert.equal(hex(h), createHash('sha3-256').update(message).digest('hex'));
  assert.equal(h.state.message.length, 1000, 'finalize does not touch the state');
});

test('the wasm module and the JavaScript fallback give the same digests and states', () => {
  const rand = rng(1234);
  const ids = Object.keys(RATE);
  try {
    for (let i = 0; i < 100; i++) {
      const id = ids[(rand() * ids.length) | 0];
      const message = binString(rand, (rand() * 900) | 0);
      const options = id.startsWith('shake') ? { length: 8 * (1 + ((rand() * 300) | 0)) } : {};
      const run = (disable) => {
        _internal.reset(disable);
        const h = make(id, options);
        h.update(message);
        return [json(h), hex(h)];
      };
      assert.deepEqual(run(false), run(true), `${id} ${message.length}`);
    }
  } finally {
    _internal.reset(false);
  }
});

test('memory never grows, however many hashers run', () => {
  const rt = _internal.runtime();
  const size = rt.u8.buffer.byteLength;
  for (let i = 0; i < 20000; i++) {
    const h = new Sha3({ length: 256 });
    h.update('abc');
    h.finalize();
  }
  const big = new Shake({ strength: 128, length: 8 * 200000 });
  big.update('x'.repeat(100000));
  assert.equal(big.finalize().length, 200000);
  assert.equal(rt.u8.buffer.byteLength, size);
});

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

test('classes extend Hasher and expose rate and options like the other hashers', () => {
  for (const [id, rate] of Object.entries(RATE)) {
    const h = make(id);
    assert.ok(h instanceof Hasher);
    assert.ok(h instanceof Sponge);
    assert.equal(h.blockSizeInBytes, rate, id);
    assert.equal(h.unitSize, 1);
    assert.deepEqual(Object.keys(h.getState()).sort(), ['hash', 'length', 'message']);
  }
  assert.equal(Sha3.length, 1);
  assert.equal(Shake.length, 1);
  assert.equal(Keccak.length, 1);
});

test('defaults: SHA3-512, Keccak-512, SHAKE128 with 32 bytes', () => {
  assert.equal(toHex(new Sha3().finalize()), createHash('sha3-512').digest('hex'));
  assert.equal(toHex(new Sha3(null).finalize()), createHash('sha3-512').digest('hex'));
  assert.equal(toHex(new Keccak().finalize()), vectors.find((v) => v.algo === 'keccak512' && v.name === 'empty').hex);
  assert.equal(toHex(new Shake().finalize()), createHash('shake128', { outputLength: 32 }).digest('hex'));
  assert.equal(toHex(new Shake({ strength: 256 }).finalize()), createHash('shake256', { outputLength: 64 }).digest('hex'));
  assert.equal(toHex(new Shake({ length: 8 }).finalize()), createHash('shake128', { outputLength: 1 }).digest('hex'));
});

test('options are validated at construction', () => {
  for (const bad of [0, 128, 225, 1024, 256.5, NaN, Infinity]) {
    assert.throws(() => new Sha3({ length: bad }), RangeError, `Sha3 length ${bad}`);
    assert.throws(() => new Keccak({ length: bad }), RangeError, `Keccak length ${bad}`);
  }
  for (const bad of ['256', true, null, {}, []]) {
    assert.throws(() => new Sha3({ length: bad }), TypeError);
    assert.throws(() => new Keccak({ length: bad }), TypeError);
    assert.throws(() => new Shake({ strength: bad }), TypeError);
    assert.throws(() => new Shake({ length: bad }), TypeError);
  }
  for (const bad of [0, 127, 512, 224]) assert.throws(() => new Shake({ strength: bad }), RangeError);
  for (const bad of [0, 4, 12, 255, -8, 2 ** 30 + 8, 1.5]) assert.throws(() => new Shake({ length: bad }), RangeError, `Shake length ${bad}`);
  assert.doesNotThrow(() => new Shake({ length: 2 ** 30 }));
  assert.doesNotThrow(() => new Sha3({ length: undefined }));
  const options = { length: 256 };
  new Sha3(options);
  assert.deepEqual(options, { length: 256 }, 'the caller\'s options are not modified');
});

test('update() takes bytes and binary strings, and rejects the rest like every hasher', () => {
  const bytes = Uint8Array.from([0x61, 0x62, 0x63]);
  const a = new Sha3({ length: 256 });
  a.update(bytes);
  assert.equal(hex(a), createHash('sha3-256').update('abc').digest('hex'));
  const b = new Sha3({ length: 256 });
  b.update(bytes.buffer);
  assert.equal(hex(b), hex(a));
  assert.throws(() => new Sha3().update('Ā'), TypeError);
  assert.throws(() => new Shake().update(123), TypeError);
  assert.throws(() => new Keccak().update(null), TypeError);
  assert.throws(() => new Keccak().update(undefined), TypeError);
});

test('CryptoApi.getHasher() and hash() know the new names', () => {
  const cases = {
    'sha3-224': Sha3, 'sha3-256': Sha3, 'sha3-384': Sha3, 'sha3-512': Sha3,
    keccak224: Keccak, keccak256: Keccak, keccak384: Keccak, keccak512: Keccak,
    shake128: Shake, shake256: Shake,
  };
  for (const [name, Class] of Object.entries(cases)) {
    const h = CryptoApi.getHasher(name);
    assert.ok(h instanceof Class, name);
    assert.equal(h.blockSizeInBytes, RATE[name], name);
  }
  assert.equal(CryptoApi.hash('sha3-256', 'abc'), createHash('sha3-256').update('abc').digest('hex'));
  assert.equal(CryptoApi.hash('sha3-512', new Uint8Array([1, 2, 3])), createHash('sha3-512').update(Buffer.from([1, 2, 3])).digest('hex'));
  assert.equal(CryptoApi.hash('shake128', 'abc'), createHash('shake128', { outputLength: 32 }).update('abc').digest('hex'));
  assert.equal(CryptoApi.hash('shake256', 'abc'), createHash('shake256', { outputLength: 64 }).update('abc').digest('hex'));
  assert.equal(CryptoApi.hash('shake128', 'abc', { length: 800 }), createHash('shake128', { outputLength: 100 }).update('abc').digest('hex'));
  // An explicit option wins over the one the name implies, as for every other name.
  assert.equal(CryptoApi.hash('sha3-256', 'abc', { length: 512 }), createHash('sha3-512').update('abc').digest('hex'));
  for (const name of ['sha3', 'SHA3-256', 'sha3_256', 'sha-3', 'shake', 'shake512', 'keccak', 'keccak-256']) {
    assert.equal(CryptoApi.getHasher(name), undefined, name);
  }
});

both('HMAC-SHA-3 matches node:crypto, for keys shorter than, equal to and longer than the block', () => {
  const rand = rng(99);
  for (const name of ['sha3-224', 'sha3-256', 'sha3-384', 'sha3-512']) {
    const rate = RATE[name];
    for (const keyLen of [0, 1, 32, rate - 1, rate, rate + 1, 2 * rate + 5]) {
      const key = binString(rand, keyLen);
      const message = binString(rand, (rand() * 400) | 0);
      const mac = new Hmac(key, CryptoApi.getHasher(name));
      mac.update(message);
      const want = createHmac(name, Buffer.from(key, 'latin1')).update(message, 'latin1').digest('hex');
      assert.equal(toHex(mac.finalize()), want, `${name} key ${keyLen}`);
      assert.equal(toHex(mac.finalize()), want, `${name} key ${keyLen} again`);
    }
  }
  assert.equal(CryptoApi.hmac('key', 'The quick brown fox jumps over the lazy dog', CryptoApi.getHasher('sha3-256')),
    createHmac('sha3-256', 'key').update('The quick brown fox jumps over the lazy dog').digest('hex'));
});
