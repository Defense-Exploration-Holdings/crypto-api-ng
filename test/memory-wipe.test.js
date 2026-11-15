// After a hash or HMAC call, nothing the call was given may be left in the
// family's wasm memory: not the message bytes, not the HMAC pad blocks, and not
// the digest or the hash words derived from them. The scan covers the whole
// linear memory of the module (scratch region, stack, data), not only the
// scratch slots the facade writes to.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import Has160, { _internal as has160 } from '../packages/crypto-api/src/hasher/has160.mjs';
import Md2, { _internal as md2 } from '../packages/crypto-api/src/hasher/md2.mjs';
import Md4, { _internal as md4 } from '../packages/crypto-api/src/hasher/md4.mjs';
import Md5, { _internal as md5 } from '../packages/crypto-api/src/hasher/md5.mjs';
import Ripemd, { _internal as ripemd } from '../packages/crypto-api/src/hasher/ripemd.mjs';
import Sha0, { _internal as sha0 } from '../packages/crypto-api/src/hasher/sha0.mjs';
import Sha1, { _internal as sha1 } from '../packages/crypto-api/src/hasher/sha1.mjs';
import Sha256, { _internal as sha256 } from '../packages/crypto-api/src/hasher/sha256.mjs';
import Sha512, { _internal as sha512 } from '../packages/crypto-api/src/hasher/sha512.mjs';
import Sm3, { _internal as sm3 } from '../packages/crypto-api/src/hasher/sm3.mjs';
import Snefru, { _internal as snefru } from '../packages/crypto-api/src/hasher/snefru.mjs';
import Whirlpool, { _internal as whirlpool } from '../packages/crypto-api/src/hasher/whirlpool.mjs';
import Sha3 from '../packages/crypto-api/src/hasher/sha3.mjs';
import Keccak from '../packages/crypto-api/src/hasher/keccak.mjs';
import Shake from '../packages/crypto-api/src/hasher/shake.mjs';
import { _internal as keccak } from '../packages/crypto-api/src/wasm/keccak.mjs';
import Blake2b, { _internal as blake2b } from '../packages/crypto-api/src/hasher/blake2b.mjs';
import Blake2s, { _internal as blake2s } from '../packages/crypto-api/src/hasher/blake2s.mjs';
import Blake3, { _internal as blake3 } from '../packages/crypto-api/src/hasher/blake3.mjs';
import { rng } from './support/le32-suite.js';

const CASES = [
  ['md2', Md2, md2, undefined],
  ['md4', Md4, md4, undefined],
  ['md5', Md5, md5, undefined],
  ['has160', Has160, has160, undefined],
  ['ripemd128', Ripemd, ripemd, { length: 128 }],
  ['ripemd160', Ripemd, ripemd, undefined],
  ['ripemd256', Ripemd, ripemd, { length: 256 }],
  ['ripemd320', Ripemd, ripemd, { length: 320 }],
  ['sha0', Sha0, sha0, undefined],
  ['sha1', Sha1, sha1, undefined],
  ['sha224', Sha256, sha256, { length: 224 }],
  ['sha256', Sha256, sha256, undefined],
  ['sm3', Sm3, sm3, undefined],
  ['sha384', Sha512, sha512, { length: 384 }],
  ['sha512', Sha512, sha512, undefined],
  ['sha512/256', Sha512, sha512, { length: 256 }],
  ['snefru128', Snefru, snefru, undefined],
  ['snefru256', Snefru, snefru, { length: 256, rounds: 4 }],
  ['whirlpool', Whirlpool, whirlpool, undefined],
  ['whirlpool-t', Whirlpool, whirlpool, { type: 't' }],
  ['whirlpool-0', Whirlpool, whirlpool, { type: '0' }],
  ['sha3-224', Sha3, keccak, { length: 224 }],
  ['sha3-256', Sha3, keccak, { length: 256 }],
  ['sha3-384', Sha3, keccak, { length: 384 }],
  ['sha3-512', Sha3, keccak, undefined],
  ['keccak256', Keccak, keccak, { length: 256 }],
  ['keccak512', Keccak, keccak, undefined],
  ['shake128', Shake, keccak, undefined],
  ['shake256', Shake, keccak, { strength: 256 }],
  ['blake2b', Blake2b, blake2b, undefined],
  ['blake2b-256', Blake2b, blake2b, { length: 256 }],
  ['blake2s', Blake2s, blake2s, undefined],
  ['blake2s-128', Blake2s, blake2s, { length: 128 }],
  ['blake3', Blake3, blake3, undefined],
];

const WINDOW = 16;

function randomBytes(rand, n) {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (rand() * 256) | 0;
  return b;
}

const binary = (b) => b.toString('latin1');

/** Every aligned window of `bytes`, as it appears in memory directly and as 32-bit words written little-endian from a big-endian reading. */
function windows(bytes, size = WINDOW) {
  const out = [];
  for (let i = 0; i + size <= bytes.length; i += 4) {
    const w = Buffer.from(bytes.subarray(i, i + size));
    out.push({ at: i, form: 'bytes', needle: w });
    out.push({ at: i, form: 'swapped words', needle: Buffer.from(w).swap32() });
  }
  return out;
}

/** Offsets in the whole memory where any window of `bytes` shows up; empty when nothing is left. */
function leaks(memory, bytes, label) {
  const found = [];
  for (const { at, form, needle } of windows(bytes)) {
    const i = memory.indexOf(needle);
    if (i !== -1) found.push(`${label}[${at}..${at + needle.length}] (${form}) at memory offset ${i}`);
  }
  return found;
}

function scan(rt, secrets) {
  const memory = Buffer.from(rt.u8.buffer, rt.u8.byteOffset, rt.u8.byteLength);
  return secrets.flatMap(([label, bytes]) => leaks(memory, bytes, label));
}

test('the scan finds bytes that are there (control)', () => {
  const rt = md5.runtime();
  assert.ok(rt, 'run `zig build js` first');
  const bytes = randomBytes(rng(1), 48);
  rt.u8.set(bytes, rt.base + 256 + 100);
  try {
    assert.ok(scan(rt, [['control', bytes]]).length > 0);
  } finally {
    rt.u8.fill(0, rt.base + 256 + 100, rt.base + 256 + 148);
  }
  assert.deepEqual(scan(rt, [['control', bytes]]), []);
});

for (const [name, Cls, internal, options] of CASES) {
  const make = () => (options ? new Cls(Object.assign({}, options)) : new Cls());

  test(`${name}: no message bytes, pad blocks or digests stay in wasm memory`, () => {
    const rt = internal.runtime();
    assert.ok(rt, 'wasm failed to instantiate; run `zig build js` first');
    const rand = rng(0x1234 + name.length);
    // Three full blocks of every size plus a tail long enough to need a second padding block.
    const message = randomBytes(rand, 3 * 128 + 101);
    const key = randomBytes(rand, 23);
    const calls = internal.wasmCalls();

    // Plain hash, one update and many small ones, with a digest at the end.
    const digests = [];
    for (const pieces of [[message.length], [7, 64, 1, 300, message.length - 372]]) {
      const h = make();
      let pos = 0;
      for (const n of pieces) {
        h.update(binary(message.subarray(pos, pos + n)));
        pos += n;
      }
      digests.push(Buffer.from(h.finalize(), 'latin1'));
    }
    assert.ok(internal.wasmCalls() > calls, 'the wasm path was not taken');
    assert.deepEqual(scan(rt, [['message', message], ['digest', digests[0]]]), []);

    // HMAC: key-derived pad blocks and the inner digest pass through the same region.
    const blockSize = make().blockSizeInBytes;
    const ipad = Buffer.alloc(blockSize, 0x36);
    const opad = Buffer.alloc(blockSize, 0x5c);
    for (let i = 0; i < key.length; i++) {
      ipad[i] ^= key[i];
      opad[i] ^= key[i];
    }
    const mac = new Hmac(binary(key), make());
    mac.update(binary(message));
    const tag = Buffer.from(mac.finalize(), 'latin1');
    assert.deepEqual(scan(rt, [
      ['message', message], ['key', key], ['ipad', ipad], ['opad', opad], ['tag', tag],
    ]), []);

    // The fallback that hands a call back to the original code half way: a code unit above 0xFF after
    // some blocks (`update()` refuses those, `state.message` and `setState()` do not).
    const wide = make();
    wide.state.message = binary(message.subarray(0, 2 * blockSize)) + 'Ā' + binary(message.subarray(0, 40));
    wide.process();
    try {
      wide.finalize();
    } catch (e) {
      // 1.1 refuses to hash the garbage a wide character leaves behind (MD2's checksum).
      assert.ok(e instanceof TypeError, String(e));
    }
    assert.deepEqual(scan(rt, [['message', message]]), []);
  });
}

// ---------------------------------------------------------------------------
// SHA-3 / SHAKE / Keccak, BLAKE2 and BLAKE3: keys, key-derived words, long output and big messages
// ---------------------------------------------------------------------------

/** Like `leaks()`, for long inputs: about `count` windows spread over the whole of `bytes`, raw and word-swapped. */
function sampledLeaks(memory, bytes, label, count = 300) {
  const found = [];
  const stride = Math.max(4, Math.floor(bytes.length / count / 4) * 4);
  for (let at = 0; at + WINDOW <= bytes.length; at += stride) {
    const w = Buffer.from(bytes.subarray(at, at + WINDOW));
    for (const [form, needle] of [['bytes', w], ['swapped words', Buffer.from(w).swap32()]]) {
      const i = memory.indexOf(needle);
      if (i !== -1) found.push(`${label}[${at}..${at + WINDOW}] (${form}) at memory offset ${i}`);
    }
  }
  return found;
}

function scanSampled(rt, secrets) {
  const memory = Buffer.from(rt.u8.buffer, rt.u8.byteOffset, rt.u8.byteLength);
  return secrets.flatMap(([label, bytes]) => (bytes.length > 2048 ? sampledLeaks(memory, bytes, label) : leaks(memory, bytes, label)));
}

/** The int32 words of a hasher (`state.hash`, key words) as the bytes they have in wasm memory. */
const wordBytes = (words) => Buffer.from(Int32Array.from(words).buffer);

const digestOf = (h, message) => {
  for (let pos = 0; pos < message.length; pos += 1000) h.update(binary(message.subarray(pos, pos + 1000)));
  return Buffer.from(h.finalize(), 'latin1');
};

describe('keys, key-derived words, long output and big messages leave nothing in the new families', () => {
  const rand = rng(0x5eed);
  const KEY32 = randomBytes(rand, 32);
  const KEY64 = randomBytes(rand, 64);
  const SMALL = randomBytes(rand, 3 * 128 + 101);
  const BIG = randomBytes(rand, 5 * 1024 + 77);
  const HUGE = randomBytes(rand, 70000 + 13);

  /**
   * Run `make()` hashers over the messages (one update, many updates, finalize twice) and scan after every digest.
   * `fixed` are values that are also constants of the module (the IV words in the chaining value): they must
   * be found exactly where they were found before the hashing started.
   */
  function check(label, rt, calls, make, secrets, messages = [SMALL, BIG, HUGE], fixed = []) {
    const before = scanSampled(rt, fixed);
    for (const message of messages) {
      for (const pieces of ['one', 'many']) {
        const h = make();
        let digest;
        if (pieces === 'one') {
          h.update(binary(message));
          digest = Buffer.from(h.finalize(), 'latin1');
        } else {
          digest = digestOf(h, message);
        }
        // finalize() twice: the second call runs the same stages again.
        const again = Buffer.from(h.finalize(), 'latin1');
        assert.deepEqual(again, digest);
        const found = scanSampled(rt, secrets.concat([['message', message], ['digest', digest]]));
        assert.deepEqual(found, [], `${label} (${pieces} update, ${message.length} bytes)`);
        assert.deepEqual(scanSampled(rt, fixed), before, `${label}: parameter words (${pieces} update, ${message.length} bytes)`);
      }
    }
    assert.ok(calls() > 0);
  }

  test('BLAKE3: the key words, the derived key of a context, the stack and the data region', () => {
    const rt = blake3.runtime();
    assert.ok(rt, 'run `zig build js` first');
    const calls = blake3.wasmCalls;
    check('keyed', rt, calls, () => new Blake3({ key: binary(KEY32) }), [['key', KEY32]]);
    check('keyed, 512 bits', rt, calls, () => new Blake3({ key: binary(KEY32), length: 512 }), [['key', KEY32]]);
    const contextHasher = new Blake3({ context: 'secret context string' });
    check('derive key', rt, calls, () => new Blake3({ context: 'secret context string' }), [['derived key', wordBytes(contextHasher.init.key)]]);
    // After a big message the stack of chaining values (up to 54 entries) was in the scratch region.
    const plain = new Blake3();
    plain.update(binary(HUGE));
    const state = plain.getState();
    assert.ok(state.stack.length >= 16);
    plain.finalize();
    assert.deepEqual(scanSampled(rt, [['stack', wordBytes(state.stack)]]), []);
    // HMAC over BLAKE3: the pad blocks (key-derived) and the inner digest pass through the same regions.
    const ipad = Buffer.alloc(64, 0x36);
    const opad = Buffer.alloc(64, 0x5c);
    for (let i = 0; i < 23; i++) {
      ipad[i] ^= KEY32[i];
      opad[i] ^= KEY32[i];
    }
    const mac = new Hmac(binary(KEY32.subarray(0, 23)), new Blake3());
    mac.update(binary(SMALL));
    const tag = Buffer.from(mac.finalize(), 'latin1');
    assert.deepEqual(scanSampled(rt, [['key', KEY32.subarray(0, 23)], ['ipad', ipad], ['opad', opad], ['tag', tag]]), []);
  });

  for (const [name, C, internal, block, max] of [['BLAKE2b', Blake2b, blake2b, 128, 64], ['BLAKE2s', Blake2s, blake2s, 64, 32]]) {
    test(`${name}: key and padded key block, salt and personalization, parameter-block words`, () => {
      const rt = internal.runtime();
      assert.ok(rt, 'run `zig build js` first');
      const key = KEY64.subarray(0, max);
      const shortKey = KEY64.subarray(0, 11);
      for (const [label, options] of [
        ['full key', { key: binary(key) }],
        ['short key (zero padded block)', { key: binary(shortKey) }],
        ['key, salt, personalization', { key: binary(shortKey), salt: 'salt-xyz', personalization: 'pers-xyz', length: 160 }],
        ['salt and personalization only', { salt: 'S1'.repeat(4), personalization: 'P2'.repeat(4) }],
        ['key as bytes', { key: new Uint8Array(key) }],
      ]) {
        const fresh = () => new C({ ...options });
        const k = options.key === undefined ? Buffer.alloc(0) : Buffer.from(binary(options.key), 'latin1');
        const secrets = [];
        if (k.length >= WINDOW) secrets.push(['key', k]);
        if (k.length) {
          // The key block is the key and zeros; look at the windows that hold key bytes (at least 11 of 16).
          const padded = Buffer.alloc(block);
          k.copy(padded);
          secrets.push(['key block', padded.subarray(0, Math.max(WINDOW, Math.min(block, k.length + 5)))]);
        }
        // Words 4 to 7 of the chaining value are the IV xor salt and personalization (the IV is a constant of the module).
        const fixed = options.salt === undefined ? [] : [['salt and personalization words', wordBytes(fresh().getState().hash).subarray(4 * (max / 8), 8 * (max / 8))]];
        check(`${name} ${label}`, rt, internal.wasmCalls, fresh, secrets, [SMALL, BIG, HUGE], fixed);
      }
    });
  }

  for (const [name, make] of [
    ['SHAKE128', (length) => new Shake({ strength: 128, length })],
    ['SHAKE256', (length) => new Shake({ strength: 256, length })],
    ['BLAKE3', (length) => new Blake3({ length })],
    ['keyed BLAKE3', (length) => new Blake3({ length, key: binary(KEY32) })],
  ]) {
    test(`${name}: output of several wasm calls, from short to 150 KB`, () => {
      const internal = name.includes('BLAKE') ? blake3 : keccak;
      const rt = internal.runtime();
      assert.ok(rt, 'run `zig build js` first');
      // Output calls are 63232 (BLAKE3) or 65024 (SHAKE) bytes at most: the last ones are short and overwrite the
      // head of the output of the one before.
      for (const bytes of [1, 64, 200, 4097, 65024, 65025, 63232 * 2 + 1000, 150000]) {
        const h = make(8 * bytes);
        h.update(binary(SMALL));
        const digest = Buffer.from(h.finalize(), 'latin1');
        assert.equal(digest.length, bytes);
        assert.deepEqual(scanSampled(rt, [['message', SMALL], ['digest', digest]]), [], `${bytes} bytes of output`);
      }
    });
  }

  test('SHA-3, Keccak and SHAKE: the sponge state and the tail', () => {
    const rt = keccak.runtime();
    assert.ok(rt, 'run `zig build js` first');
    for (const [label, make] of [
      ['SHA3-256', () => new Sha3({ length: 256 })],
      ['SHA3-512', () => new Sha3({ length: 512 })],
      ['Keccak-256', () => new Keccak({ length: 256 })],
      ['SHAKE128', () => new Shake({ length: 4096 })],
    ]) {
      // The sponge words after absorbing: `state.hash` is the secret-derived value.
      const h = make();
      h.update(binary(BIG));
      const hash = h.getState().hash;
      const digest = Buffer.from(h.finalize(), 'latin1');
      assert.deepEqual(scanSampled(rt, [['message', BIG], ['digest', digest], ['sponge words', wordBytes(hash)]]), [], label);
      check(label, rt, keccak.wasmCalls, make, [], [SMALL, BIG, HUGE]);
    }
  });

  test('a refused call, and the JavaScript hand-over after it, leave nothing behind either', () => {
    const RealInstance = WebAssembly.Instance;
    const refuseAll = /^(keccak|blake)/;
    WebAssembly.Instance = function Instance(module, imports) {
      const real = new RealInstance(module, imports);
      const exports = {};
      for (const key of Object.keys(real.exports)) {
        const value = real.exports[key];
        exports[key] = typeof value === 'function' && refuseAll.test(key) && !key.endsWith('_state_size') ? () => 3 : value;
      }
      return { exports };
    };
    const internals = [keccak, blake2b, blake2s, blake3];
    try {
      internals.forEach((i) => i.reset(false));
      for (const i of internals) assert.ok(i.runtime(), 'run `zig build js` first');
      const makers = [
        [keccak, () => new Sha3({ length: 256 })],
        [keccak, () => new Shake({ length: 8000 })],
        [blake2b, () => new Blake2b({ key: binary(KEY64) })],
        [blake2s, () => new Blake2s({ key: binary(KEY32) })],
        [blake3, () => new Blake3({ key: binary(KEY32), length: 800 })],
      ];
      for (const [internal, make] of makers) {
        const h = make();
        h.update(binary(BIG));
        const digest = Buffer.from(h.finalize(), 'latin1');
        assert.deepEqual(scanSampled(internal.runtime(), [['message', BIG], ['digest', digest], ['key', KEY32]]), []);
      }
    } finally {
      WebAssembly.Instance = RealInstance;
      internals.forEach((i) => i.reset(false));
    }
  });
});
