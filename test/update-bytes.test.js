// update() with bytes (src/tools/direct.mjs): a Uint8Array, ArrayBuffer or other view is copied
// straight into wasm memory instead of going through a binary string. The state and the digest
// must be exactly what update() with the same bytes as a binary string gives, for every hasher,
// every way of splitting the message, and every state the fast path does not handle (an
// overridden process() or processBlock(), a state from setState(), no WebAssembly).
//
// The binary-string path is the reference. Independent digests come from node:crypto.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import CryptoApi from '../packages/crypto-api/src/index.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import Md5, { _internal as md5 } from '../packages/crypto-api/src/hasher/md5.mjs';
import Sha256, { _internal as sha256 } from '../packages/crypto-api/src/hasher/sha256.mjs';
import Ripemd, { _internal as ripemd } from '../packages/crypto-api/src/hasher/ripemd.mjs';
import Md2, { _internal as md2 } from '../packages/crypto-api/src/hasher/md2.mjs';
import Snefru, { _internal as snefru } from '../packages/crypto-api/src/hasher/snefru.mjs';
import Sha3 from '../packages/crypto-api/src/hasher/sha3.mjs';
import { _internal as keccak } from '../packages/crypto-api/src/wasm/keccak.mjs';
import Blake2b, { _internal as blake2b } from '../packages/crypto-api/src/hasher/blake2b.mjs';
import Blake3, { _internal as blake3 } from '../packages/crypto-api/src/hasher/blake3.mjs';
import Tiger, { _internal as tiger } from '../packages/crypto-api/src/hasher/tiger.mjs';
import XxHash64, { _internal as xxhash64 } from '../packages/crypto-api/src/hasher/xxhash64.mjs';
import { bytesHandler } from '../packages/crypto-api/src/tools/direct.mjs';
import { copyIn, binaryOf } from '../packages/crypto-api/src/wasm/family.mjs';
import { rng } from './support/le32-suite.js';

const NAMES = [
  'blake2b', 'blake2b-256', 'blake2s', 'blake2s-128', 'blake3',
  'has160', 'md2', 'md4', 'md5', 'ripemd128', 'ripemd160', 'ripemd256', 'ripemd320',
  'sha0', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sm3',
  'sha3-224', 'sha3-256', 'sha3-512', 'keccak256', 'shake128', 'shake256',
  'snefru', 'snefru256', 'snefru128/2', 'snefru256/4', 'whirlpool', 'whirlpool-0', 'whirlpool-t',
  'tiger', 'tiger2', 'streebog', 'streebog256', 'crc32', 'crc32c', 'xxhash32', 'xxhash64',
  'xxhash3', 'xxhash128', 'murmur3', 'murmur3-x64-128',
];

const LENGTHS = [0, 1, 15, 16, 17, 47, 48, 63, 64, 65, 127, 128, 129, 191, 1023, 1024, 1025, 2111, 2112, 2113, 3000, 70000];

function randomBytes(rand, n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (rand() * 256) | 0;
  return b;
}

const binary = (bytes) => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('latin1');

/** State JSON and digest after feeding `pieces` (binary strings or bytes) to a fresh hasher. */
function run(make, pieces) {
  const h = make();
  for (const piece of pieces) h.update(piece);
  const state = JSON.stringify(h.getState());
  return { state, digest: h.finalize() };
}

/** Split points that hit the block-boundary cases of the fast path. */
function splits(length) {
  return [...new Set([0, 1, 5, 16, 63, 64, 100, 1000, length >> 1, length - 1, length])]
    .filter((s) => s >= 0 && s <= length);
}

describe('update() with bytes leaves the same state and digest as with a binary string', () => {
  for (const name of NAMES) {
    it(name, () => {
      const make = () => CryptoApi.getHasher(name);
      assert.notEqual(bytesHandler(make()), undefined, 'no bytes handler is registered');
      const rand = rng(0xb17e5 + name.length);
      for (const length of LENGTHS) {
        const bytes = randomBytes(rand, length);
        for (const at of splits(length)) {
          const head = bytes.subarray(0, at);
          const tail = bytes.subarray(at);
          const expected = run(make, [binary(head), binary(tail)]);
          assert.deepEqual(run(make, [head, tail]), expected, `${length} bytes split at ${at}`);
          // An ArrayBuffer, and a view that does not start at offset 0 of its buffer.
          const copy = new Uint8Array(length + 3);
          copy.set(bytes, 3);
          assert.deepEqual(run(make, [head.slice().buffer, new DataView(copy.buffer, 3 + at)]), expected,
            `ArrayBuffer + DataView, ${length} bytes split at ${at}`);
          // Strings and bytes mixed.
          assert.deepEqual(run(make, [binary(head), tail]), expected, `string + bytes, ${length} split at ${at}`);
          assert.deepEqual(run(make, [head, binary(tail)]), expected, `bytes + string, ${length} split at ${at}`);
        }
      }
    });
  }
});

describe('the digests match node:crypto', () => {
  const pairs = [
    ['md5', 'md5'], ['sha1', 'sha1'], ['sha256', 'sha256'], ['sha512', 'sha512'],
    ['sha3-256', 'sha3-256'], ['blake2b', 'blake2b512'], ['ripemd160', 'ripemd160'],
  ];
  const rand = rng(77);
  const message = randomBytes(rand, 300001);
  const text = 'The quick brown fox jumps over the lazy dog. '.repeat(3000);
  for (const [name, node] of pairs) {
    it(name, () => {
      let supported = true;
      try {
        createHash(node);
      } catch (e) {
        supported = false;
      }
      if (!supported) return;
      const want = createHash(node).update(message).digest('hex');
      for (const piece of [message, message.buffer, binary(message)]) {
        const h = CryptoApi.getHasher(name);
        h.update(piece);
        assert.equal(Buffer.from(h.finalize(), 'latin1').toString('hex'), want);
      }
      // ASCII text and a binary string with bytes above 0x7F take different string copies.
      const h = CryptoApi.getHasher(name);
      h.update(text);
      assert.equal(Buffer.from(h.finalize(), 'latin1').toString('hex'), createHash(node).update(text, 'latin1').digest('hex'));
    });
  }
});

describe('the bytes path is not taken where it would change behavior', () => {
  const rand = rng(99);
  const message = randomBytes(rand, 5000);

  it('an instance or subclass that replaces process() gets one process() call per update()', () => {
    for (const Cls of [Md5, Sha256, Md2, Snefru, Sha3, Blake2b, Blake3, Tiger]) {
      const h = new Cls();
      let calls = 0;
      const original = h.process;
      h.process = function () {
        calls++;
        return original.call(this);
      };
      h.update(message);
      h.update(message.subarray(1));
      assert.equal(calls, 2, Cls.name);
      assert.equal(bytesHandler(h), undefined);
      assert.deepEqual(run(() => h, []), run(() => new Cls(), [binary(message), binary(message.subarray(1))]), Cls.name);

      class Sub extends Cls {
        process() {
          calls++;
          return super.process();
        }
      }
      calls = 0;
      const s = new Sub();
      s.update(message);
      assert.equal(calls, 1, `${Cls.name} subclass`);
    }
  });

  it('a replaced processBlock() still runs', () => {
    for (const [Cls, field] of [[Md5, 'processBlock'], [Sha256, 'processBlock'], [Md2, 'processBlock'], [Ripemd, 'processBlock160']]) {
      const plain = new Cls();
      const h = new Cls();
      let blocks = 0;
      const original = Cls.prototype[field];
      h[field] = function (block) {
        blocks++;
        return original.call(this, block);
      };
      if (Cls === Ripemd) h.processBlock = h[field];
      h.update(message);
      plain.update(binary(message));
      assert.ok(blocks > 0, Cls.name);
      assert.equal(h.finalize(), plain.finalize(), Cls.name);
    }
  });

  it('a pending message from setState() with a code unit above 0xFF goes to the original code', () => {
    for (const Cls of [Md5, Sha256, Ripemd, Md2]) {
      const a = new Cls();
      const b = new Cls();
      const state = a.getState();
      state.message = 'abcĀ';
      a.setState(JSON.parse(JSON.stringify(state)));
      b.setState(JSON.parse(JSON.stringify(state)));
      a.update(message);
      b.update(binary(message));
      assert.deepEqual(a.getState(), b.getState(), Cls.name);
    }
  });

  it('a long pending message from setState() is compressed first', () => {
    for (const make of [() => new Md5(), () => new Sha256(), () => new Blake2b(), () => new Blake3(), () => new XxHash64()]) {
      const a = make();
      const b = make();
      const state = a.getState();
      state.message = binary(message.subarray(0, 333));
      a.setState(JSON.parse(JSON.stringify(state)));
      b.setState(JSON.parse(JSON.stringify(state)));
      a.update(message);
      b.update(binary(message));
      assert.deepEqual(a.getState(), b.getState());
      assert.equal(a.finalize(), b.finalize());
    }
  });

  it('a state the engines refuse throws the same error as before', () => {
    for (const make of [() => new Blake2b(), () => new Blake3(), () => new Tiger(), () => new Sha3()]) {
      const a = make();
      a.state.hash = 'nope';
      a.state.stack = 'nope';
      let bytesError;
      let stringError;
      try {
        a.update(message);
      } catch (e) {
        bytesError = e;
      }
      const b = make();
      b.state.hash = 'nope';
      b.state.stack = 'nope';
      try {
        b.update(binary(message));
      } catch (e) {
        stringError = e;
      }
      assert.ok(stringError, 'the string path throws');
      assert.equal(String(bytesError), String(stringError));
    }
  });
});

describe('without WebAssembly', () => {
  const rand = rng(1234);
  const message = randomBytes(rand, 10000);
  for (const [name, make, hooks] of [
    ['md5', () => new Md5(), md5], ['sha256', () => new Sha256(), sha256], ['ripemd160', () => new Ripemd(), ripemd],
    ['md2', () => new Md2(), md2], ['snefru', () => new Snefru(), snefru], ['sha3-256', () => new Sha3({ length: 256 }), keccak],
    ['blake2b', () => new Blake2b(), blake2b], ['blake3', () => new Blake3(), blake3], ['tiger', () => new Tiger(), tiger],
    ['xxhash64', () => new XxHash64(), xxhash64],
  ]) {
    it(name, () => {
      const expected = run(make, [binary(message)]);
      hooks.reset(true);
      try {
        assert.deepEqual(run(make, [message.subarray(0, 77), message.subarray(77)]), expected);
      } finally {
        hooks.reset();
      }
      assert.deepEqual(run(make, [message.subarray(0, 77), message.subarray(77)]), expected);
    });
  }
});

describe('Hmac', () => {
  const rand = rng(4321);
  const message = randomBytes(rand, 9000);
  const key = randomBytes(rand, 20);

  it('passes bytes on and matches node:crypto', () => {
    for (const [name, node] of [['md5', 'md5'], ['sha256', 'sha256'], ['sha512', 'sha512']]) {
      const mac = new Hmac(key, CryptoApi.getHasher(name));
      mac.update(message.subarray(0, 100));
      mac.update(message.subarray(100));
      assert.equal(Buffer.from(mac.finalize(), 'latin1').toString('hex'),
        createHmac(node, key).update(message).digest('hex'));
    }
  });

  it('gives a hasher with its own update() a binary string, as before', () => {
    const seen = [];
    class Own extends Md5 {
      update(m) {
        seen.push(typeof m);
        return super.update(m);
      }
    }
    const mac = new Hmac(key, new Own());
    mac.update(message);
    assert.ok(seen.length > 0);
    assert.ok(seen.every((t) => t === 'string'));
    assert.equal(Buffer.from(mac.finalize(), 'latin1').toString('hex'), createHmac('md5', key).update(message).digest('hex'));
  });

  it('still rejects what update() rejects', () => {
    const mac = new Hmac(key, new Md5());
    assert.throws(() => mac.update([1, 2, 3]), TypeError);
    assert.throws(() => new Md5().update([1, 2, 3]), TypeError);
    assert.equal(Hasher.prototype.update.length, 1);
  });
});

describe('copyIn() and binaryOf()', () => {
  const memory = new Uint8Array(1 << 16);
  const cases = {
    ascii: 'abcdefghijklmnopqrstuvwxyz0123456789'.repeat(40),
    latin1: Array.from({ length: 1500 }, (_, i) => String.fromCharCode((i * 37) & 0xff)).join(''),
    short: 'x\xffy',
    wide: 'a'.repeat(100) + 'ā' + 'b'.repeat(100),
  };
  for (const [label, s] of Object.entries(cases)) {
    it(label, () => {
      memory.fill(0xaa);
      const bits = copyIn(memory, 10, s, 3, s.length);
      let want = 0;
      for (let i = 3; i < s.length; i++) {
        want |= s.charCodeAt(i);
        assert.equal(memory[10 + i - 3], s.charCodeAt(i) & 0xff, `byte ${i}`);
      }
      assert.equal(memory[9], 0xaa);
      assert.equal(memory[10 + s.length - 3], 0xaa);
      // 0 for a range of bytes, the OR of the code units otherwise; only "above 0xFF" matters.
      assert.equal(bits > 0xff, want > 0xff);
      if (label !== 'wide') assert.equal(binaryOf(Uint8Array.from(memory.subarray(10, 10 + s.length - 3)), 0), s.substring(3));
    });
  }
  it('bytes', () => {
    const bytes = Uint8Array.from({ length: 20000 }, (_, i) => i * 13);
    assert.equal(copyIn(memory, 5, bytes, 100, 19000), 0);
    assert.deepEqual(memory.subarray(5, 5 + 18900), bytes.subarray(100, 19000));
    assert.equal(binaryOf(bytes, 100, 19000), binary(bytes.subarray(100, 19000)));
    assert.equal(binaryOf(bytes, 19990), binary(bytes.subarray(19990)));
  });
});
