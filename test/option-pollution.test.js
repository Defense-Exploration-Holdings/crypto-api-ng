// Option values that are only inherited (set on `Object.prototype` by a bug
// elsewhere in the page or process) must never reach a hasher: crypto-api 0.8.5
// read `options.rounds`, `options.length` and `options.type` through the
// prototype chain, so `Object.prototype.rounds = 1` gave a one-round SHA-256.
// Every hasher, `CryptoApi.hash()` and `CryptoApi.hmac()` must return what they
// return on a clean `Object.prototype`, with wasm and with wasm disabled.
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';

import CryptoApi from '../packages/crypto-api/src/crypto-api.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { GET_HASHER_NAMES, ADDED_HASHER_NAMES } from './harness/catalog.mjs';

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
import Tiger, { _internal as tiger } from '../packages/crypto-api/src/hasher/tiger.mjs';
import Tiger2, { _internal as tiger2 } from '../packages/crypto-api/src/hasher/tiger2.mjs';
import Streebog, { _internal as streebog } from '../packages/crypto-api/src/hasher/streebog.mjs';
import Crc32, { _internal as crc32 } from '../packages/crypto-api/src/hasher/crc32.mjs';
import Crc32c, { _internal as crc32c } from '../packages/crypto-api/src/hasher/crc32c.mjs';
import XxHash32, { _internal as xxhash32 } from '../packages/crypto-api/src/hasher/xxhash32.mjs';
import XxHash64, { _internal as xxhash64 } from '../packages/crypto-api/src/hasher/xxhash64.mjs';

const INTERNALS = [has160, md2, md4, md5, ripemd, sha0, sha1, sha256, sha512, sm3, snefru, whirlpool, keccak, blake2b, blake2s, blake3, tiger, tiger2, streebog, crc32, crc32c, xxhash32, xxhash64];
// The hashers that have no 0.8.5 original: SHA-3, SHAKE, Keccak, BLAKE2 and BLAKE3 (every `getHasher()` name of them).
const NEW_NAMES = [
  'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'keccak224', 'keccak256', 'keccak384', 'keccak512', 'shake128', 'shake256',
  'blake2b', 'blake2b-512', 'blake2b-384', 'blake2b-256', 'blake2b-160', 'blake2b-128',
  'blake2s', 'blake2s-256', 'blake2s-224', 'blake2s-160', 'blake2s-128', 'blake3',
  'tiger', 'tiger192', 'tiger160', 'tiger128', 'tiger2', 'streebog', 'streebog256', 'streebog512',
  'crc32', 'crc32c', 'xxhash32', 'xxhash64',
];
const NAMES = GET_HASHER_NAMES.concat(ADDED_HASHER_NAMES.map((a) => a.name), NEW_NAMES);

const SHORT = 'abc';
const LONG = 'The quick brown fox jumps over the lazy dog. '.repeat(9);

/** Values that would change a digest if a hasher honored them. */
const HOSTILE = {
  'rounds 1': { rounds: 1 },
  'rounds 2': { rounds: 2 },
  'length 32': { length: 32 },
  'length 160': { length: 160 },
  'length 384': { length: 384 },
  'type t': { type: 't' },
  'type 0': { type: '0' },
  'all three': { rounds: 1, length: 32, type: 't' },
  // Options of the hashers without an original. Every value is one that would change a digest.
  'length 8': { length: 8 },
  'strength 256': { strength: 256 },
  'strength 128': { strength: 128 },
  'key': { key: 'k'.repeat(32) },
  'salt': { salt: 'salt' },
  'personalization': { personalization: 'pers' },
  'context': { context: 'my context' },
  'seed': { seed: 12345 },
  'key as bytes': { key: new Uint8Array(32).fill(7) },
  'salt and personalization': { salt: 's'.repeat(8), personalization: 'p'.repeat(8) },
  'everything': {
    rounds: 1, length: 8, type: '0', strength: 256, key: 'k'.repeat(32), salt: 'salt', personalization: 'pers', context: 'ctx', seed: 99,
  },
  // Values that would throw if they were validated.
  'invalid values': {
    rounds: 'x', length: 'y', type: {}, strength: null, key: 5, salt: {}, personalization: [], context: 7, seed: 'z',
  },
};

/** Run `fn` with the given properties inherited from `Object.prototype`, restoring it afterwards. */
function polluted(props, fn) {
  const keys = Object.keys(props);
  const saved = keys.map((k) => Object.getOwnPropertyDescriptor(Object.prototype, k));
  try {
    for (const k of keys) {
      Object.defineProperty(Object.prototype, k, { value: props[k], writable: true, enumerable: false, configurable: true });
    }
    return fn();
  } finally {
    keys.forEach((k, i) => {
      if (saved[i]) Object.defineProperty(Object.prototype, k, saved[i]);
      else delete Object.prototype[k];
    });
  }
}

/** Everything a caller can observe from one hasher name, as plain strings (safe to compute while polluted). */
function observe(name) {
  const out = [];
  for (const message of [SHORT, LONG]) {
    out.push(CryptoApi.hash(name, message));
    out.push(CryptoApi.hmac('key', message, CryptoApi.getHasher(name)));
    const h = CryptoApi.getHasher(name);
    h.update(message);
    out.push(JSON.stringify(h.options));
    out.push(toHex(h.finalize()));
    out.push(JSON.stringify(h.getState()));
  }
  return out.join('\n');
}

const CLASSES = [
  ['Has160', Has160], ['Md2', Md2], ['Md4', Md4], ['Md5', Md5], ['Ripemd', Ripemd], ['Sha0', Sha0], ['Sha1', Sha1],
  ['Sha256', Sha256], ['Sha512', Sha512], ['Sm3', Sm3], ['Snefru', Snefru], ['Whirlpool', Whirlpool],
  ['Sha3', Sha3], ['Keccak', Keccak], ['Shake', Shake], ['Blake2b', Blake2b], ['Blake2s', Blake2s], ['Blake3', Blake3],
  ['Tiger', Tiger], ['Tiger2', Tiger2], ['Streebog', Streebog], ['Crc32', Crc32], ['Crc32c', Crc32c], ['XxHash32', XxHash32], ['XxHash64', XxHash64],
];

/** Own options of the new classes, every one of them set. */
const NEW_OWN = [
  ['Sha3', Sha3, { length: 256 }],
  ['Sha3', Sha3, { length: 224 }],
  ['Keccak', Keccak, { length: 384 }],
  ['Shake', Shake, { strength: 256, length: 200 }],
  ['Shake', Shake, { strength: 128 }],
  ['Shake', Shake, { length: 80 }],
  ['Blake2b', Blake2b, { length: 256, key: 'own key', salt: 'own salt', personalization: 'own pers' }],
  ['Blake2b', Blake2b, { length: 40 }],
  ['Blake2s', Blake2s, { length: 128, key: new Uint8Array([1, 2, 3]), salt: 'own', personalization: 'own' }],
  ['Blake2s', Blake2s, { key: '' }],
  ['Blake3', Blake3, { length: 520, key: 'o'.repeat(32) }],
  ['Blake3', Blake3, { length: 64, context: 'own context' }],
  ['Blake3', Blake3, {}],
  ['Tiger', Tiger, { length: 128 }],
  ['Tiger2', Tiger2, { length: 160 }],
  ['Streebog', Streebog, { length: 256 }],
  ['Crc32', Crc32, {}],
  ['XxHash32', XxHash32, { seed: 7 }],
  ['XxHash64', XxHash64, { seed: 7 }],
];

/** Constructor-level checks: the digest of the class with no options, and with explicit own options. */
function observeClasses(withHmac = true) {
  const out = [];
  for (const [name, C] of CLASSES) {
    const h = new C();
    h.update(LONG);
    out.push(name + ' ' + JSON.stringify(h.options) + ' ' + toHex(h.finalize()));
  }
  for (const length of [32, 128, 160, 192, 224, 256, 384, 512]) {
    const h = new Sha512({ length });
    h.update(LONG);
    out.push('Sha512/' + length + ' ' + JSON.stringify(h.getState().hash) + ' ' + toHex(h.finalize()));
  }
  for (const type of ['', '0', 't']) {
    const h = new Whirlpool({ type });
    h.update(LONG);
    out.push('Whirlpool ' + type + ' ' + toHex(h.finalize()));
  }
  // The classes without an original, with no options and with every option of their own.
  for (const [name, C, own] of NEW_OWN) {
    for (const message of [SHORT, LONG, LONG.repeat(40)]) {
      // A spread copy defines the properties; Object.assign would call an inherited setter.
      const h = new C({ ...own });
      h.update(message);
      out.push(name + ' ' + JSON.stringify(h.options) + ' ' + toHex(h.finalize()) + ' ' + JSON.stringify(h.getState()));
    }
    if (withHmac) {
      // Hmac copies the options with Object.assign, which an accessor on the prototype would intercept.
      const m = new Hmac('key', new C({ ...own }));
      m.update(LONG);
      out.push(name + ' hmac ' + toHex(m.finalize()));
    }
  }
  // The caller's object receives the defaults, as in 0.8.5.
  const given = {};
  new Sha256(given);
  out.push(JSON.stringify(given));
  const partial = { rounds: 10 };
  new Sha256(partial);
  out.push(JSON.stringify(partial));
  return out.join('\n');
}

function suite(label, wasm) {
  describe(label, () => {
  before(() => {
    INTERNALS.forEach((i) => i.reset(!wasm));
  });
  after(() => {
    INTERNALS.forEach((i) => i.reset(false));
  });

  test(`${label}: the engine is the one under test`, () => {
    for (const i of INTERNALS) assert.equal(i.runtime() !== null, wasm, 'run `zig build js` first');
  });

  test(`${label}: every getHasher name ignores inherited rounds, length and type`, () => {
    for (const name of NAMES) {
      const clean = observe(name);
      for (const [what, props] of Object.entries(HOSTILE)) {
        const got = polluted(props, () => observe(name));
        assert.equal(got, clean, `${name} with inherited ${what}`);
      }
    }
  });

  test(`${label}: the classes and the options object they fill in are unchanged`, () => {
    const clean = observeClasses();
    for (const [what, props] of Object.entries(HOSTILE)) {
      assert.equal(polluted(props, observeClasses), clean, `inherited ${what}`);
    }
  });

  test(`${label}: a first use under pollution does not poison later hashers`, () => {
    // Whirlpool and Sha512 derive tables / IVs lazily on first use.
    const clean = observeClasses();
    const first = polluted({ rounds: 1, length: 32, type: 't' }, observeClasses);
    assert.equal(first, clean);
    assert.equal(observeClasses(), clean);
  });

  test(`${label}: an inherited setter or read-only value does not intercept the defaults`, () => {
    const clean = observeClasses(false);
    const trap = (key) => {
      const saved = Object.getOwnPropertyDescriptor(Object.prototype, key);
      return {
        install() {
          Object.defineProperty(Object.prototype, key, {
            get() { return 1; },
            set() { throw new Error('setter of inherited ' + key + ' was called'); },
            configurable: true,
          });
        },
        restore() {
          if (saved) Object.defineProperty(Object.prototype, key, saved);
          else delete Object.prototype[key];
        },
      };
    };
    // Not `length`: the original's own state object assigns `state.length`, which an inherited setter would intercept.
    const traps = ['rounds', 'type', 'strength', 'key', 'salt', 'personalization', 'context', 'seed'].map(trap);
    try {
      traps.forEach((t) => t.install());
      assert.equal(observeClasses(false), clean);
    } finally {
      traps.forEach((t) => t.restore());
    }
  });

  test(`${label}: own options are still validated`, () => {
    assert.throws(() => new Sha256({ rounds: 0 }), RangeError);
    assert.throws(() => polluted({ rounds: 5 }, () => new Sha256({ rounds: 99 })), RangeError);
    assert.throws(() => polluted({ length: 224 }, () => new Sha256({ length: 100 })), RangeError);
    assert.throws(() => new Sha256({ rounds: '5' }), TypeError);
    // An own value is honored even when something else is inherited.
    const own = polluted({ rounds: 1 }, () => new Sha256({ rounds: 5 }).options.rounds);
    assert.equal(own, 5);
  });

  test(`${label}: own options of the new classes are validated and win over inherited ones`, () => {
    const hostile = { length: 8, strength: 256, key: 'z'.repeat(32), salt: 'zz', personalization: 'zz', context: 'zz' };
    const bad = [
      [Sha3, { length: 100 }, RangeError], [Keccak, { length: 100 }, RangeError], [Shake, { strength: 192 }, RangeError],
      [Shake, { length: 12 }, RangeError], [Sha3, { length: '256' }, TypeError], [Shake, { strength: '128' }, TypeError],
      [Blake2b, { length: 4 }, RangeError], [Blake2s, { length: 264 }, RangeError], [Blake2b, { key: 'k'.repeat(65) }, RangeError],
      [Blake2s, { salt: 's'.repeat(9) }, RangeError], [Blake2s, { personalization: 5 }, TypeError], [Blake2b, { key: null }, TypeError],
      [Blake3, { length: 12 }, RangeError], [Blake3, { key: 'short' }, RangeError], [Blake3, { context: 5 }, TypeError],
      [Blake3, { key: 'k'.repeat(32), context: 'c' }, TypeError],
      [Tiger, { length: 200 }, RangeError], [Tiger2, { length: '8' }, TypeError], [Streebog, { length: 128 }, RangeError],
      [XxHash32, { seed: 2 ** 32 }, RangeError], [XxHash64, { seed: -1 }, RangeError], [XxHash64, { seed: '1' }, TypeError],
    ];
    for (const [C, options, error] of bad) {
      assert.throws(() => polluted(hostile, () => new C(Object.assign({}, options))), error, JSON.stringify(options));
    }
    // Inherited values do not turn an own option into a conflict either.
    polluted({ key: 'k'.repeat(32), context: 'c' }, () => {
      new Blake3({ context: 'own' });
      new Blake3({ key: 'o'.repeat(32) });
    });
    // Options object with an own `undefined`: the default, not the inherited value.
    const got = polluted({ length: 8, key: 'k'.repeat(32) }, () => {
      const a = new Blake2b({ length: undefined, key: undefined });
      a.update(SHORT);
      const b = new Shake({ length: undefined });
      b.update(SHORT);
      return toHex(a.finalize()) + toHex(b.finalize());
    });
    const a = new Blake2b();
    a.update(SHORT);
    const b = new Shake();
    b.update(SHORT);
    assert.equal(got, toHex(a.finalize()) + toHex(b.finalize()));
  });

  test(`${label}: options of a non-object kind are no options for the sponge hashers`, () => {
    for (const C of [Sha3, Keccak, Shake]) {
      const clean = toHex(new C().finalize());
      for (const given of [undefined, null, 0, 5, true, 'abc', '']) {
        polluted({ length: 8, strength: 256 }, () => {
          assert.equal(toHex(new C(given).finalize()), clean, String(given));
        });
      }
    }
  });

  test(`${label}: an inherited invalid value is not validated and not used`, () => {
    for (const [name, C] of CLASSES) {
      polluted({ rounds: 'x', length: 'y', type: 'z', strength: 'w', key: 5, salt: 5, personalization: 5, context: 5, seed: 'q' }, () => {
        const h = new C();
        h.update(SHORT);
        h.finalize();
      });
      assert.ok(name);
    }
  });

  test(`${label}: Hmac copies keep working with own options only`, () => {
    for (const name of NAMES) {
      const clean = CryptoApi.hmac('key', LONG, CryptoApi.getHasher(name));
      const got = polluted({ rounds: 1, length: 32, type: 't' }, () => {
        const hasher = CryptoApi.getHasher(name);
        const mac = new Hmac('key', hasher);
        mac.update(LONG);
        const first = toHex(mac.finalize());
        return first + ' ' + toHex(mac.finalize());
      });
      assert.equal(got, clean + ' ' + clean, name);
    }
  });
  });
}

suite('wasm', true);
suite('no wasm', false);
