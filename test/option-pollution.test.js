// Option values that are only inherited (set on `Object.prototype` by a bug
// elsewhere in the page or process) must never reach a hasher: crypto-api 0.8.5
// read `options.rounds`, `options.length` and `options.type` through the
// prototype chain, so `Object.prototype.rounds = 1` gave a one-round SHA-256.
// Every hasher, `CryptoApi.hash()` and `CryptoApi.hmac()` must return what they
// return on a clean `Object.prototype`, with wasm and with wasm disabled.
// Values that are own properties of the options object keep the behavior of
// 0.8.5 exactly, whatever they are (this is the parity release: no validation).
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';

import CryptoApi from '../packages/crypto-api/src/crypto-api.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { GET_HASHER_NAMES, OPTION_CELLS } from './harness/catalog.mjs';

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

const INTERNALS = [has160, md2, md4, md5, ripemd, sha0, sha1, sha256, sha512, sm3, snefru, whirlpool];
// `sm3` is not a `getHasher` name in 1.0 (as in 0.8.5); the class is covered below.
const NAMES = GET_HASHER_NAMES;

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
];

/** Constructor-level checks: the digest of the class with no options, and with explicit own options. */
function observeClasses() {
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
  // The caller's object receives the defaults, as in 0.8.5.
  const given = {};
  new Sha256(given);
  out.push(JSON.stringify(given));
  const partial = { rounds: 10 };
  new Sha256(partial);
  out.push(JSON.stringify(partial));
  return out.join('\n');
}

/**
 * Own option values of every family, valid, invalid or falsy: result, options object afterwards and
 * thrown error, as strings. Nothing here may depend on what `Object.prototype` holds.
 */
function observeOwnCells() {
  const out = [];
  for (const [name, C] of CLASSES) {
    for (const cell of OPTION_CELLS[name.toLowerCase()] || []) {
      const options = { ...cell };
      let line = name + ' ' + JSON.stringify(cell) + ' ';
      try {
        const h = new C(options);
        h.update(LONG);
        line += toHex(h.finalize()) + ' ' + JSON.stringify(h.options);
      } catch (e) {
        line += 'throws ' + e.name + ': ' + e.message;
      }
      out.push(line + ' ' + JSON.stringify(options));
    }
  }
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
      const clean = observeClasses();
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
      const traps = ['rounds', 'type'].map(trap);
      try {
        traps.forEach((t) => t.install());
        assert.equal(observeClasses(), clean);
      } finally {
        traps.forEach((t) => t.restore());
      }
    });

    test(`${label}: own values, valid or not, behave as in 0.8.5 whatever is inherited`, () => {
      const clean = observeOwnCells();
      for (const [what, props] of Object.entries(HOSTILE)) {
        assert.equal(polluted(props, observeOwnCells), clean, `inherited ${what}`);
      }
    });

    test(`${label}: own values are honored and falsy ones still mean the default`, () => {
      polluted({ rounds: 1 }, () => {
        assert.equal(new Sha256({ rounds: 5 }).options.rounds, 5);
        assert.equal(new Sha256({ rounds: 0 }).options.rounds, 64);
        assert.equal(new Sha256({ rounds: undefined }).options.rounds, 64);
        assert.equal(new Sha1({ rounds: 0 }).options.rounds, 80);
        assert.equal(new Md2({ rounds: 0 }).options.rounds, 18);
      });
      // Out-of-range own values are not rejected in 1.0, as in 0.8.5.
      assert.doesNotThrow(() => new Sha256({ rounds: 99 }));
      assert.doesNotThrow(() => new Sha256({ length: 100 }));
    });

    test(`${label}: an inherited invalid value is not used`, () => {
      for (const [name, C] of CLASSES) {
        const got = polluted({ rounds: 'x', length: 'y', type: 'z' }, () => {
          const h = new C();
          h.update(SHORT);
          return toHex(h.finalize());
        });
        const h = new C();
        h.update(SHORT);
        assert.equal(got, toHex(h.finalize()), name);
      }
    });

    test(`${label}: a non-object options value behaves as in 0.8.5`, () => {
      // The original constructors throw on these (assigning to a primitive in strict mode) or ignore them.
      for (const [name, C] of CLASSES) {
        const outcome = (value) => {
          try {
            const h = new C(value);
            h.update(SHORT);
            return toHex(h.finalize());
          } catch (e) {
            return e.name;
          }
        };
        for (const value of [0, '', null, undefined, false, 5, 'abc', true]) {
          assert.equal(polluted({ rounds: 1, length: 32, type: 't' }, () => outcome(value)), outcome(value), `${name}(${String(value)})`);
        }
      }
    });

    test(`${label}: Hmac gives the same results with inherited options around`, () => {
      // A second `finalize()` of the original Hmac is not a repeat of the first; only compare like with like.
      const run = (name) => {
        const mac = new Hmac('key', CryptoApi.getHasher(name));
        mac.update(LONG);
        const first = toHex(mac.finalize());
        return first + ' ' + toHex(mac.finalize());
      };
      for (const name of NAMES) {
        const clean = run(name);
        assert.equal(polluted({ rounds: 1, length: 32, type: 't' }, () => run(name)), clean, name);
      }
    });
  });
}

suite('wasm', true);
suite('no wasm', false);
