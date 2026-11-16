// Differential tests for everything that is not a hasher class: Hmac, the four
// encoders, the rotate helpers and the CryptoApi facade (getHasher/hash/hmac/getHmac).
// Where 1.1 fixes a 0.8.5 behavior (Hmac reuse, non-string input, sm3, option
// checks) the expected 1.1 result is derived from the original's answer.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { loadBoth, make } from '../harness/load.mjs';
import {
  VARIANTS, FAMILIES, GET_HASHER_NAMES, UNKNOWN_HASHER_NAMES, optionSupported,
} from '../harness/catalog.mjs';
import { Rng } from '../harness/prng.mjs';
import { modelFromUtf } from '../harness/fixes-model.mjs';

const ITERS = Number(process.env.FUZZ_ITERS ?? 200);
const SEED = Number(process.env.FUZZ_SEED ?? 1);

let oracle;
let target;
before(async () => ({ oracle, target } = await loadBoth()));

const outcome = (fn) => {
  try { return { ok: fn() }; } catch (e) { return { err: `${e?.constructor?.name}: ${e?.message}` }; }
};
const same = (a, b, ctx) => assert.deepStrictEqual(b, a, ctx);
const fam = (id) => FAMILIES.find((f) => f.id === id);

// ---------------------------------------------------------------------------
describe('Hmac', () => {
  const KEY_LENS = [0, 1, 16, 63, 64, 65, 127, 128, 129, 200];
  for (const v of VARIANTS) {
    it(`hmac over ${v.id}`, () => {
      const rng = new Rng(SEED, `hmac-${v.id}`);
      for (let i = 0; i < Math.max(10, ITERS / 4); i++) {
        const key = rng.bytes(rng.chance(0.5) ? rng.pick(KEY_LENS) : rng.range(0, 260));
        const chunks = [rng.bytes(rng.range(0, 150)), rng.bytes(rng.range(0, 150))];
        const extra = rng.bytes(rng.range(0, 150));
        // 0.8.5: the first finalize() is correct, everything after it is not.
        const macOf = (api, message) => {
          const m = new api.Hmac(key, make(api, fam(v.family), structuredClone(v.options)));
          m.update(message);
          return api.toHex(m.finalize());
        };
        const fresh = JSON.stringify(make(oracle, fam(v.family), structuredClone(v.options)).getState());
        const expected = {
          stateAfterCtor: fresh,
          mac: macOf(oracle, chunks.join('')),
          mac2: { ok: macOf(oracle, chunks.join('')) },
          macMore: macOf(oracle, chunks.join('') + extra),
          macReset: macOf(oracle, extra),
          stateAfter: fresh,
        };
        const h = make(target, fam(v.family), structuredClone(v.options));
        const m = new target.Hmac(key, h);
        const got = { stateAfterCtor: JSON.stringify(h.getState()) };
        for (const c of chunks) m.update(c);
        got.mac = target.toHex(m.finalize());
        got.mac2 = outcome(() => target.toHex(m.finalize())); // 1.1: finalize() is repeatable
        m.update(extra); // ... and does not end the message
        got.macMore = target.toHex(m.finalize());
        m.reset();
        m.update(extra);
        got.macReset = target.toHex(m.finalize());
        got.stateAfter = JSON.stringify(h.getState()); // 1.1: the hasher passed in is not touched
        same(expected, got, `${v.id} keylen=${key.length} iteration=${i} seed=${SEED}`);
      }
    });
  }

  it('keys: bytes are accepted, other non-strings and wide strings throw TypeError (1.1)', () => {
    const run = (api, k) => outcome(() => {
      const m = new api.Hmac(k, new api.hashers.Md5());
      m.update('abc');
      return api.toHex(m.finalize());
    });
    for (const k of [undefined, null, 5, [1, 2], { length: 3 }, 'wideĀሴ']) {
      assert.match(run(target, k).err ?? '', /^TypeError: /, `key ${String(k)}`);
    }
    same(run(oracle, '\x01\x02\x03'), run(target, new Uint8Array([1, 2, 3])), 'Uint8Array key');
    same(run(oracle, '\x01\x02\x03'), run(target, Uint8Array.from([1, 2, 3]).buffer), 'ArrayBuffer key');
    same(run(oracle, ''), run(target, ''), 'empty key');
    for (const msg of [5, null, 'Ā']) {
      const m = new target.Hmac('key', new target.hashers.Md5());
      assert.throws(() => m.update(msg), TypeError, `message ${String(msg)}`);
    }
  });

  it('works with a user-written hasher (Hmac is generic)', () => {
    const make1 = (api) => {
      class XorSum extends api.bases.Hasher {
        constructor(o) { super(o); this.blockSizeInBytes = 8; }
        finalize() { let s = 0; for (const c of this.state.message) s = (s * 31 + c.charCodeAt(0)) | 0; return String.fromCharCode(s & 255, (s >> 8) & 255); }
      }
      const m = new api.Hmac('key', new XorSum());
      m.update('hello');
      return api.toHex(m.finalize());
    };
    same(outcome(() => make1(oracle)), outcome(() => make1(target)));
  });
});

// ---------------------------------------------------------------------------
describe('encoders', () => {
  const astral = ['\u{1F600}', '\u{10FFFF}', '\u{10000}'];
  const lone = ['\ud800', '\udc00', '\udbff', '\udfff'];
  const randomText = (rng) => {
    let s = '';
    for (let i = rng.range(0, 40); i > 0; i--) {
      const r = rng.int(10);
      s += r === 0 ? rng.pick(astral) : r === 1 ? rng.pick(lone) : r < 5 ? String.fromCharCode(rng.int(0x80))
        : r < 7 ? String.fromCharCode(0x80 + rng.int(0x780)) : String.fromCharCode(rng.int(0x10000));
    }
    return s;
  };

  it('fromUtf', () => {
    const rng = new Rng(SEED, 'utf');
    const fixed = ['', '\0', 'a', 'é', '€', '\u{1F600}', 'a\ud800', '\udc00a', '\ud800\ud800', '􏿿', '\u007f\u0080߿ࠀ￿'];
    for (const s of [...fixed, ...Array.from({ length: ITERS * 5 }, () => randomText(rng))]) {
      // 1.1 encodes a surrogate that is not part of a valid pair as U+FFFD (fixes model);
      // text without one must still equal the original byte for byte.
      same({ ok: modelFromUtf(s) }, outcome(() => target.fromUtf(s)), JSON.stringify(s));
      if (s.isWellFormed()) same(outcome(() => oracle.fromUtf(s)), outcome(() => target.fromUtf(s)), JSON.stringify(s));
    }
    for (const bad of [undefined, null, 5, {}, [], ['a']]) {
      same(outcome(() => oracle.fromUtf(bad)), outcome(() => target.fromUtf(bad)), String(bad));
    }
  });

  it('toHex and toBase64 (including code units above 0xFF)', () => {
    const rng = new Rng(SEED, 'hexb64');
    const inputs = ['', 'a', 'Ā', 'Āÿ', '￿', '\0\0\0', 'ab', 'abc', 'abcd'];
    for (let i = 0; i < ITERS * 3; i++) inputs.push(rng.chance(0.2) ? rng.wide(rng.range(0, 30)) : rng.bytes(rng.range(0, 90)));
    for (const s of inputs) {
      same(outcome(() => oracle.toHex(s)), outcome(() => target.toHex(s)), `toHex ${JSON.stringify(s)}`);
      same(outcome(() => oracle.toBase64(s)), outcome(() => target.toBase64(s)), `toBase64 ${JSON.stringify(s)}`);
    }
    for (const bad of [undefined, null, 5, [], {}]) {
      same(outcome(() => oracle.toHex(bad)), outcome(() => target.toHex(bad)), `toHex ${String(bad)}`);
      same(outcome(() => oracle.toBase64(bad)), outcome(() => target.toBase64(bad)), `toBase64 ${String(bad)}`);
    }
  });

  it('fromArrayBuffer', () => {
    const rng = new Rng(SEED, 'ab');
    const inputs = [];
    for (let i = 0; i < 60; i++) {
      const bytes = Array.from({ length: rng.range(0, 40) }, () => rng.int(256));
      inputs.push(() => Uint8Array.from(bytes).buffer);
      inputs.push(() => Uint8Array.from(bytes));
      inputs.push(() => Uint16Array.from(bytes.map((b) => b * 257)));
      inputs.push(() => Int8Array.from(bytes));
      inputs.push(() => Float32Array.from(bytes));
      inputs.push(() => [...bytes]);
      inputs.push(() => bytes.map((b) => b + 256 * rng.int(3)));
      inputs.push(() => new DataView(Uint8Array.from(bytes).buffer));
    }
    inputs.push(() => 'abc', () => undefined, () => null, () => 7, () => ({}), () => ({ length: 2, 0: 5, 1: 300 }));
    for (const make1 of inputs) {
      same(outcome(() => oracle.fromArrayBuffer(make1())), outcome(() => target.fromArrayBuffer(make1())));
    }
  });
});

// ---------------------------------------------------------------------------
describe('tools', () => {
  it('rotate helpers', () => {
    const rng = new Rng(SEED, 'tools');
    const nums = [0, 1, -1, 0x7fffffff, -0x80000000, 0xffffffff, 0x80000000, 1.5, NaN, 2 ** 40];
    for (let i = 0; i < ITERS * 3; i++) nums.push(rng.next() | 0);
    for (const fn of ['rotateLeft', 'rotateRight']) {
      for (const x of nums) {
        for (const n of [0, 1, 7, 16, 31, 32, 33, -1, 64]) {
          same(outcome(() => oracle.tools[fn](x, n)), outcome(() => target.tools[fn](x, n)), `${fn}(${x},${n})`);
        }
      }
    }
    for (const fn of ['rotateRight64hi', 'rotateRight64lo']) {
      for (let i = 0; i < ITERS * 3; i++) {
        const hi = rng.next() | 0; const lo = rng.next() | 0; const n = rng.range(0, 70);
        same(outcome(() => oracle.tools[fn](hi, lo, n)), outcome(() => target.tools[fn](hi, lo, n)), `${fn}(${hi},${lo},${n})`);
      }
    }
  });
});

// ---------------------------------------------------------------------------
describe('CryptoApi facade', () => {
  const OPTS = [undefined, {}, { rounds: 3 }, { length: 224 }, { type: 't' }, { rounds: 80, length: 160 }];

  it('getHasher: every documented name builds the same hasher, or rejects unsupported options (1.1)', () => {
    let rejected = 0;
    for (const name of GET_HASHER_NAMES) {
      for (const opts of OPTS) {
        const run = (api) => outcome(() => {
          const arg = opts && structuredClone(opts);
          const h = api.CryptoApi.getHasher(name, arg);
          h.update('abc');
          return { hex: api.toHex(h.finalize()), options: JSON.stringify(h.options), callerOptions: JSON.stringify(arg), cls: h.constructor.name };
        });
        const expected = run(oracle);
        if (expected.err) {
          // The original fails on these options too (e.g. Snefru rounds 80); 1.1 fails at construction.
          assert.match(run(target).err ?? '', /^(RangeError|TypeError): /, `${name} ${JSON.stringify(opts)}`);
          continue;
        }
        const familyOf = FAMILIES.find((f) => f.className === expected.ok.cls);
        if (optionSupported(familyOf.id, JSON.parse(expected.ok.options))) {
          same(expected, run(target), `${name} ${JSON.stringify(opts)}`);
        } else {
          rejected++;
          assert.match(run(target).err ?? '', /^(RangeError|TypeError): /, `${name} ${JSON.stringify(opts)}`);
        }
      }
    }
    assert.ok(rejected > 0);
  });

  it('getHasher: sm3 (1.1)', () => {
    const h = target.CryptoApi.getHasher('sm3');
    assert.ok(h instanceof target.hashers.Sm3);
    const o = new oracle.hashers.Sm3();
    for (const x of [h, o]) x.update('abc');
    same(oracle.toHex(o.finalize()), target.toHex(h.finalize()));
    const r = target.CryptoApi.getHasher('sm3', { rounds: 32 });
    assert.equal(r.options.rounds, 32);
  });

  it('getHasher: unknown names return undefined', () => {
    for (const name of UNKNOWN_HASHER_NAMES.filter((n) => n !== 'sm3')) {
      same(outcome(() => oracle.CryptoApi.getHasher(name)), outcome(() => target.CryptoApi.getHasher(name)), name);
    }
    for (const bad of [undefined, null, 5, {}]) {
      same(outcome(() => oracle.CryptoApi.getHasher(bad)), outcome(() => target.CryptoApi.getHasher(bad)), String(bad));
    }
  });

  it('hash(): every name, UTF-8 text including astral and lone surrogates', () => {
    const rng = new Rng(SEED, 'facade-hash');
    const texts = ['', 'abc', 'Привет', '€uro', '\u{1F600}', 'a\ud800', '\0'];
    for (let i = 0; i < 20; i++) texts.push(rng.wide(rng.range(0, 100)));
    for (const name of [...GET_HASHER_NAMES, ...UNKNOWN_HASHER_NAMES]) {
      for (const t of texts) {
        // The original's hash() would use its own fromUtf; 1.1 differs for lone surrogates only.
        const expected = outcome(() => {
          const h = name === 'sm3' ? new oracle.hashers.Sm3() : oracle.CryptoApi.getHasher(name);
          h.update(modelFromUtf(t));
          return oracle.toHex(h.finalize());
        });
        same(expected, outcome(() => target.CryptoApi.hash(name, t)), `${name} ${JSON.stringify(t)}`);
      }
    }
    // 1.1: bytes are hashed as they are, not UTF-8 encoded.
    same(oracle.CryptoApi.hash('sha256', 'abc'), target.CryptoApi.hash('sha256', new Uint8Array([97, 98, 99])));
    assert.throws(() => target.CryptoApi.hash('sha256', 5), TypeError);
  });

  it('hmac() and getHmac()', () => {
    const rng = new Rng(SEED, 'facade-hmac');
    for (const name of GET_HASHER_NAMES) {
      for (let i = 0; i < 5; i++) {
        const key = rng.wide(rng.range(0, 200));
        const msg = rng.wide(rng.range(0, 200));
        const utf = (api, t) => (api === oracle ? modelFromUtf(t) : api.fromUtf(t));
        const viaHmac = (api) => outcome(() => {
          if (api === target) return api.CryptoApi.hmac(key, msg, api.CryptoApi.getHasher(name));
          // The original's hmac() would use its own fromUtf; 1.1 differs for lone surrogates only.
          const m = api.CryptoApi.getHmac(utf(api, key), api.CryptoApi.getHasher(name));
          m.update(utf(api, msg));
          return api.toHex(m.finalize());
        });
        same(viaHmac(oracle), viaHmac(target), `hmac ${name}`);
        const viaGet = (api) => outcome(() => {
          const m = api.CryptoApi.getHmac(utf(api, key), api.CryptoApi.getHasher(name));
          m.update(utf(api, msg));
          return api.toHex(m.finalize());
        });
        same(viaGet(oracle), viaGet(target), `getHmac ${name}`);
      }
    }
  });

  it('exposes the same encoder members', () => {
    // Members that crypto-api-ng added on top of 0.8.5 (documented in the CHANGELOG); nothing else may differ.
    const ADDED_ENCODERS = ['base64ToBytes', 'bytesToBase64', 'bytesToHex', 'bytesToUtf8', 'hexToBytes', 'utf8ToBytes'];
    same(Object.keys(oracle.CryptoApi.encoder).sort(), Object.keys(target.CryptoApi.encoder).filter((n) => !ADDED_ENCODERS.includes(n)).sort());
    const ADDED = ['hashBytes', 'hkdf', 'hkdfBytes', 'hmacBytes', 'pbkdf2', 'pbkdf2Bytes'];
    same(Object.getOwnPropertyNames(Object.getPrototypeOf(oracle.CryptoApi)).sort(),
      Object.getOwnPropertyNames(Object.getPrototypeOf(target.CryptoApi)).filter((n) => !ADDED.includes(n)).sort());
  });
});
