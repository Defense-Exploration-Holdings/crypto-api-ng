// Differential tests for everything that is not a hasher class: Hmac, the four
// encoders, the rotate helpers and the CryptoApi facade (getHasher/hash/hmac/getHmac).
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { loadBoth, make } from '../harness/load.mjs';
import {
  VARIANTS, FAMILIES, GET_HASHER_NAMES, UNKNOWN_HASHER_NAMES,
} from '../harness/catalog.mjs';
import { Rng } from '../harness/prng.mjs';

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
        const run = (api) => {
          const h = make(api, fam(v.family), structuredClone(v.options));
          const m = new api.Hmac(key, h);
          const trace = { stateAfterCtor: JSON.stringify(h.getState()) };
          for (const c of chunks) m.update(c);
          trace.mac = api.toHex(m.finalize());
          trace.mac2 = outcome(() => api.toHex(m.finalize())); // reuse quirk: second finalize
          trace.stateAfter = JSON.stringify(h.getState());
          return trace;
        };
        same(run(oracle), run(target), `${v.id} keylen=${key.length} iteration=${i} seed=${SEED}`);
      }
    });
  }

  it('hostile keys and messages behave the same', () => {
    const keys = [undefined, null, 5, [1, 2], new Uint8Array([1, 2, 3]), { length: 3 }, 'wideĀሴ', ''];
    for (const k of keys) {
      const run = (api) => outcome(() => {
        const m = new api.Hmac(k, new api.hashers.Md5());
        m.update('abc');
        return api.toHex(m.finalize());
      });
      same(run(oracle), run(target), `key ${String(k)}`);
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
      same(outcome(() => oracle.fromUtf(s)), outcome(() => target.fromUtf(s)), JSON.stringify(s));
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

  it('getHasher: every documented name builds the same hasher', () => {
    for (const name of GET_HASHER_NAMES) {
      for (const opts of OPTS) {
        const run = (api) => outcome(() => {
          const arg = opts && structuredClone(opts);
          const h = api.CryptoApi.getHasher(name, arg);
          h.update('abc');
          return { hex: api.toHex(h.finalize()), options: JSON.stringify(h.options), callerOptions: JSON.stringify(arg), cls: h.constructor.name };
        });
        same(run(oracle), run(target), `${name} ${JSON.stringify(opts)}`);
      }
    }
  });

  it('getHasher: unknown names return undefined', () => {
    for (const name of UNKNOWN_HASHER_NAMES) {
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
        same(outcome(() => oracle.CryptoApi.hash(name, t)), outcome(() => target.CryptoApi.hash(name, t)), `${name} ${JSON.stringify(t)}`);
      }
    }
  });

  it('hmac() and getHmac()', () => {
    const rng = new Rng(SEED, 'facade-hmac');
    for (const name of GET_HASHER_NAMES) {
      for (let i = 0; i < 5; i++) {
        const key = rng.wide(rng.range(0, 200));
        const msg = rng.wide(rng.range(0, 200));
        const viaHmac = (api) => outcome(() => api.CryptoApi.hmac(key, msg, api.CryptoApi.getHasher(name)));
        same(viaHmac(oracle), viaHmac(target), `hmac ${name}`);
        const viaGet = (api) => outcome(() => {
          const m = api.CryptoApi.getHmac(api.fromUtf(key), api.CryptoApi.getHasher(name));
          m.update(api.fromUtf(msg));
          return api.toHex(m.finalize());
        });
        same(viaGet(oracle), viaGet(target), `getHmac ${name}`);
      }
    }
  });

  it('exposes the same encoder members', () => {
    same(Object.keys(oracle.CryptoApi.encoder).sort(), Object.keys(target.CryptoApi.encoder).sort());
    same(Object.getOwnPropertyNames(Object.getPrototypeOf(oracle.CryptoApi)).sort(), Object.getOwnPropertyNames(Object.getPrototypeOf(target.CryptoApi)).sort());
  });
});
