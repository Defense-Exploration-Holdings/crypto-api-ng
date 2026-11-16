// Executable form of the documented quirks of crypto-api 0.8.5.
// 1. The oracle must still give the pinned answer (the claim is true).
// 2. The target must give the same answer (the quirk is kept), except for the
//    quirks 1.1 fixes, where it must give the 1.1 answer instead, and the
//    documented v1 divergences, where the listed alternative is also accepted.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { loadBoth, make } from '../harness/load.mjs';
import { fixesModel } from '../harness/fixes-model.mjs';
import { QUIRK_PROBES } from '../harness/quirks.mjs';
import { FAMILIES, VARIANTS } from '../harness/catalog.mjs';

const PINNED = {
  'wide characters hash to neither UTF-8 nor Latin-1': { got: '96489126c82d49521b9bb2a2b4ef9a8f684ce3e63e2b330f339f5a5c61f26d92', isUtf8: false, isLatin1: false },
  'update(Uint8Array) hashes the text "1,2" and counts 2': { message: '1,2', length: 2 },
  'sha256 rounds 80 runs on undefined constants': 'e321909e6921aa381045c0124c3939887206c271301fd42af86100bddecd82e9',
  'snefru rounds 9 throws TypeError': '!TypeError',
  'whirlpool type 0 equals plain whirlpool': { same: true },
  'sha512 rounds 159 equals default': { same: true },
  'sha256 length 160 is a 5-word digest': 40,
  'getHasher(sm3) and getHasher(SHA256) are undefined': { sm3: true, upper: true },
  'hash() of an unknown name throws TypeError': '!TypeError',
  'hmac-md5 second finalize differs, first is correct': { first: '80070713463e7749b90c2dc24911e275', differs: true },
  'new Hmac(key, md5) leaves 64 bytes in the hasher': 64,
  'md2 starts with 48 null hash words': { hash: 48, checksum: 16 },
  'has160 IV is unsigned until the first block, signed after': {
    before: [1732584193, 4023233417, 2562383102, 271733878, 3285377520], afterHasNegative: true,
  },
  'ripemd IV is unsigned until the first block': [1732584193, 4023233417, 2562383102, 271733878, 3285377520],
  'state.length high bits are dropped (2**29 vs 2**29 + 2**32)': { same: true },
  'constructor writes defaults into the caller options': { sha256: { length: 256, rounds: 64 }, whirlpool: { type: '', rounds: 10 } },
  'fromUtf of a lone high surrogate is invalid UTF-8': '61f0908080',
  'toHex of a wide character is not two digits': '100',
  'ripemd has an own processBlock property': true,
  'setState keeps a live reference in the original': { live: true },
};

/** Quirks fixed in 1.1: the only answer the target may give. */
const FIXED_ANSWERS = {
  'wide characters hash to neither UTF-8 nor Latin-1': '!TypeError',
  'update(Uint8Array) hashes the text "1,2" and counts 2': { message: '\x01\x02', length: 2 },
  'sha256 rounds 80 runs on undefined constants': '!RangeError',
  'snefru rounds 9 throws TypeError': '!RangeError',
  'sha256 length 160 is a 5-word digest': '!RangeError',
  'getHasher(sm3) and getHasher(SHA256) are undefined': { sm3: false, upper: true },
  'hmac-md5 second finalize differs, first is correct': { first: '80070713463e7749b90c2dc24911e275', differs: false },
  'new Hmac(key, md5) leaves 64 bytes in the hasher': 0,
  'fromUtf of a lone high surrogate is invalid UTF-8': '61efbfbd',
  'state.length high bits are dropped (2**29 vs 2**29 + 2**32)': { same: false },
};

const out = (fn) => { try { return fn(); } catch (e) { return `!${e.constructor.name}`; } };

/** Documented v1 divergences: extra answers the target may give. */
const DIVERGENCES = {
  'setState keeps a live reference in the original': [{ live: false }],
};

let oracle;
let target;
before(async () => ({ oracle, target } = await loadBoth()));

describe('verified quirks of crypto-api 0.8.5', () => {
  for (const name of Object.keys(QUIRK_PROBES)) {
    it(name, () => {
      assert.ok(name in PINNED, 'probe has no pinned answer');
      assert.deepStrictEqual(QUIRK_PROBES[name](oracle), PINNED[name], 'the oracle no longer behaves as documented');
      const got = out(() => QUIRK_PROBES[name](target));
      const allowed = name in FIXED_ANSWERS ? [FIXED_ANSWERS[name]] : [PINNED[name], ...(DIVERGENCES[name] ?? [])];
      assert.ok(allowed.some((a) => JSON.stringify(a) === JSON.stringify(got)), `target answered ${JSON.stringify(got)}, allowed ${JSON.stringify(allowed)}`);
    });
  }

  it('hmac-md5 first finalize equals node:crypto', () => {
    for (const api of [oracle, target]) {
      const m = new api.Hmac('key', new api.hashers.Md5());
      m.update('The quick brown fox jumps over the lazy dog');
      assert.equal(api.toHex(m.finalize()), createHmac('md5', 'key').update('The quick brown fox jumps over the lazy dog').digest('hex'));
    }
  });
});

describe('64-bit length field (the 2 GiB bug of 0.8.5 is fixed in 1.1)', () => {
  // Real 2 GiB inputs are impractical, so state.length is set directly: the
  // padding code reads it exactly as it would after that many bytes. Below
  // 2^31 the target equals the original; everywhere it equals the fixes model,
  // whose length field is computed with BigInt (test/harness/fixes-model.mjs).
  const LENGTHS = [0, 1, 2 ** 28, 2 ** 29 - 1, 2 ** 29, 2 ** 29 + 1, 2 ** 31 - 1, 2 ** 31, 2 ** 31 + 5, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 3, 2 ** 33 + 77, 2 ** 40 + 1, 2 ** 53 - 1, -1, 1.5];
  for (const v of VARIANTS) {
    it(v.id, () => {
      const fam = FAMILIES.find((f) => f.id === v.family);
      const run = (api, len, msg) => {
        const h = make(api, fam, structuredClone(v.options));
        h.update(msg);
        h.state.length = len;
        try { return api.toHex(h.finalize()); } catch (e) { return `!${e.constructor.name}`; }
      };
      const model = fixesModel(oracle);
      let fixed = 0;
      for (const len of LENGTHS) {
        for (const msg of ['', 'abc', 'x'.repeat(63), 'y'.repeat(130)]) {
          const got = run(target, len, msg);
          assert.equal(got, run(model, len, msg), `length=${len} msg.length=${msg.length}`);
          if (len >= 0 && len < 2 ** 31) assert.equal(got, run(oracle, len, msg), `length=${len} msg.length=${msg.length} (below 2^31)`);
          else if (Number.isInteger(len) && len > 0 && got !== run(oracle, len, msg)) fixed++;
        }
      }
      // MD2 has no length field.
      if (fam.lengthFieldBytes > 0 || fam.id === 'snefru') assert.ok(fixed > 0, 'the 2 GiB fix changes some digests');
    });
  }
});

describe('direct use of .state', () => {
  it('reads and writes through h.state behave like plain properties', () => {
    for (const v of VARIANTS) {
      const fam = FAMILIES.find((f) => f.id === v.family);
      const run = (api) => {
        const h = make(api, fam, structuredClone(v.options));
        h.update('hello world, this is a test of direct state access');
        const seen = JSON.stringify(h.state);
        h.state.message += 'extra';
        h.state.length += 5;
        h.update('tail');
        const replaced = h.getState();
        replaced.length += 1;
        h.state = replaced;
        h.update('more');
        return { seen, digest: api.toHex(h.finalize()) };
      };
      assert.deepStrictEqual(run(target), run(oracle), v.id);
    }
  });
});
