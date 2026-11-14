// Independent oracle: node:crypto (OpenSSL) for the algorithms it implements.
// The original crypto-api and the target must both agree with OpenSSL on random
// messages at every length that matters, and HMAC must match createHmac.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { loadBoth, make } from '../harness/load.mjs';
import { VARIANTS, FAMILIES, boundaryLengths } from '../harness/catalog.mjs';
import { Rng } from '../harness/prng.mjs';

const ITERS = Number(process.env.FUZZ_ITERS ?? 200);
const SEED = Number(process.env.FUZZ_SEED ?? 1);
const bin = (s) => Buffer.from(s, 'latin1');

let apis;
before(async () => { const { oracle, target } = await loadBoth(); apis = [oracle, target]; });

describe('hashes match OpenSSL', () => {
  for (const v of VARIANTS.filter((x) => x.openssl)) {
    const fam = FAMILIES.find((f) => f.id === v.family);
    it(v.id, () => {
      const rng = new Rng(SEED, `openssl-${v.id}`);
      const lengths = [...boundaryLengths(fam.blockBytes, fam.lengthFieldBytes), 1000, 4096];
      for (const api of apis) {
        // every boundary length, once
        const cases = lengths.map((n) => rng.bytes(n));
        for (let i = 0; i < Math.min(ITERS, 200); i++) cases.push(rng.bytes(rng.range(0, 700)));
        for (const msg of cases) {
          const h = make(api, fam, structuredClone(v.options));
          // stream in two random pieces
          const cut = rng.int(msg.length + 1);
          h.update(msg.slice(0, cut));
          h.update(msg.slice(cut));
          const expected = createHash(v.openssl).update(bin(msg)).digest('hex');
          assert.equal(api.toHex(h.finalize()), expected, `${api.label} ${v.id} len=${msg.length}`);
        }
      }
    });
  }

  it('one million "a" (FIPS 180 long-message vector)', () => {
    const million = 'a'.repeat(1_000_000);
    for (const api of apis) {
      for (const v of VARIANTS.filter((x) => x.openssl && /^sha/.test(x.id))) {
        const h = make(api, FAMILIES.find((f) => f.id === v.family), structuredClone(v.options));
        for (let i = 0; i < 1_000_000; i += 10_000) h.update(million.slice(i, i + 10_000));
        assert.equal(api.toHex(h.finalize()), createHash(v.openssl).update(million).digest('hex'), `${api.label} ${v.id}`);
      }
    }
  });
});

describe('HMAC matches OpenSSL', () => {
  const MACS = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ripemd160', 'sm3'];
  for (const id of MACS) {
    const v = VARIANTS.find((x) => x.id === id);
    const fam = FAMILIES.find((f) => f.id === v.family);
    it(`hmac-${id}`, () => {
      const rng = new Rng(SEED, `hmac-openssl-${id}`);
      const keyLens = [0, 1, 20, 63, 64, 65, 127, 128, 129, 200];
      for (const api of apis) {
        for (const kl of keyLens) {
          const key = rng.bytes(kl);
          const msg = rng.bytes(rng.range(0, 300));
          const mac = new api.Hmac(key, make(api, fam, structuredClone(v.options)));
          mac.update(msg);
          assert.equal(api.toHex(mac.finalize()), createHmac(v.openssl, bin(key)).update(bin(msg)).digest('hex'), `${api.label} keylen=${kl}`);
        }
      }
    });
  }
});
