// Published test vectors (extracted from the original suite into test/vectors/)
// must hold for BOTH the oracle and the target, in one update() call, in
// byte-by-byte streaming, and in a getState()/setState() round trip.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadBoth, make } from '../harness/load.mjs';
import { VARIANTS, HMAC_VARIANTS, FAMILIES } from '../harness/catalog.mjs';
import { VECTORS_DIR } from '../harness/paths.mjs';

const readVectors = (name) => JSON.parse(readFileSync(join(VECTORS_DIR, `${name}.json`), 'utf8'));
const family = (id) => FAMILIES.find((f) => f.id === id);

let apis;
before(async () => { const { oracle, target } = await loadBoth(); apis = [oracle, target]; });

describe('hash vectors', () => {
  for (const v of VARIANTS) {
    const vectors = readVectors(v.id);
    it(`${v.id}: ${vectors.length} vectors`, () => {
      assert.ok(vectors.length > 0);
      for (const api of apis) {
        for (const vec of vectors) {
          const ctx = `${api.label} ${vec.name}`;
          // sanity: inputHex really is the bytes of input
          assert.equal(api.toHex(vec.input), vec.inputHex, ctx);

          const whole = make(api, family(v.family), structuredClone(v.options));
          whole.update(vec.input);
          assert.equal(api.toHex(whole.finalize()), vec.hex, `${ctx} (single update)`);

          const bytewise = make(api, family(v.family), structuredClone(v.options));
          for (const ch of vec.input) bytewise.update(ch);
          assert.equal(api.toHex(bytewise.finalize()), vec.hex, `${ctx} (byte-wise)`);

          // state round trip at every split point of the first 130 bytes
          const half = Math.min(vec.input.length, 130);
          for (let cut = 0; cut <= half; cut += 7) {
            const a = make(api, family(v.family), structuredClone(v.options));
            a.update(vec.input.slice(0, cut));
            const state = a.getState();
            const b = make(api, family(v.family), structuredClone(v.options));
            b.setState(state);
            b.update(vec.input.slice(cut));
            assert.equal(api.toHex(b.finalize()), vec.hex, `${ctx} (state at ${cut})`);
          }
        }
      }
    });
  }
});

describe('HMAC vectors', () => {
  for (const id of HMAC_VARIANTS) {
    const v = VARIANTS.find((x) => x.id === id);
    const vectors = readVectors(`hmac-${id}`);
    it(`hmac-${id}: ${vectors.length} vectors`, () => {
      assert.equal(vectors.length, 7);
      for (const api of apis) {
        for (const vec of vectors) {
          const mac = new api.Hmac(vec.key, make(api, family(v.family), structuredClone(v.options)));
          mac.update(vec.input);
          assert.equal(api.toHex(mac.finalize()), vec.hex, `${api.label} ${vec.name}`);
        }
      }
    });
  }
});

describe('vector files', () => {
  it('cover all 238 hash and HMAC cases of the original suite', () => {
    let n = 0;
    for (const v of VARIANTS) n += readVectors(v.id).length;
    for (const id of HMAC_VARIANTS) n += readVectors(`hmac-${id}`).length;
    assert.equal(n, 238);
  });
});
