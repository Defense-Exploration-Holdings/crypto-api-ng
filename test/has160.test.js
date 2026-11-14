// HAS-160 facade tests: wasm-accelerated Has160 vs the untouched crypto-api 0.8.5 class.
// The shared checklist lives in support/le32-suite.js; this file adds `rounds`.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import Has160, { _internal } from '../packages/crypto-api/src/hasher/has160.mjs';
import LegacyHas160 from '../packages/crypto-api/legacy/hasher/has160.mjs';
import { defineSuite, rng, binString, hex, json, attempt } from './support/le32-suite.js';

const base = { Facade: Has160, Legacy: LegacyHas160, internal: _internal, words: 5, replacesHash: false };

const kit = defineSuite({ ...base, name: 'has160', vectors: 'has160', hmacVectors: 'hmac-has160' });
for (const rounds of [1, 20, 33, 79]) {
  defineSuite({ ...base, name: `has160 rounds=${rounds}`, options: { rounds } });
}

const wasmUsed = kit.wasmUsed;

test('has160: the first words are unsigned until the first block is processed (original quirk)', () => {
  const a = new Has160();
  const b = new LegacyHas160();
  assert.equal(json(a), json(b));
  assert.equal(JSON.parse(json(a)).hash[1], 0xefcdab89);
  a.update('x'.repeat(63));
  b.update('x'.repeat(63));
  assert.equal(json(a), json(b));
  a.update('y');
  b.update('y');
  assert.equal(json(a), json(b));
  assert.ok(JSON.parse(json(a)).hash.every((w) => w >= -(2 ** 31) && w < 2 ** 31), 'int32 after the first block');
});

test('has160: every rounds value 0..80 (set through options) matches the original, one wasm call', () => {
  const msg = 'The quick brown fox jumps over the lazy dog'.repeat(4);
  for (let rounds = 0; rounds <= 80; rounds++) {
    const a = new Has160();
    const b = new LegacyHas160();
    a.options.rounds = rounds;
    b.options.rounds = rounds;
    a.update(msg);
    b.update(msg);
    const used = wasmUsed(() => assert.equal(hex(a), hex(b), `rounds ${rounds}`));
    assert.equal(used, 1, `rounds ${rounds} runs in wasm`);
    assert.equal(json(a), json(b), `rounds ${rounds}`);
  }
});

test('has160: rounds outside 0..80 or not an integer is the original code', () => {
  const odd = [81, 100, 1000, -1, -80, 1.5, 79.9, 80.1, NaN, -Infinity, '20', '80', ' 5', true, false, null, undefined, [], {}, [3], 1e5];
  // Infinity (and anything that large) makes the original loop for ever, so it is not probed.
  for (const rounds of odd) {
    for (const via of ['ctor', 'mutate']) {
      const mk = (Class) => {
        if (via === 'ctor') return new Class({ rounds });
        const h = new Class();
        h.options.rounds = rounds;
        return h;
      };
      const a = mk(Has160);
      const b = mk(LegacyHas160);
      const steps = [(h) => h.update('abc'), (h) => h.update('d'.repeat(130)), (h) => h.getState(), (h) => hex(h), (h) => h.getState()];
      steps.forEach((step, i) => {
        assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `rounds ${String(rounds)} (${via}) step ${i}`);
      });
    }
  }
});

test('has160: rounds is read at every call, like the original', () => {
  const a = new Has160();
  const b = new LegacyHas160();
  for (const h of [a, b]) {
    h.update('a'.repeat(64));
    h.options.rounds = 40;
    h.update('b'.repeat(64));
    h.options.rounds = 80;
    h.update('c'.repeat(100));
    h.options = { rounds: 7 };
  }
  assert.equal(json(a), json(b));
  assert.equal(hex(a), hex(b));
});

test('has160: options that are not an object', () => {
  for (const options of [null, undefined, 5, 'x', true]) {
    const a = new Has160();
    const b = new LegacyHas160();
    a.update('a'.repeat(10));
    b.update('a'.repeat(10));
    a.options = options;
    b.options = options;
    const ra = attempt(() => { a.update('b'.repeat(120)); return hex(a); });
    const rb = attempt(() => { b.update('b'.repeat(120)); return hex(b); });
    assert.deepEqual(ra, rb, `options ${String(options)}`);
  }
});

test('has160: the options object is updated like the original (rounds default filled in)', () => {
  const oa = {};
  const ob = {};
  new Has160(oa);
  new LegacyHas160(ob);
  assert.deepEqual(oa, ob);
  assert.equal(oa.rounds, 80);
});

test('has160: random rounds with random splits', () => {
  const rand = rng(11);
  for (let it = 0; it < 100; it++) {
    const rounds = 1 + ((rand() * 80) | 0);
    const a = new Has160({ rounds });
    const b = new LegacyHas160({ rounds });
    const msg = binString(rand, (rand() * 400) | 0);
    for (let pos = 0; pos < msg.length;) {
      const n = (rand() * 90) | 0;
      a.update(msg.substr(pos, n));
      b.update(msg.substr(pos, n));
      pos += n;
    }
    assert.equal(hex(a), hex(b), `rounds ${rounds}`);
    assert.equal(json(a), json(b));
  }
});
