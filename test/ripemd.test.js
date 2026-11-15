// RIPEMD facade tests: wasm-accelerated Ripemd (128/160/256/320) vs the
// untouched crypto-api 0.8.5 class. The shared checklist lives in
// support/le32-suite.js; this file adds the `length` option handling.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import Ripemd, { _internal } from '../packages/crypto-api/src/hasher/ripemd.mjs';
import LegacyRipemd from '../packages/crypto-api/legacy/hasher/ripemd.mjs';
import { defineSuite, rng, binString, hex, json, attempt } from './support/le32-suite.js';

const base = { Facade: Ripemd, Legacy: LegacyRipemd, internal: _internal, replacesHash: false, shadowedProcessBlock: true };

defineSuite({ ...base, name: 'ripemd128', options: { length: 128 }, words: 4, vectors: 'ripemd128' });
defineSuite({ ...base, name: 'ripemd160', options: { length: 160 }, words: 5, vectors: 'ripemd160', node: 'ripemd160' });
defineSuite({ ...base, name: 'ripemd256', options: { length: 256 }, words: 8, vectors: 'ripemd256' });
defineSuite({ ...base, name: 'ripemd320', options: { length: 320 }, words: 10, vectors: 'ripemd320' });
defineSuite({ ...base, name: 'ripemd (no options)', words: 5 });

const wasmUsed = (fn) => {
  const before = _internal.wasmCalls();
  fn();
  return _internal.wasmCalls() - before;
};

test('ripemd: unlisted or odd `length` options throw at construction (v2)', () => {
  for (const length of [0, 100, 129, 512, 161, -128, 1.5, NaN, Infinity]) assert.throws(() => new Ripemd({ length }), RangeError, String(length));
  for (const length of ['128', '160', ' 320', true, null, [], [128], {}, 320n]) assert.throws(() => new Ripemd({ length }), TypeError, String(length));
});

test('ripemd: listed `length` options and undefined behave exactly like the original', () => {
  for (const length of [128, 160, 256, 320, 128.0, undefined]) {
    const mk = (Class) => {
      try {
        return new Class({ length });
      } catch (e) {
        return `${e.constructor.name}: ${e.message}`;
      }
    };
    const a = mk(Ripemd);
    const b = mk(LegacyRipemd);
    if (typeof a === 'string' || typeof b === 'string') {
      assert.equal(a, b, `ctor length ${String(length)}`);
      continue;
    }
    const steps = [(h) => h.getState(), (h) => h.update('abc'), (h) => h.update('d'.repeat(130)), (h) => h.getState(), (h) => hex(h), (h) => h.getState(), (h) => h.options];
    steps.forEach((step, i) => {
      assert.deepEqual(attempt(() => step(a)), attempt(() => step(b)), `length ${String(length)} step ${i}`);
    });
  }
});

test('ripemd: `length` set to a string after construction still works through the original reset(), and is accelerated', () => {
  const a = new Ripemd({ length: 160 });
  assert.equal(wasmUsed(() => { a.update('x'.repeat(100)); a.finalize(); }), 2);
  const b = new Ripemd();
  b.options.length = '256'; // not === 256: the original falls to the 160 branch
  b.reset();
  assert.equal(b.getState().hash.length, 5);
  assert.equal(wasmUsed(() => { b.update('x'.repeat(100)); b.finalize(); }), 2);
});

test('ripemd: changing options.length after construction does nothing until reset(), like the original', () => {
  for (const [from, to] of [[160, 128], [128, 320], [256, 160], [320, 256]]) {
    const a = new Ripemd({ length: from });
    const b = new LegacyRipemd({ length: from });
    for (const h of [a, b]) {
      h.update('p'.repeat(70));
      h.options.length = to;
      h.update('q'.repeat(70));
    }
    assert.equal(json(a), json(b), `${from} -> ${to} before reset`);
    assert.equal(hex(a), hex(b));
    for (const h of [a, b]) {
      h.reset();
      h.update('r'.repeat(150));
    }
    assert.equal(json(a), json(b), `${from} -> ${to} after reset`);
    assert.equal(hex(a), hex(b));
    assert.equal(a.getState().hash.length, b.getState().hash.length);
  }
});

test('ripemd: processBlock chosen from the wrong variant (state/function mismatch) is the original code', () => {
  const names = ['processBlock128', 'processBlock160', 'processBlock256', 'processBlock320'];
  const lengths = [128, 160, 256, 320];
  for (const length of lengths) {
    for (const name of names) {
      const a = new Ripemd({ length });
      const b = new LegacyRipemd({ length });
      a.processBlock = a[name];
      b.processBlock = b[name];
      const ra = attempt(() => { a.update('m'.repeat(200)); return hex(a); });
      const rb = attempt(() => { b.update('m'.repeat(200)); return hex(b); });
      assert.deepEqual(ra, rb, `${length} state with ${name}`);
      assert.equal(attempt(() => json(a)).value, attempt(() => json(b)).value, `${length} with ${name} state`);
    }
  }
});

test('ripemd: overriding a processBlockNNN on a subclass is honored', () => {
  for (const [length, name] of [[128, 'processBlock128'], [160, 'processBlock160'], [256, 'processBlock256'], [320, 'processBlock320']]) {
    const seenA = [];
    const seenB = [];
    class F extends Ripemd {
      [name](block) { seenA.push(block[0]); return super[name](block); }
    }
    class L extends LegacyRipemd {
      [name](block) { seenB.push(block[0]); return super[name](block); }
    }
    const a = new F({ length });
    const b = new L({ length });
    assert.equal(wasmUsed(() => {
      a.update('s'.repeat(300));
      b.update('s'.repeat(300));
      assert.equal(hex(a), hex(b));
    }), 0, `${name} override disables wasm`);
    assert.ok(seenA.length > 0);
    assert.deepEqual(seenA, seenB);
  }
});

test('ripemd: static helper functions are inherited from the original', () => {
  for (const k of ['F', 'G', 'H', 'I', 'J', 'T', 'T64', 'T80']) {
    assert.equal(typeof Ripemd[k], 'function', k);
  }
  assert.equal(Ripemd.F(1, 2, 3), LegacyRipemd.F(1, 2, 3));
});

test('ripemd: all four variants interleaved in one module do not disturb each other', () => {
  const rand = rng(21);
  const hs = [128, 160, 256, 320].flatMap((length) => Array.from({ length: 3 }, () => ({
    a: new Ripemd({ length }), b: new LegacyRipemd({ length })
  })));
  for (let step = 0; step < 600; step++) {
    const { a, b } = hs[(rand() * hs.length) | 0];
    const chunk = binString(rand, (rand() * 200) | 0);
    a.update(chunk);
    b.update(chunk);
  }
  for (const { a, b } of hs) {
    assert.equal(json(a), json(b));
    assert.equal(hex(a), hex(b));
  }
});
