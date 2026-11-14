// Structural parity: same class names, inheritance chains, methods, instance
// properties, and the same behavior when users subclass a hasher and override its
// internals (the extension API v1 keeps).
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { loadBoth } from '../harness/load.mjs';
import { FAMILIES, BASE_CLASSES, VARIANTS } from '../harness/catalog.mjs';

let oracle;
let target;
before(async () => ({ oracle, target } = await loadBoth()));

// A facade is a class with the same name as the verbatim
// original it extends, so `Sha1 -> Sha1 -> Hasher32be`. That one extra link is the
// design, not a divergence: collapse a class into its parent when the names match.
const chain = (Cls) => {
  const names = [];
  for (let c = Cls; c && c !== Function.prototype; c = Object.getPrototypeOf(c)) {
    if (names[names.length - 1] !== c.name) names.push(c.name);
  }
  return names;
};
const protoMethods = (Cls) => {
  const out = new Set();
  for (let p = Cls.prototype; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
    for (const k of Object.getOwnPropertyNames(p)) if (k !== 'constructor') out.add(k);
  }
  return out;
};

describe('class shape', () => {
  for (const f of FAMILIES) {
    it(f.className, () => {
      const O = oracle.hashers[f.className];
      const T = target.hashers[f.className];
      assert.equal(T.name, O.name);
      assert.deepStrictEqual(chain(T), chain(O), 'inheritance chain');
      for (const k of protoMethods(O)) assert.ok(protoMethods(T).has(k) || k === 'state', `missing method ${k}`);
      assert.equal(T.length, O.length, 'constructor arity');

      const o = new O();
      const t = new T();
      for (const k of Object.keys(o)) {
        if (k === 'state') { assert.ok('state' in t); assert.equal(typeof t.state, 'object'); continue; }
        assert.ok(k in t, `missing instance property ${k}`);
        assert.equal(typeof t[k], typeof o[k], `typeof ${k}`);
        if (['number', 'string', 'boolean'].includes(typeof o[k])) assert.equal(t[k], o[k], k);
      }
      assert.deepStrictEqual(JSON.parse(JSON.stringify(t.options)), JSON.parse(JSON.stringify(o.options)));
      assert.equal(Object.prototype.hasOwnProperty.call(t, 'processBlock'), Object.prototype.hasOwnProperty.call(o, 'processBlock'));
    });
  }

  for (const b of BASE_CLASSES) {
    it(`${b.className} base class is exported and subclassable`, () => {
      assert.equal(target.bases[b.className].name, b.className);
      assert.deepStrictEqual(chain(target.bases[b.className]), chain(oracle.bases[b.className]));
    });
  }

  it('instances are instanceof the target base classes (not only the oracle ones)', () => {
    const base = (f) => ({ md2: 'Hasher8' }[f.id] ?? ((f.id === 'has160' || f.id === 'md4' || f.id === 'md5' || f.id === 'ripemd') ? 'Hasher32le' : 'Hasher32be'));
    for (const f of FAMILIES) {
      const t = new target.hashers[f.className]();
      assert.ok(t instanceof target.bases.Hasher, `${f.id} instanceof Hasher`);
      assert.ok(t instanceof target.bases[base(f)], `${f.id} instanceof ${base(f)}`);
      const o = new oracle.hashers[f.className]();
      assert.ok(o instanceof oracle.bases[base(f)], `oracle sanity: ${f.id} instanceof ${base(f)}`);
    }
  });
});

describe('user subclasses that override internals', () => {
  for (const v of VARIANTS) {
    const f = FAMILIES.find((x) => x.id === v.family);
    it(`${v.id}: overriding processBlock, finalize and update`, () => {
      const run = (api) => {
        const Base = api.hashers[f.className];
        const calls = [];
        class Custom extends Base {
          processBlock(...a) { calls.push('pb'); return super.processBlock(...a); }
          update(m) { calls.push(`u${m.length}`); return super.update(m); }
          finalize() { calls.push('fin'); return super.finalize(); }
        }
        const h = new Custom(structuredClone(v.options));
        h.update('a'.repeat(200));
        h.update('tail');
        return { digest: api.toHex(h.finalize()), calls: calls.join(','), state: JSON.stringify(h.getState()) };
      };
      assert.deepStrictEqual(run(target), run(oracle));
    });

    it(`${v.id}: overriding getStateHash and addLengthBits/padding hooks`, () => {
      const run = (api) => {
        const Base = api.hashers[f.className];
        const log = [];
        class Custom extends Base {
          getStateHash(...a) { log.push('gsh'); return super.getStateHash(...a); }
          addLengthBits(...a) { log.push('alb'); return super.addLengthBits?.(...a); }
        }
        const h = new Custom(structuredClone(v.options));
        h.update('hello');
        const r = (() => { try { return api.toHex(h.finalize()); } catch (e) { return `!${e.constructor.name}`; } })();
        return { r, log: log.join(',') };
      };
      assert.deepStrictEqual(run(target), run(oracle));
    });
  }
});
