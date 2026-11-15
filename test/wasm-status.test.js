// Two guarantees about the wasm exports and the facades around them:
//
//  1. Every export that indexes with a value read from the State (`buffered`,
//     `rounds`, ...) or that needs a block-aligned length returns a non-zero
//     `runtime.Status` for a bad value, and touches nothing.
//  2. A facade that gets a non-zero status (or any other refusal) gives the work
//     back to the original code, with `this.state` consistent, and returns the
//     same digest and `getState()` as the original.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { ABI_VERSION, STATE_OFF, OUT_OFF, INPUT_OFF } from '../packages/crypto-api/src/wasm/family.mjs';
import { EXPECTED_ABI_VERSION } from '../js/index.js';

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

import LHas160 from '../packages/crypto-api/legacy/hasher/has160.mjs';
import LMd2 from '../packages/crypto-api/legacy/hasher/md2.mjs';
import LMd4 from '../packages/crypto-api/legacy/hasher/md4.mjs';
import LMd5 from '../packages/crypto-api/legacy/hasher/md5.mjs';
import LRipemd from '../packages/crypto-api/legacy/hasher/ripemd.mjs';
import LSha0 from '../packages/crypto-api/legacy/hasher/sha0.mjs';
import LSha1 from '../packages/crypto-api/legacy/hasher/sha1.mjs';
import LSha256 from '../packages/crypto-api/legacy/hasher/sha256.mjs';
import LSha512 from '../packages/crypto-api/legacy/hasher/sha512.mjs';
import LSm3 from '../packages/crypto-api/legacy/hasher/sm3.mjs';
import LSnefru from '../packages/crypto-api/legacy/hasher/snefru.mjs';
import LWhirlpool from '../packages/crypto-api/legacy/hasher/whirlpool.mjs';

test('the ABI version is 2 on every side', () => {
  assert.equal(ABI_VERSION, 2);
  assert.equal(EXPECTED_ABI_VERSION, 2);
  assert.equal(md5.runtime().ex.abi_version(), 2);
});

// ---------------------------------------------------------------------------
// 1. Raw exports. Offsets are the ones of the Zig `State` structs (docs/abi.md).
//    `bufferedBytes` is the width of the `buffered` field.
const RAW = [
  { prefix: 'md5', internal: md5, block: 64, buffered: 24, bufferedBytes: 4 },
  { prefix: 'md4', internal: md4, block: 64, buffered: 24, bufferedBytes: 4 },
  { prefix: 'has160', internal: has160, block: 64, buffered: 32, bufferedBytes: 4 },
  { prefix: 'ripemd128', internal: ripemd, block: 64, buffered: 24, bufferedBytes: 4 },
  { prefix: 'ripemd160', internal: ripemd, block: 64, buffered: 32, bufferedBytes: 4 },
  { prefix: 'ripemd256', internal: ripemd, block: 64, buffered: 40, bufferedBytes: 4 },
  { prefix: 'ripemd320', internal: ripemd, block: 64, buffered: 48, bufferedBytes: 4 },
  { prefix: 'md2', internal: md2, block: 16, buffered: 68, bufferedBytes: 4, rounds: 64, maxRounds: 0xffffffff },
  { prefix: 'sha0', internal: sha0, block: 64, buffered: 32, bufferedBytes: 4, rounds: 20, maxRounds: 80 },
  { prefix: 'sha1', internal: sha1, block: 64, buffered: 32, bufferedBytes: 4, rounds: 20, maxRounds: 80 },
  { prefix: 'sha256', internal: sha256, block: 64, buffered: 48, bufferedBytes: 4, rounds: 32, maxRounds: 64 },
  { prefix: 'sm3', internal: sm3, block: 64, buffered: 48, bufferedBytes: 4, rounds: 32, maxRounds: 64 },
  { prefix: 'sha512', internal: sha512, block: 128, buffered: 80, bufferedBytes: 4, rounds: 64, maxRounds: 160 },
  { prefix: 'whirlpool', internal: whirlpool, block: 64, buffered: 80, bufferedBytes: 4, rounds: 64, maxRounds: 10 },
  { prefix: 'whirlpool0', internal: whirlpool, block: 64, buffered: 80, bufferedBytes: 4, rounds: 64, maxRounds: 10 },
  { prefix: 'whirlpoolt', internal: whirlpool, block: 64, buffered: 80, bufferedBytes: 4, rounds: 64, maxRounds: 10 },
  { prefix: 'snefru', internal: snefru, block: 48, buffered: 62, bufferedBytes: 1, snefru: true },
];

describe('raw exports refuse bad State values and lengths', () => {
  for (const c of RAW) {
    test(c.prefix, () => {
      const rt = c.internal.runtime();
      assert.ok(rt, 'wasm failed to instantiate; run `zig build js` first');
      const { u8, ex, base } = rt;
      const st = base + STATE_OFF;
      const out = base + OUT_OFF;
      const input = base + INPUT_OFF;
      const u32At = (off, v) => new DataView(u8.buffer).setUint32(off, v, true);
      const reset = () => {
        u8.fill(0, base, base + INPUT_OFF + 512);
        if (c.snefru) {
          u8[st + 60] = 4; // words (a 128-bit digest: 12-word blocks of 48 bytes)
          u8[st + 61] = 8; // rounds
        } else if (c.rounds !== undefined) {
          u32At(st + c.rounds, c.prefix === 'md2' ? 18 : c.maxRounds);
        }
      };
      const sentinel = () => {
        u8.fill(0xa5, out, out + 128);
        u8.fill(0xa5, input, input + 512);
      };
      const snapshot = () => Buffer.from(u8.subarray(base, base + INPUT_OFF + 512));
      const setBuffered = (v) => {
        if (c.bufferedBytes === 1) u8[st + c.buffered] = v;
        else u32At(st + c.buffered, v);
      };
      const refused = (fn, what) => {
        sentinel();
        const before = snapshot();
        const status = fn();
        assert.equal(typeof status, 'number', `${c.prefix}: ${what} returns a Status`);
        assert.notEqual(status, 0, `${c.prefix}: ${what} must be refused`);
        assert.deepEqual(snapshot(), before, `${c.prefix}: ${what} must touch nothing`);
      };
      try {
        // Valid calls return 0 (control).
        reset();
        assert.equal(ex[c.prefix + '_blocks'](st, input, c.block), 0, 'valid blocks');
        assert.equal(ex[c.prefix + '_update'](st, input, 3), 0, 'valid update');
        assert.equal(ex[c.prefix + '_final'](st, c.prefix.startsWith('sha512') || c.prefix.startsWith('whirlpool') ? input : out), 0, 'valid final');

        // `buffered` at or past the block size would index past the State's buffer.
        const badBuffered = c.bufferedBytes === 1 ? [c.block, 255] : [c.block, c.block + 1, 0x7fffffff, 0xffffffff];
        for (const v of badBuffered) {
          reset();
          setBuffered(v);
          refused(() => ex[c.prefix + '_update'](st, input, 3), `update with buffered ${v}`);
          refused(() => ex[c.prefix + '_final'](st, out), `final with buffered ${v}`);
        }

        // `len` of `blocks` must be a whole number of blocks.
        reset();
        for (const len of [1, c.block - 1, c.block + 1, 2 * c.block + 3]) {
          refused(() => ex[c.prefix + '_blocks'](st, input, len), `blocks with len ${len}`);
        }

        // `rounds` outside what the compression function supports.
        if (c.rounds !== undefined) {
          const bad = [0, c.maxRounds + 1].filter((v) => v >= 0 && v <= 0xffffffff && !(c.maxRounds === 0xffffffff && v > 0xffffffff));
          for (const v of bad) {
            reset();
            u32At(st + c.rounds, v);
            refused(() => ex[c.prefix + '_blocks'](st, input, c.block), `blocks with rounds ${v}`);
            refused(() => ex[c.prefix + '_final'](st, out), `final with rounds ${v}`);
          }
        }
        if (c.snefru) {
          for (const [off, v] of [[60, 0], [60, 16], [61, 0], [61, 9]]) {
            reset();
            u8[st + off] = v;
            refused(() => ex.snefru_blocks(st, input, 48), `blocks with State byte ${off} = ${v}`);
            refused(() => ex.snefru_final(st, out), `final with State byte ${off} = ${v}`);
          }
        }
      } finally {
        u8.fill(0, base, base + INPUT_OFF + 512);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// 2. Facades fall back when an export refuses.
const CASES = [
  ['md2', Md2, LMd2, md2, undefined],
  ['md4', Md4, LMd4, md4, undefined],
  ['md5', Md5, LMd5, md5, undefined],
  ['has160', Has160, LHas160, has160, undefined],
  ['ripemd128', Ripemd, LRipemd, ripemd, { length: 128 }],
  ['ripemd160', Ripemd, LRipemd, ripemd, undefined],
  ['ripemd256', Ripemd, LRipemd, ripemd, { length: 256 }],
  ['ripemd320', Ripemd, LRipemd, ripemd, { length: 320 }],
  ['sha0', Sha0, LSha0, sha0, undefined],
  ['sha1', Sha1, LSha1, sha1, undefined],
  ['sha224', Sha256, LSha256, sha256, { length: 224 }],
  ['sha256', Sha256, LSha256, sha256, undefined],
  ['sm3', Sm3, LSm3, sm3, undefined],
  ['sha384', Sha512, LSha512, sha512, { length: 384 }],
  ['sha512', Sha512, LSha512, sha512, undefined],
  ['sha512/256', Sha512, LSha512, sha512, { length: 256 }],
  ['snefru128', Snefru, LSnefru, snefru, undefined],
  ['snefru256', Snefru, LSnefru, snefru, { length: 256, rounds: 4 }],
  ['whirlpool', Whirlpool, LWhirlpool, whirlpool, undefined],
  ['whirlpool-t', Whirlpool, LWhirlpool, whirlpool, { type: 't' }],
];
const INTERNALS = [...new Set(CASES.map((c) => c[3]))];

function message(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += String.fromCharCode((i * 31 + (i >> 8) * 7 + 5) & 0xff);
  return s;
}

/**
 * Run `fn` with WebAssembly instances whose `*_blocks` fail from the
 * `blocksFrom`-th call on (1-based; 0 = never) and whose `*_final` fails when
 * `refuseFinal`, with Status 3 and without running. Returns what was refused.
 */
function withRefusals({ blocksFrom, refuseFinal }, fn) {
  const RealInstance = WebAssembly.Instance;
  const seen = { blocks: 0, refusedBlocks: 0, refusedFinal: 0 };
  WebAssembly.Instance = function Instance(module, imports) {
    const real = new RealInstance(module, imports);
    // `real.exports` is frozen, so wrap into a plain copy.
    const exports = {};
    for (const key of Object.keys(real.exports)) {
      const value = real.exports[key];
      if (key.endsWith('_blocks')) {
        exports[key] = (...args) => {
          seen.blocks++;
          if (blocksFrom > 0 && seen.blocks >= blocksFrom) {
            seen.refusedBlocks++;
            return 3;
          }
          return value(...args);
        };
      } else if (key.endsWith('_final') && refuseFinal) {
        exports[key] = () => {
          seen.refusedFinal++;
          return 3;
        };
      } else {
        exports[key] = value;
      }
    }
    return { exports };
  };
  INTERNALS.forEach((i) => i.reset(false));
  try {
    INTERNALS.forEach((i) => assert.ok(i.runtime(), 'wasm failed to instantiate; run `zig build js` first'));
    fn();
  } finally {
    WebAssembly.Instance = RealInstance;
    INTERNALS.forEach((i) => i.reset(false));
  }
  return seen;
}

const state = (h) => JSON.stringify(h.getState());
const make = (C, options) => (options ? new C(Object.assign({}, options)) : new C());

const SCENARIOS = [
  { name: 'every blocks call refused', refusals: { blocksFrom: 1, refuseFinal: false }, size: 400, expect: ['blocks'] },
  { name: 'final refused', refusals: { blocksFrom: 0, refuseFinal: true }, size: 400, expect: ['final'] },
  { name: 'everything refused', refusals: { blocksFrom: 1, refuseFinal: true }, size: 400, expect: ['blocks', 'final'] },
  // 70000 bytes is more than one 64 KiB chunk: the second chunk is refused after the first was applied.
  { name: 'second chunk refused after the first was applied', refusals: { blocksFrom: 2, refuseFinal: false }, size: 70100, expect: ['blocks'] },
  { name: 'second chunk and final refused', refusals: { blocksFrom: 2, refuseFinal: true }, size: 70100, expect: ['blocks', 'final'] },
];

describe('facades fall back to the original code when an export is refused', () => {
  for (const sc of SCENARIOS) {
    test(sc.name, () => {
      const msg = message(sc.size);
      const seen = withRefusals(sc.refusals, () => {
        for (const [name, Facade, Legacy, internal, options] of CASES) {
          const f = make(Facade, options);
          const l = make(Legacy, options);
          f.update(msg);
          l.update(msg);
          assert.equal(state(f), state(l), `${name}: state after update`);
          const digest = f.finalize();
          assert.equal(toHex(digest), toHex(l.finalize()), `${name}: digest`);
          assert.equal(state(f), state(l), `${name}: state after finalize`);

          // A second message on the same instance after reset(), and a split update.
          f.reset();
          l.reset();
          f.update(msg.slice(0, 77));
          l.update(msg.slice(0, 77));
          f.update(msg.slice(77));
          l.update(msg.slice(77));
          assert.equal(toHex(f.finalize()), toHex(l.finalize()), `${name}: digest after reset`);
          assert.equal(typeof internal.wasmCalls(), 'number');
        }
      });
      // The refusals really happened, so the fallback paths ran.
      if (sc.expect.includes('blocks')) assert.ok(seen.refusedBlocks > 0, 'no blocks call was refused');
      if (sc.expect.includes('final')) assert.ok(seen.refusedFinal > 0, 'no final call was refused');
    });
  }

  test('a refused final does not change the hasher: the digest is the same on a second hasher without wasm', () => {
    for (const [name, Facade, Legacy, , options] of CASES) {
      const msg = message(150);
      withRefusals({ blocksFrom: 0, refuseFinal: true }, () => {
        const f = make(Facade, options);
        f.update(msg);
        const before = state(f);
        const l = make(Legacy, options);
        l.update(msg);
        assert.equal(before, state(l), `${name}: state before finalize`);
        assert.equal(toHex(f.finalize()), toHex(l.finalize()), `${name}: digest`);
      });
    }
  });
});
