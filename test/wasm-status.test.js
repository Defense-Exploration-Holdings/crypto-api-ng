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

import Sha3 from '../packages/crypto-api/src/hasher/sha3.mjs';
import Keccak from '../packages/crypto-api/src/hasher/keccak.mjs';
import Shake from '../packages/crypto-api/src/hasher/shake.mjs';
import { _internal as keccak } from '../packages/crypto-api/src/wasm/keccak.mjs';
import Blake2b, { _internal as blake2b } from '../packages/crypto-api/src/hasher/blake2b.mjs';
import Blake2s, { _internal as blake2s } from '../packages/crypto-api/src/hasher/blake2s.mjs';
import Blake3, { _internal as blake3 } from '../packages/crypto-api/src/hasher/blake3.mjs';

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

// ===========================================================================
// SHA-3 / SHAKE / Keccak, BLAKE2 and BLAKE3 (no original to fall back on: the
// engine of last resort is their own plain-JavaScript implementation).
//
//  3. The new exports refuse bad State values, lengths and counts, and touch nothing.
//  4. Their facades check every status. A refused call is redone by the JavaScript
//     engine on the untouched state, and the result is the one the JavaScript engine
//     gives on its own; nothing is read from the output region of a refused call.
//  5. A state that no engine can work on is refused with the same error by both engines.
// ===========================================================================

const NEW_INTERNALS = [keccak, blake2b, blake2s, blake3];

const view = (rt) => new DataView(rt.u8.buffer);

describe('the sponge, BLAKE2 and BLAKE3 exports refuse bad values and touch nothing', () => {
  const REGION = 256 + 2048 + 4096;
  /** Run `body` with the scratch region cleared before and after. */
  function withScratch(internal, body) {
    const rt = internal.runtime();
    assert.ok(rt, 'wasm failed to instantiate; run `zig build js` first');
    const { u8, base } = rt;
    u8.fill(0, base, base + REGION);
    try {
      body(rt, base);
    } finally {
      u8.fill(0, base, base + REGION);
    }
  }
  const snapshot = (rt) => Buffer.from(rt.u8.subarray(rt.base, rt.base + REGION));
  /** Fill what the export could write to with a marker, call it and check it was refused without a single write. */
  function refused(rt, what, call) {
    rt.u8.fill(0xa5, rt.base + 256 + 8, rt.base + REGION);
    const before = snapshot(rt);
    const status = call();
    assert.equal(typeof status, 'number', `${what} returns a Status`);
    assert.notEqual(status, 0, `${what} must be refused`);
    assert.deepEqual(snapshot(rt), before, `${what} must touch nothing`);
  }

  test('keccak', () => {
    withScratch(keccak, (rt, base) => {
      const { ex } = rt;
      const dv = view(rt);
      const st = base;
      const input = base + 256;
      const out = base + 512;
      const setRate = (rate, pos = 0) => {
        dv.setUint32(st + 200, rate, true);
        dv.setUint32(st + 204, pos, true);
      };
      // Valid calls return 0 (control).
      assert.equal(ex.keccak_init(st, 136), 0);
      assert.equal(ex.keccak_blocks(st, input, 136), 0);
      assert.equal(ex.keccak_final(st, input, 5, 0x06, out, 32), 0);
      assert.equal(ex.keccak_squeeze(st, out, 32), 0);

      for (const rate of [0, 4, 7, 73, 200, 208, 0xffffffff]) {
        refused(rt, `init with rate ${rate}`, () => ex.keccak_init(st, rate));
        setRate(rate);
        refused(rt, `blocks with rate ${rate}`, () => ex.keccak_blocks(st, input, 0));
        refused(rt, `final with rate ${rate}`, () => ex.keccak_final(st, input, 0, 0x06, out, 32));
        refused(rt, `squeeze with rate ${rate}`, () => ex.keccak_squeeze(st, out, 32));
      }
      // The squeeze position is used as an index too.
      for (const pos of [137, 0x7fffffff, 0xffffffff]) {
        setRate(136, pos);
        refused(rt, `blocks with pos ${pos}`, () => ex.keccak_blocks(st, input, 136));
        refused(rt, `final with pos ${pos}`, () => ex.keccak_final(st, input, 0, 0x06, out, 32));
        refused(rt, `squeeze with pos ${pos}`, () => ex.keccak_squeeze(st, out, 32));
      }
      setRate(136);
      for (const len of [1, 135, 137, 273]) {
        refused(rt, `blocks with len ${len}`, () => ex.keccak_blocks(st, input, len));
      }
      for (const len of [136, 137, 0xffffffff]) {
        refused(rt, `final with len ${len}`, () => ex.keccak_final(st, input, len, 0x06, out, 32));
      }
      for (const suffix of [0, 0x80, 0xff, 0x100, 0xffffffff]) {
        refused(rt, `final with suffix ${suffix}`, () => ex.keccak_final(st, input, 3, suffix, out, 32));
      }
    });
  });

  for (const [prefix, internal, block] of [['blake2b', blake2b, 128], ['blake2s', blake2s, 64]]) {
    test(prefix, () => {
      withScratch(internal, (rt, base) => {
        const { ex } = rt;
        const st = base;
        const input = base + 256;
        const out = base + 128;
        assert.equal(ex[prefix + '_blocks'](st, input, block), 0);
        assert.equal(ex[prefix + '_blocks'](st, input, 0), 0);
        assert.equal(ex[prefix + '_final'](st, input, block, out), 0);
        assert.equal(ex[prefix + '_final'](st, input, 0, out), 0);
        for (const len of [1, block - 1, block + 1, 2 * block + 3, 0xffffffff]) {
          refused(rt, `${prefix}_blocks with len ${len}`, () => ex[prefix + '_blocks'](st, input, len));
        }
        for (const len of [block + 1, 2 * block, 0xffffffff]) {
          refused(rt, `${prefix}_final with tail_len ${len}`, () => ex[prefix + '_final'](st, input, len, out));
        }
      });
    });
  }

  test('blake3', () => {
    withScratch(blake3, (rt, base) => {
      const { ex } = rt;
      const dv = view(rt);
      const st = base;
      const params = base + 128;
      const stack = base + 256;
      const data = base + 2304;
      const setChunks = (n) => dv.setBigUint64(st + 40, BigInt(n), true);
      const LIMIT = 2n ** 53n;
      setChunks(0);
      assert.equal(ex.blake3_update(st, stack, data, 2), 0);
      assert.equal(ex.blake3_update(st, stack, data, 0), 0);
      assert.equal(ex.blake3_root(st, stack, data, 1024, params), 0);
      assert.equal(ex.blake3_xof(params, 0, data, 100), 0, 'the output stage has nothing to refuse');
      setChunks(0);
      assert.equal(ex.blake3_root(st, stack, data, 0, params), 0, 'an empty message');

      for (const chunks of [LIMIT, LIMIT + 1n, 2n ** 63n, 2n ** 64n - 1n]) {
        setChunks(chunks);
        refused(rt, `update with ${chunks} chunks`, () => ex.blake3_update(st, stack, data, 1));
        refused(rt, `root with ${chunks} chunks`, () => ex.blake3_root(st, stack, data, 10, params));
      }
      // The count of the call counts too: the stack has 54 entries, for chunk counts below 2^53.
      for (const [chunks, n] of [[LIMIT - 1n, 1], [LIMIT - 2n, 2], [LIMIT - 61n, 61]]) {
        setChunks(chunks);
        refused(rt, `update of ${n} chunks after ${chunks}`, () => ex.blake3_update(st, stack, data, n));
      }
      setChunks(0);
      for (const len of [1025, 2048, 0xffffffff]) {
        refused(rt, `root with tail_len ${len}`, () => ex.blake3_root(st, stack, data, len, params));
      }
      // An empty last chunk is only the whole message when nothing was added before it.
      for (const chunks of [1, 2, 3, 1000, LIMIT - 1n]) {
        setChunks(chunks);
        refused(rt, `root with an empty tail after ${chunks} chunks`, () => ex.blake3_root(st, stack, data, 0, params));
      }
    });
  });
});

// ---------------------------------------------------------------------------
// 4. Forced refusals
// ---------------------------------------------------------------------------

/**
 * Run `fn` with WebAssembly instances of the new families whose exports named in `plan` refuse (Status 3,
 * without running) from the n-th call on (1-based). Counts every call by export name.
 */
function withExportRefusals(plan, fn) {
  const RealInstance = WebAssembly.Instance;
  const seen = {};
  const refusedCalls = {};
  WebAssembly.Instance = function Instance(module, imports) {
    const real = new RealInstance(module, imports);
    const exports = {};
    for (const key of Object.keys(real.exports)) {
      const value = real.exports[key];
      if (typeof value === 'function' && /^(keccak|blake)/.test(key)) {
        exports[key] = (...args) => {
          seen[key] = (seen[key] || 0) + 1;
          if (key in plan && seen[key] >= plan[key]) {
            refusedCalls[key] = (refusedCalls[key] || 0) + 1;
            return 3;
          }
          return value(...args);
        };
      } else {
        exports[key] = value;
      }
    }
    return { exports };
  };
  NEW_INTERNALS.forEach((i) => i.reset(false));
  try {
    NEW_INTERNALS.forEach((i) => assert.ok(i.runtime(), 'wasm failed to instantiate; run `zig build js` first'));
    fn();
  } finally {
    WebAssembly.Instance = RealInstance;
    NEW_INTERNALS.forEach((i) => i.reset(false));
  }
  return { seen, refused: refusedCalls };
}

/** What `fn` returns with every new family on its plain-JavaScript engine. */
function onJavaScript(fn) {
  NEW_INTERNALS.forEach((i) => i.reset(true));
  try {
    return fn();
  } finally {
    NEW_INTERNALS.forEach((i) => i.reset(false));
  }
}

function binary(n, seed = 1) {
  let s = '';
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    s += String.fromCharCode(x >>> 24);
  }
  return s;
}

/** The hashers of the three families, each with an input that needs several wasm calls per stage. */
const NEW_CASES = [
  ['sha3-256', Sha3, { length: 256 }, 140000],
  ['sha3-512', Sha3, { length: 512 }, 140000],
  ['keccak256', Keccak, { length: 256 }, 140000],
  ['shake128, 100 KB of output', Shake, { strength: 128, length: 800000 }, 140000],
  ['shake256, 100 KB of output', Shake, { strength: 256, length: 800000 }, 3000],
  ['blake2b', Blake2b, {}, 140000],
  ['blake2b, keyed, salted', Blake2b, { length: 256, key: 'k'.repeat(64), salt: 'salt', personalization: 'pers' }, 140000],
  ['blake2s', Blake2s, {}, 140000],
  ['blake2s, keyed', Blake2s, { key: 'k'.repeat(32), length: 128 }, 140000],
  ['blake3', Blake3, {}, 70000],
  ['blake3, 100 KB of output', Blake3, { length: 800000 }, 70000],
  ['blake3, keyed', Blake3, { key: 'K'.repeat(32), length: 512 }, 70000],
  ['blake3, derive key', Blake3, { context: 'a context', length: 256 }, 70000],
  ['blake3, short message', Blake3, {}, 100],
];

const REFUSALS = [
  ['every compress call refused', { keccak_blocks: 1, blake2b_blocks: 1, blake2s_blocks: 1, blake3_update: 1 }],
  ['second compress call refused after the first was applied', { keccak_blocks: 2, blake2b_blocks: 2, blake2s_blocks: 2, blake3_update: 2 }],
  ['final refused', { keccak_final: 1, blake2b_final: 1, blake2s_final: 1, blake3_root: 1 }],
  ['squeeze and the second xof call refused', { keccak_squeeze: 1, blake3_xof: 2 }],
  ['xof refused at once', { blake3_xof: 1 }],
  ['everything refused', {
    keccak_blocks: 1, keccak_final: 1, keccak_squeeze: 1, blake2b_blocks: 1, blake2b_final: 1, blake2s_blocks: 1, blake2s_final: 1,
    blake3_update: 1, blake3_root: 1, blake3_xof: 1,
  }],
];

describe('the facades redo a refused call in JavaScript, on the untouched state', () => {
  for (const [what, plan] of REFUSALS) {
    test(what, () => {
      let anyRefused = 0;
      for (const [name, C, options, size] of NEW_CASES) {
        const message = binary(size, name.length);
        const run = () => {
          const h = new C({ ...options });
          h.update(message.slice(0, 77));
          h.update(message.slice(77));
          const state = JSON.stringify(h.getState());
          const first = toHex(h.finalize());
          // finalize() leaves the state alone, and a second call gives the same digest.
          assert.equal(JSON.stringify(h.getState()), state, `${name}: finalize() changed the state`);
          assert.equal(toHex(h.finalize()), first, `${name}: second finalize()`);
          // An update after a refusal continues the same message.
          const g = new C({ ...options });
          g.update(message);
          g.update('tail');
          return [first, state, toHex(g.finalize())].join('\n');
        };
        const want = onJavaScript(run);
        let got;
        const { refused: n } = withExportRefusals(plan, () => {
          got = run();
        });
        assert.equal(got, want, name);
        anyRefused += Object.values(n).reduce((a, b) => a + b, 0);
      }
      assert.ok(anyRefused > 0, 'no call was refused');
    });
  }

  test('BLAKE3 starts the output stage only after its root call succeeded', () => {
    const message = binary(5000, 3);
    for (const options of [{}, { key: 'K'.repeat(32) }, { context: 'ctx' }]) {
      const want = onJavaScript(() => {
        const h = new Blake3({ ...options, length: 1024 });
        h.update(message);
        return toHex(h.finalize());
      });
      let got;
      const { seen, refused: r } = withExportRefusals({ blake3_root: 1 }, () => {
        const h = new Blake3({ ...options, length: 1024 });
        h.update(message);
        got = toHex(h.finalize());
      });
      assert.equal(got, want, JSON.stringify(options));
      assert.ok(r.blake3_root >= 1, 'root was refused');
      assert.equal(seen.blake3_xof, undefined, 'xof ran after a refused root');
    }
  });

  test('a refused final call does not change the hasher', () => {
    for (const [C, options] of [[Blake2b, {}], [Blake2s, { key: 'k' }], [Sha3, { length: 256 }], [Shake, { length: 4096 }], [Blake3, {}]]) {
      const message = binary(1000, 5);
      const h = new C({ ...options });
      h.update(message);
      const state = JSON.stringify(h.getState());
      const want = onJavaScript(() => toHex(h.finalize()));
      let got;
      withExportRefusals({ keccak_final: 1, blake2b_final: 1, blake2s_final: 1, blake3_root: 1 }, () => {
        got = toHex(h.finalize());
      });
      assert.equal(got, want);
      assert.equal(JSON.stringify(h.getState()), state);
    }
  });
});

// ---------------------------------------------------------------------------
// 5. States that no engine can work on
// ---------------------------------------------------------------------------

/** Run `body(engine)` with wasm, then with the JavaScript engines only. */
function onBothEngines(body) {
  for (const [label, disable] of [['wasm', false], ['js', true]]) {
    NEW_INTERNALS.forEach((i) => i.reset(disable));
    try {
      assert.equal(!!keccak.runtime(), !disable, 'run `zig build js` first');
      body(label);
    } finally {
      NEW_INTERNALS.forEach((i) => i.reset(false));
    }
  }
}

/** The error class (or the digest) an operation ends with, for comparing the two engines. */
function outcome(fn) {
  try {
    const value = fn();
    return typeof value === 'string' ? 'digest ' + toHex(value) : 'ok';
  } catch (e) {
    assert.ok(e instanceof TypeError || e instanceof RangeError, String(e));
    assert.ok(e.message.length > 0 && e.message.length < 160, e.message);
    return e.constructor.name;
  }
}

describe('a state no engine can work on is refused, by both engines alike', () => {
  test('regression: BLAKE3 does not finalize an empty last chunk after chunks were added', () => {
    onBothEngines((engine) => {
      // Leave root parameters of a different, keyed hash in the module.
      const other = new Blake3({ key: 'M'.repeat(32) });
      other.update('the other hasher\'s message');
      other.finalize();
      const v = new Blake3();
      v.setState({ message: '', length: 0, chunks: 1, stack: [1, 2, 3, 4, 5, 6, 7, 8] });
      assert.throws(() => v.finalize(), RangeError, engine);
      assert.throws(() => v.finalize(), RangeError, engine);
    });
  });

  test('regression: SHA-3 with a block size that is not a rate neither drops the message nor returns raw bytes', () => {
    onBothEngines((engine) => {
      const s = new Sha3({ length: 256 });
      s.blockSizeInBytes = 100;
      assert.throws(() => s.update('a'.repeat(300)), RangeError, engine);
      assert.equal(s.getState().message.length, 300, 'the message is still in the state');
      assert.throws(() => s.finalize(), RangeError, engine);
      // With the rate back, the same state gives the digest of the message.
      s.blockSizeInBytes = 136;
      const ok = new Sha3({ length: 256 });
      ok.update('a'.repeat(300));
      assert.equal(toHex(s.finalize()), toHex(ok.finalize()), engine);
    });
  });

  const sponges = [['Sha3', () => new Sha3({ length: 256 })], ['Keccak', () => new Keccak({ length: 512 })], ['Shake', () => new Shake({ length: 1024 })]];
  const goodHash = () => new Array(50).fill(0);

  test('sponge: message, hash and block size are validated', () => {
    const results = {};
    onBothEngines((engine) => {
      const seen = [];
      for (const [name, make] of sponges) {
        const cases = [
          ['message 5', { message: 5, length: 0, hash: goodHash() }],
          ['message null', { message: null, length: 0, hash: goodHash() }],
          ['message array', { message: ['a'], length: 0, hash: goodHash() }],
          ['hash missing', { message: 'abc', length: 3 }],
          ['hash 49 words', { message: 'abc', length: 3, hash: new Array(49).fill(0) }],
          ['hash 51 words', { message: 'abc', length: 3, hash: new Array(51).fill(0) }],
          ['hash object', { message: 'abc', length: 3, hash: { length: 50 } }],
          ['hash typed array', { message: 'abc', length: 3, hash: new Int32Array(50) }],
          ['hash string word', { message: 'abc', length: 3, hash: goodHash().fill('1', 7, 8) }],
          ['hash fraction', { message: 'abc', length: 3, hash: goodHash().fill(1.5, 3, 4) }],
          ['hash NaN', { message: 'abc', length: 3, hash: goodHash().fill(NaN, 49) }],
          ['hash null word', { message: 'abc', length: 3, hash: goodHash().fill(null, 0, 1) }],
          ['long message, short hash', { message: 'a'.repeat(500), length: 500, hash: new Array(10).fill(0) }],
        ];
        for (const [what, state] of cases) {
          const h = make();
          h.setState(structuredClone(state));
          const a = outcome(() => h.finalize());
          assert.equal(a, 'TypeError', `${name} ${what} finalize`);
          seen.push(`${name} ${what} ${a}`);
          // update() hits the same checks as soon as it has a block to absorb.
          const u = make();
          u.setState(structuredClone(state));
          seen.push(`${name} ${what} update ${outcome(() => u.update('a'.repeat(200)))}`);
        }
        for (const rate of [0, 4, 7, 100, 136.5, 200, 208, -8, NaN, Infinity]) {
          for (const message of ['abc', 'a'.repeat(500)]) {
            const h = make();
            h.blockSizeInBytes = rate;
            h.state.message = message;
            const a = outcome(() => h.finalize());
            assert.equal(a, 'RangeError', `${name} rate ${rate} finalize`);
            seen.push(`${name} rate ${rate} ${a}`);
          }
        }
        for (const rate of ['136', null, undefined, {}]) {
          const h = make();
          h.blockSizeInBytes = rate;
          assert.equal(outcome(() => h.finalize()), 'TypeError', `${name} rate ${String(rate)}`);
        }
        // Valid states: whole unprocessed blocks, and words outside int32 (taken modulo 2^32 by both engines).
        for (const hash of [goodHash(), goodHash().fill(2 ** 32 + 5, 0, 1)]) {
          const h = make();
          h.setState({ message: 'a'.repeat(450), length: 450, hash });
          const a = outcome(() => h.finalize());
          assert.match(a, /^digest /, `${name} valid state`);
          seen.push(`${name} valid ${a}`);
        }
      }
      results[engine] = seen.join('\n');
    });
    assert.equal(results.wasm, results.js, 'both engines give the same outcomes');
  });

  test('BLAKE2: hash, counter and last block are validated', () => {
    for (const [C, hashInts, block] of [[Blake2b, 16, 128], [Blake2s, 8, 64]]) {
      const results = {};
      onBothEngines((engine) => {
        const seen = [];
        const hash = () => new Array(hashInts).fill(0);
        const base = () => ({ message: 'abc', length: 3, counter: 0, hash: hash() });
        const cases = [
          ['hash missing', { ...base(), hash: undefined }],
          ['hash short', { ...base(), hash: hash().slice(1) }],
          ['hash long', { ...base(), hash: hash().concat([0]) }],
          ['hash string word', { ...base(), hash: hash().fill('1', 2, 3) }],
          ['hash fraction', { ...base(), hash: hash().fill(0.5, 1, 2) }],
          ['hash NaN', { ...base(), hash: hash().fill(NaN, 0, 1) }],
          ['counter missing', { ...base(), counter: undefined }],
          ['counter string', { ...base(), counter: '0' }],
          ['counter negative', { ...base(), counter: -block }],
          ['counter fraction', { ...base(), counter: 0.5 }],
          ['counter unaligned', { ...base(), counter: block + 1 }],
          ['counter unsafe', { ...base(), counter: 2 ** 53 }],
          ['message number', { ...base(), message: 5 }],
          ['message null', { ...base(), message: null }],
          ['empty last block after compressed blocks', { ...base(), message: '', counter: block }],
          ['valid', base()],
          ['valid, whole blocks pending', { ...base(), message: 'a'.repeat(3 * block + 1) }],
          ['valid, exactly one block', { ...base(), message: 'a'.repeat(block), counter: 0 }],
          ['valid, empty message', { ...base(), message: '' }],
        ];
        for (const [what, state] of cases) {
          const h = new C();
          h.setState(structuredClone(state));
          seen.push(`${what}: ${outcome(() => h.finalize())}`);
          const u = new C();
          u.setState(structuredClone(state));
          seen.push(`${what}: update ${outcome(() => u.update('x'.repeat(2 * block)))}`);
        }
        results[engine] = seen.join('\n');
      });
      assert.equal(results.wasm, results.js, `${C.name}: both engines give the same outcomes`);
      // (The `update` lines only have to agree between the engines: an update that appends to a bad message may repair it.)
      for (const line of results.wasm.split('\n').filter((l) => !l.includes(': update '))) {
        if (line.startsWith('valid')) assert.ok(/: digest/.test(line), line);
        else assert.ok(/: (TypeError|RangeError)$/.test(line), line);
      }
    }
  });

  test('BLAKE3: chunk count, stack and last chunk are validated', () => {
    const results = {};
    onBothEngines((engine) => {
      const seen = [];
      const stack = (n) => Array.from({ length: n }, (_, i) => i + 1);
      const cases = [
        ['chunks negative', { message: 'abc', length: 3, chunks: -1, stack: [] }],
        ['chunks fraction', { message: 'abc', length: 3, chunks: 0.5, stack: [] }],
        ['chunks string', { message: 'abc', length: 3, chunks: '1', stack: stack(8) }],
        ['chunks NaN', { message: 'abc', length: 3, chunks: NaN, stack: [] }],
        ['chunks 2^53', { message: 'abc', length: 3, chunks: 2 ** 53, stack: stack(8) }],
        ['chunks missing', { message: 'abc', length: 3, stack: [] }],
        ['stack missing', { message: 'abc', length: 3, chunks: 1 }],
        ['stack too short', { message: 'abc', length: 1027, chunks: 1, stack: stack(7) }],
        ['stack too long', { message: 'abc', length: 1027, chunks: 1, stack: stack(9) }],
        ['stack for another count', { message: 'abc', length: 3075, chunks: 3, stack: stack(8) }],
        ['stack with a string', { message: 'abc', length: 1027, chunks: 1, stack: stack(7).concat(['x']) }],
        ['stack with a fraction', { message: 'abc', length: 1027, chunks: 1, stack: stack(7).concat([0.5]) }],
        ['stack object', { message: 'abc', length: 1027, chunks: 1, stack: { length: 8 } }],
        ['message number', { message: 5, length: 0, chunks: 0, stack: [] }],
        ['message null', { message: null, length: 0, chunks: 0, stack: [] }],
        ['empty last chunk after chunks', { message: '', length: 0, chunks: 1, stack: stack(8) }],
        ['empty last chunk after many chunks', { message: '', length: 0, chunks: 3, stack: stack(16) }],
        ['valid, empty', { message: '', length: 0, chunks: 0, stack: [] }],
        ['valid, one chunk', { message: 'abc', length: 1027, chunks: 1, stack: stack(8) }],
        ['valid, three chunks', { message: 'a'.repeat(1024), length: 4096, chunks: 3, stack: stack(16) }],
        ['valid, pending chunks', { message: 'a'.repeat(5000), length: 5000, chunks: 0, stack: [] }],
        ['valid, big words', { message: 'abc', length: 1027, chunks: 1, stack: stack(8).map((x) => x * 0x10000001) }],
      ];
      for (const [what, state] of cases) {
        const h = new Blake3();
        h.setState(structuredClone(state));
        seen.push(`${what}: ${outcome(() => h.finalize())}`);
        const u = new Blake3();
        u.setState(structuredClone(state));
        seen.push(`${what}: update ${outcome(() => u.update('x'.repeat(3000)))}`);
      }
      results[engine] = seen.join('\n');
    });
    assert.equal(results.wasm, results.js, 'both engines give the same outcomes');
    for (const line of results.wasm.split('\n').filter((l) => !l.includes(': update '))) {
      if (line.startsWith('valid')) assert.ok(/: digest/.test(line), line);
      else assert.ok(/: (TypeError|RangeError)$/.test(line), line);
    }
    for (const what of ['chunks negative', 'chunks fraction', 'chunks string', 'chunks NaN', 'chunks 2^53', 'chunks missing', 'stack missing',
      'stack too short', 'stack too long', 'stack for another count', 'stack with a string', 'stack with a fraction', 'stack object',
      'message number', 'message null', 'empty last chunk after chunks', 'empty last chunk after many chunks']) {
      assert.match(results.wasm, new RegExp(`^${what.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')}: (TypeError|RangeError)$`, 'm'), what);
    }
  });
});
