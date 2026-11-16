// crypto-api-ng:facade
'use strict';

/*
 * Tiger and Tiger2 in plain JavaScript: the engine used when WebAssembly is not available,
 * and the reference the wasm engine is tested against. See src/blocks/base.mjs for how it
 * is used and src/hash/tiger.zig for the algorithm.
 *
 * Engine interface (shared with src/wasm/blocks.mjs):
 *   blocks(state, message, start, end)  compress the whole blocks message[start, end)
 *   final(state, tail)                  the full 24-byte digest of the last block `tail`
 *
 * `state.hash` holds the three 64-bit chaining words as six int32 (low half first),
 * `state.counter` the number of bytes compressed so far.
 *
 * The S-boxes are derived on first use with the generator of the Tiger design (the same
 * code, in the same order, as `generate` in src/hash/tiger.zig), so they do not add 8 KiB
 * of literals to the bundle. `sbox()` is exported for the tests.
 */

export const BLOCK = 64;
export const DIGEST = 24;
export const IV = [0x89ABCDEF, 0x01234567, 0x76543210, 0xFEDCBA98, 0xC3B2E187, 0xF096A5B4].map((w) => w | 0);

const SEED = 'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham';
const TWO32 = 4294967296;

const s = new Int32Array(6);
const x = new Int32Array(16);
let table = null;

/** `a -= (lo, hi)` and friends on the 64-bit word `i` of `s`. */
function sub(i, lo, hi) {
  const d = (s[2 * i] >>> 0) - (lo >>> 0);
  s[2 * i] = d | 0;
  s[2 * i + 1] = (s[2 * i + 1] - hi - (d < 0 ? 1 : 0)) | 0;
}

function add(i, lo, hi) {
  const t = (s[2 * i] >>> 0) + (lo >>> 0);
  s[2 * i] = t | 0;
  s[2 * i + 1] = (s[2 * i + 1] + hi + (t > 0xffffffff ? 1 : 0)) | 0;
}

/** One round: `c ^= x[xi]`, then `a` and `b` are updated from the S-boxes `t`. */
function round(t, ai, bi, ci, xi, mul) {
  const clo = s[2 * ci] ^ x[2 * xi];
  const chi = s[2 * ci + 1] ^ x[2 * xi + 1];
  s[2 * ci] = clo;
  s[2 * ci + 1] = chi;
  const a1 = 2 * (clo & 255);
  const a2 = 2 * (256 + ((clo >>> 16) & 255));
  const a3 = 2 * (512 + (chi & 255));
  const a4 = 2 * (768 + ((chi >>> 16) & 255));
  sub(ai, t[a1] ^ t[a2] ^ t[a3] ^ t[a4], t[a1 + 1] ^ t[a2 + 1] ^ t[a3 + 1] ^ t[a4 + 1]);
  const b1 = 2 * (768 + ((clo >>> 8) & 255));
  const b2 = 2 * (512 + ((clo >>> 24) & 255));
  const b3 = 2 * (256 + ((chi >>> 8) & 255));
  const b4 = 2 * ((chi >>> 24) & 255);
  add(bi, t[b1] ^ t[b2] ^ t[b3] ^ t[b4], t[b1 + 1] ^ t[b2 + 1] ^ t[b3 + 1] ^ t[b4 + 1]);
  // b *= mul (mul is 5, 7 or 9)
  const p = (s[2 * bi] >>> 0) * mul;
  s[2 * bi] = p | 0;
  s[2 * bi + 1] = (Math.imul(s[2 * bi + 1], mul) + Math.floor(p / TWO32)) | 0;
}

const tmp = new Int32Array(2);

/** x[i] -= (lo, hi) */
function subX(i, lo, hi) {
  const d = (x[2 * i] >>> 0) - (lo >>> 0);
  x[2 * i] = d | 0;
  x[2 * i + 1] = (x[2 * i + 1] - hi - (d < 0 ? 1 : 0)) | 0;
}

/** x[i] += (lo, hi) */
function addX(i, lo, hi) {
  const t = (x[2 * i] >>> 0) + (lo >>> 0);
  x[2 * i] = t | 0;
  x[2 * i + 1] = (x[2 * i + 1] + hi + (t > 0xffffffff ? 1 : 0)) | 0;
}

/** tmp = ~x[k] << 19 */
function notShl19(k) {
  const lo = ~x[2 * k];
  const hi = ~x[2 * k + 1];
  tmp[0] = lo << 19;
  tmp[1] = (hi << 19) | (lo >>> 13);
}

/** tmp = ~x[k] >> 23 (logical) */
function notShr23(k) {
  const lo = ~x[2 * k];
  const hi = ~x[2 * k + 1];
  tmp[0] = (lo >>> 23) | (hi << 9);
  tmp[1] = hi >>> 23;
}

function keySchedule() {
  subX(0, x[14] ^ 0xA5A5A5A5, x[15] ^ 0xA5A5A5A5);
  x[2] ^= x[0];
  x[3] ^= x[1];
  addX(2, x[2], x[3]);
  notShl19(1);
  subX(3, x[4] ^ tmp[0], x[5] ^ tmp[1]);
  x[8] ^= x[6];
  x[9] ^= x[7];
  addX(5, x[8], x[9]);
  notShr23(4);
  subX(6, x[10] ^ tmp[0], x[11] ^ tmp[1]);
  x[14] ^= x[12];
  x[15] ^= x[13];
  addX(0, x[14], x[15]);
  notShl19(7);
  subX(1, x[0] ^ tmp[0], x[1] ^ tmp[1]);
  x[4] ^= x[2];
  x[5] ^= x[3];
  addX(3, x[4], x[5]);
  notShr23(2);
  subX(4, x[6] ^ tmp[0], x[7] ^ tmp[1]);
  x[10] ^= x[8];
  x[11] ^= x[9];
  addX(6, x[10], x[11]);
  subX(7, x[12] ^ 0x89ABCDEF, x[13] ^ 0x01234567);
}

/**
 * The compression function on the chaining value in `s` and the block words in `x`, with the
 * S-boxes `t`. `s` is updated in place.
 */
function compress(t) {
  const a0 = s[0];
  const a1 = s[1];
  const b0 = s[2];
  const b1 = s[3];
  const c0 = s[4];
  const c1 = s[5];
  for (let pass = 0; pass < 3; pass++) {
    if (pass !== 0) {
      keySchedule();
    }
    const mul = pass === 0 ? 5 : pass === 1 ? 7 : 9;
    round(t, 0, 1, 2, 0, mul);
    round(t, 1, 2, 0, 1, mul);
    round(t, 2, 0, 1, 2, mul);
    round(t, 0, 1, 2, 3, mul);
    round(t, 1, 2, 0, 4, mul);
    round(t, 2, 0, 1, 5, mul);
    round(t, 0, 1, 2, 6, mul);
    round(t, 1, 2, 0, 7, mul);
    // (a, b, c) = (c, a, b)
    const l0 = s[0];
    const l1 = s[1];
    s[0] = s[4];
    s[1] = s[5];
    s[4] = s[2];
    s[5] = s[3];
    s[2] = l0;
    s[3] = l1;
  }
  // a ^= aa; b -= bb; c += cc
  s[0] ^= a0;
  s[1] ^= a1;
  const d = (s[2] >>> 0) - (b0 >>> 0);
  s[2] = d | 0;
  s[3] = (s[3] - b1 - (d < 0 ? 1 : 0)) | 0;
  const e = (s[4] >>> 0) + (c0 >>> 0);
  s[4] = e | 0;
  s[5] = (s[5] + c1 + (e > 0xffffffff ? 1 : 0)) | 0;
}

/** Load the 16 little-endian int32 of `message[pos, pos + len)` into `x`, zero padded. */
function load(message, pos, len) {
  for (let i = 0; i < 16; i++) {
    const p = pos + 4 * i;
    const e = pos + len;
    x[i] = (p < e ? message.charCodeAt(p) : 0) |
      ((p + 1 < e ? message.charCodeAt(p + 1) : 0) << 8) |
      ((p + 2 < e ? message.charCodeAt(p + 2) : 0) << 16) |
      ((p + 3 < e ? message.charCodeAt(p + 3) : 0) << 24);
  }
}

/** Derive the four S-boxes (see `generate` in src/hash/tiger.zig). */
function generate() {
  const t = new Int32Array(2048);
  for (let i = 0; i < 1024; i++) {
    const b = (i & 255) * 0x01010101;
    t[2 * i] = b;
    t[2 * i + 1] = b;
  }
  const saved = [x.slice(), s.slice()];
  s.set(IV);
  let abc = 2;
  for (let pass = 0; pass < 5; pass++) {
    for (let i = 0; i < 256; i++) {
      for (let sb = 0; sb < 1024; sb += 256) {
        abc++;
        if (abc === 3) {
          abc = 0;
          // The key schedule rewrites `x`, so the seed is loaded again for every call.
          load(SEED, 0, 64);
          compress(t);
        }
        const lo = s[2 * abc];
        const hi = s[2 * abc + 1];
        for (let col = 0; col < 8; col++) {
          const half = col >> 2;
          const shift = 8 * (col & 3);
          const j = sb + (((half ? hi : lo) >>> shift) & 255);
          const ii = 2 * (sb + i) + half;
          const jj = 2 * j + half;
          const at = (t[ii] >>> shift) & 255;
          const aj = (t[jj] >>> shift) & 255;
          t[ii] = (t[ii] & ~(255 << shift)) | (aj << shift);
          t[jj] = (t[jj] & ~(255 << shift)) | (at << shift);
        }
      }
    }
  }
  x.set(saved[0]);
  s.set(saved[1]);
  return t;
}

/** The S-boxes: 1024 words as int32 pairs, low half first. */
export function sbox() {
  if (table === null) {
    table = generate();
  }
  return table;
}

function engine(pad) {
  return {
    name: 'js',

    blocks(state, message, start, end) {
      const t = sbox();
      const h = state.hash;
      for (let i = 0; i < 6; i++) {
        s[i] = h[i];
      }
      for (let pos = start; pos < end; pos += BLOCK) {
        load(message, pos, BLOCK);
        compress(t);
      }
      for (let i = 0; i < 6; i++) {
        h[i] = s[i];
      }
      state.counter += end - start;
    },

    final(state, tail) {
      const t = sbox();
      for (let i = 0; i < 6; i++) {
        s[i] = state.hash[i];
      }
      // The tail and the padding byte; a full 64-byte tail leaves a block of its own for the padding.
      const total = state.counter + tail.length;
      let block = tail;
      if (tail.length === BLOCK) {
        load(tail, 0, BLOCK);
        compress(t);
        block = '';
      }
      const len = block.length;
      load(block + String.fromCharCode(pad), 0, len + 1);
      if (len + 1 + 8 > BLOCK) {
        compress(t);
        load('', 0, 0);
      }
      // The message length in bits, 64-bit little-endian, in the last two words of the block.
      x[14] = (total * 8) % TWO32 | 0;
      x[15] = Math.floor((total * 8) / TWO32) | 0;
      compress(t);
      let out = '';
      for (let i = 0; i < 6; i++) {
        const w = s[i];
        out += String.fromCharCode(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff);
      }
      return out;
    }
  };
}

export const tiger = engine(0x01);
export const tiger2 = engine(0x80);
