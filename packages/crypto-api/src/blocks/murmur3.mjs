// crypto-api-ng:facade
'use strict';

/*
 * MurmurHash3 x86_32 and x64_128 in plain JavaScript: the engines used when WebAssembly is not
 * available, and the reference the wasm engines are tested against. See src/blocks/base.mjs for
 * how they are used and src/hash/murmur3.zig for the algorithm.
 *
 * Engine interface (shared with src/wasm/blocks.mjs):
 *   blocks(state, message, start, end)  process the whole blocks message[start, end)
 *   final(state, tail)                  the digest of the last block `tail`
 *
 * x86_32: `state.hash` is h1 (one int32).
 * x64_128: h1 and h2 as 64-bit words, low half first (four int32). `state.counter` is the number
 * of bytes processed so far.
 */

import {r, add, mul64, rotl, shr, word, be32, le32} from "./u64.mjs";

// ---- x86_32 -----------------------------------------------------------------

const C1 = 0xcc9e2d51 | 0;
const C2 = 0x1b873593 | 0;

const rotl32 = (x, n) => (x << n) | (x >>> (32 - n));
const mixK = (k) => Math.imul(rotl32(Math.imul(k, C1), 15), C2);

/** The initial `state.hash` for a seed (0 to 2^32 - 1). */
export function iv32(seed) {
  return [seed | 0];
}

export const murmur3_32 = {
  name: 'js',

  blocks(state, message, start, end) {
    let h = state.hash[0];
    for (let p = start; p < end; p += 4) {
      h ^= mixK(word(message, p));
      h = (Math.imul(rotl32(h, 13), 5) + 0xe6546b64) | 0;
    }
    state.hash[0] = h;
    state.counter += end - start;
  },

  final(state, tail) {
    let h = state.hash[0];
    let pos = 0;
    if (tail.length === 4) {
      h ^= mixK(word(tail, 0));
      h = (Math.imul(rotl32(h, 13), 5) + 0xe6546b64) | 0;
      pos = 4;
    }
    let k = 0;
    for (let i = 0; pos + i < tail.length; i++) {
      k |= tail.charCodeAt(pos + i) << (8 * i);
    }
    if (pos < tail.length) {
      h ^= mixK(k);
    }
    h ^= (state.counter + tail.length) % 4294967296;
    h ^= h >>> 16;
    h = Math.imul(h, 0x85ebca6b | 0);
    h ^= h >>> 13;
    h = Math.imul(h, 0xc2b2ae35 | 0);
    h ^= h >>> 16;
    return be32(h);
  }
};

// ---- x64_128 ----------------------------------------------------------------

const K1L = 0x114253d5 | 0, K1H = 0x87c37b91 | 0;
const K2L = 0x2745937f | 0, K2H = 0x4cf5ad43 | 0;

/** The initial `state.hash` for a seed (0 to 2^32 - 1). */
export function iv128(seed) {
  return [seed | 0, 0, seed | 0, 0];
}

/** k1 = rotl(k1 * c1, 31) * c2, in `r`. */
function mix1(lo, hi) {
  mul64(lo, hi, K1L, K1H);
  rotl(r.lo, r.hi, 31);
  mul64(r.lo, r.hi, K2L, K2H);
}

/** k2 = rotl(k2 * c2, 33) * c1, in `r`. */
function mix2(lo, hi) {
  mul64(lo, hi, K2L, K2H);
  rotl(r.lo, r.hi, 33);
  mul64(r.lo, r.hi, K1L, K1H);
}

function fmix(lo, hi) {
  shr(lo, hi, 33);
  mul64(lo ^ r.lo, hi ^ r.hi, 0xed558ccd | 0, 0xff51afd7 | 0);
  lo = r.lo;
  hi = r.hi;
  shr(lo, hi, 33);
  mul64(lo ^ r.lo, hi ^ r.hi, 0x1a85ec53 | 0, 0xc4ceb9fe | 0);
  lo = r.lo;
  hi = r.hi;
  shr(lo, hi, 33);
  r.lo ^= lo;
  r.hi ^= hi;
}

/** One 16-byte block at `p` of `m` into `h` (h1 low, h1 high, h2 low, h2 high). */
function block128(h, m, p) {
  mix1(word(m, p), word(m, p + 4));
  rotl(h[0] ^ r.lo, h[1] ^ r.hi, 27);
  add(r.lo, r.hi, h[2], h[3]);
  mul64(r.lo, r.hi, 5, 0);
  add(r.lo, r.hi, 0x52dce729, 0);
  h[0] = r.lo;
  h[1] = r.hi;
  mix2(word(m, p + 8), word(m, p + 12));
  rotl(h[2] ^ r.lo, h[3] ^ r.hi, 31);
  add(r.lo, r.hi, h[0], h[1]);
  mul64(r.lo, r.hi, 5, 0);
  add(r.lo, r.hi, 0x38495ab5, 0);
  h[2] = r.lo;
  h[3] = r.hi;
}

export const murmur3_128 = {
  name: 'js',

  blocks(state, message, start, end) {
    for (let p = start; p < end; p += 16) {
      block128(state.hash, message, p);
    }
    state.counter += end - start;
  },

  final(state, tail) {
    const h = state.hash.slice(0, 4);
    let pos = 0;
    if (tail.length === 16) {
      block128(h, tail, 0);
      pos = 16;
    }
    const k = [0, 0, 0, 0];
    const n = tail.length - pos;
    for (let i = 0; i < n; i++) {
      k[i >> 2] |= tail.charCodeAt(pos + i) << (8 * (i & 3));
    }
    if (n > 8) {
      mix2(k[2], k[3]);
      h[2] ^= r.lo;
      h[3] ^= r.hi;
    }
    if (n > 0) {
      mix1(k[0], k[1]);
      h[0] ^= r.lo;
      h[1] ^= r.hi;
    }
    const total = state.counter + tail.length;
    const tlo = total % 4294967296 | 0;
    const thi = Math.floor(total / 4294967296) | 0;
    let h1l = h[0] ^ tlo;
    let h1h = h[1] ^ thi;
    let h2l = h[2] ^ tlo;
    let h2h = h[3] ^ thi;
    add(h1l, h1h, h2l, h2h);
    h1l = r.lo;
    h1h = r.hi;
    add(h2l, h2h, h1l, h1h);
    h2l = r.lo;
    h2h = r.hi;
    fmix(h1l, h1h);
    h1l = r.lo;
    h1h = r.hi;
    fmix(h2l, h2h);
    h2l = r.lo;
    h2h = r.hi;
    add(h1l, h1h, h2l, h2h);
    h1l = r.lo;
    h1h = r.hi;
    add(h2l, h2h, h1l, h1h);
    return le32(h1l) + le32(h1h) + le32(r.lo) + le32(r.hi);
  }
};
