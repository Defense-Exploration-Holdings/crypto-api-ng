// crypto-api-ng:facade
'use strict';

/*
 * XXH3-64 and XXH3-128 in plain JavaScript: the engines used when WebAssembly is not available,
 * and the reference the wasm engines are tested against. See src/blocks/base.mjs for how they are
 * used and src/hash/xxh3.zig for the algorithm.
 *
 * Engine interface (shared with src/wasm/blocks.mjs):
 *   blocks(state, message, start, end)  process the whole 1024-byte blocks message[start, end)
 *   final(state, tail)                  the hash (8 or 16 bytes, most significant first) of the end `tail`
 *
 * `state.hash` is the eight accumulators and the seed as 64-bit words, low half first (18 int32).
 * `state.counter` is the number of bytes processed so far. Once a block has been processed, the
 * tail holds at least the last 64 bytes of the message.
 */

import {r, add, sub, mul32, mul64, mul128, rotl, shr, shl, bswap32, word, wordOf, fromNumber, be32} from "./u64.mjs";

const SECRET = [
  0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
  0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
  0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
  0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
  0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
  0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
  0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
  0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
  0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
  0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
  0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
  0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e
];

const SECRET_LEN = 192;
const STRIPE = 64;
const STRIPES = 16;
const BLOCK = 1024;

// Constants as low and high int32.
const P32_1 = 0x9E3779B1 | 0;
const P32_2 = 0x85EBCA77 | 0;
const P32_3 = 0xC2B2AE3D | 0;
const P1L = 0x85EBCA87 | 0, P1H = 0x9E3779B1 | 0;
const P2L = 0x27D4EB4F | 0, P2H = 0xC2B2AE3D | 0;
const P3L = 0x9E3779F9 | 0, P3H = 0x165667B1 | 0;
const P4L = 0xC2B2AE63 | 0, P4H = 0x85EBCA77 | 0;
const P5L = 0x165667C5 | 0, P5H = 0x27D4EB2F | 0;
const MX1L = 0x9E3779F9 | 0, MX1H = 0x16566791 | 0;
const MX2L = 0x1E98DF25 | 0, MX2H = 0x9FB21C65 | 0;

/** The eight accumulators and the seed (0 to 2^53 - 1): the initial `state.hash`. */
export function iv(seed) {
  fromNumber(seed);
  return [P32_3, 0, P1L, P1H, P2L, P2H, P3L, P3H, P4L, P4H, P32_2, 0, P5L, P5H, P32_1, 0, r.lo, r.hi];
}

/** The secret of the seed in `state.hash` (the default secret for seed 0). */
function secretOf(hash) {
  const slo = hash[16];
  const shi = hash[17];
  if (slo === 0 && shi === 0) {
    return SECRET;
  }
  const out = new Array(SECRET_LEN);
  for (let i = 0; i < SECRET_LEN; i += 8) {
    const lo = wordOf(SECRET, i);
    const hi = wordOf(SECRET, i + 4);
    if (i % 16 === 0) {
      add(lo, hi, slo, shi);
    } else {
      sub(lo, hi, slo, shi);
    }
    for (let k = 0; k < 4; k++) {
      out[i + k] = (r.lo >>> (8 * k)) & 0xff;
      out[i + 4 + k] = (r.hi >>> (8 * k)) & 0xff;
    }
  }
  return out;
}

// ---- helpers ----------------------------------------------------------------

function avalanche64(lo, hi) {
  shr(lo, hi, 33);
  mul64(lo ^ r.lo, hi ^ r.hi, P2L, P2H);
  lo = r.lo;
  hi = r.hi;
  shr(lo, hi, 29);
  mul64(lo ^ r.lo, hi ^ r.hi, P3L, P3H);
  lo = r.lo;
  hi = r.hi;
  shr(lo, hi, 32);
  r.lo ^= lo;
  r.hi ^= hi;
}

function avalanche3(lo, hi) {
  shr(lo, hi, 37);
  mul64(lo ^ r.lo, hi ^ r.hi, MX1L, MX1H);
  lo = r.lo;
  hi = r.hi;
  r.lo = lo ^ hi;
  r.hi = hi;
}

function rrmxmx(lo, hi, len) {
  rotl(lo, hi, 49);
  let xl = lo ^ r.lo;
  let xh = hi ^ r.hi;
  rotl(lo, hi, 24);
  mul64(xl ^ r.lo, xh ^ r.hi, MX2L, MX2H);
  lo = r.lo;
  hi = r.hi;
  shr(lo, hi, 35);
  add(r.lo, r.hi, len, 0);
  mul64(lo ^ r.lo, hi ^ r.hi, MX2L, MX2H);
  lo = r.lo;
  hi = r.hi;
  shr(lo, hi, 28);
  r.lo ^= lo;
  r.hi ^= hi;
}

/** fold64(a, b): the low and high halves of the 128-bit product, XORed. */
function fold64(alo, ahi, blo, bhi) {
  mul128(alo, ahi, blo, bhi);
  r.lo ^= r.lo2;
  r.hi ^= r.hi2;
}

/** mix16(in at a, secret at s, seed) */
function mix16(m, a, sec, s, slo, shi) {
  add(wordOf(sec, s), wordOf(sec, s + 4), slo, shi);
  const xl = word(m, a) ^ r.lo;
  const xh = word(m, a + 4) ^ r.hi;
  sub(wordOf(sec, s + 8), wordOf(sec, s + 12), slo, shi);
  fold64(xl, xh, word(m, a + 8) ^ r.lo, word(m, a + 12) ^ r.hi);
}

function accumulate512(acc, m, p, sec, s) {
  for (let i = 0; i < 8; i++) {
    const vlo = word(m, p + 8 * i);
    const vhi = word(m, p + 8 * i + 4);
    mul32(vlo ^ wordOf(sec, s + 8 * i), vhi ^ wordOf(sec, s + 8 * i + 4));
    const plo = r.lo;
    const phi = r.hi;
    const j = 2 * (i ^ 1);
    add(acc[j], acc[j + 1], vlo, vhi);
    acc[j] = r.lo;
    acc[j + 1] = r.hi;
    add(acc[2 * i], acc[2 * i + 1], plo, phi);
    acc[2 * i] = r.lo;
    acc[2 * i + 1] = r.hi;
  }
}

function scramble(acc, sec) {
  for (let i = 0; i < 8; i++) {
    const lo = acc[2 * i];
    const hi = acc[2 * i + 1];
    shr(lo, hi, 47);
    const k = SECRET_LEN - STRIPE + 8 * i;
    mul64(lo ^ r.lo ^ wordOf(sec, k), hi ^ r.hi ^ wordOf(sec, k + 4), P32_1, 0);
    acc[2 * i] = r.lo;
    acc[2 * i + 1] = r.hi;
  }
}

function block(acc, m, p, sec) {
  for (let n = 0; n < STRIPES; n++) {
    accumulate512(acc, m, p + n * STRIPE, sec, n * 8);
  }
  scramble(acc, sec);
}

/** The accumulators after the whole message (longer than 240 bytes). */
function finishAcc(state, tail, sec) {
  const acc = state.hash.slice(0, 16);
  const len = tail.length;
  const whole = Math.floor((len - 1) / BLOCK);
  for (let n = 0; n < whole; n++) {
    block(acc, tail, n * BLOCK, sec);
  }
  const start = whole * BLOCK;
  const stripes = Math.floor((len - 1 - start) / STRIPE);
  for (let n = 0; n < stripes; n++) {
    accumulate512(acc, tail, start + n * STRIPE, sec, n * 8);
  }
  accumulate512(acc, tail, len - STRIPE, sec, SECRET_LEN - STRIPE - 7);
  return acc;
}

function mergeAccs(acc, sec, s, startLo, startHi) {
  let lo = startLo;
  let hi = startHi;
  for (let i = 0; i < 4; i++) {
    fold64(acc[4 * i] ^ wordOf(sec, s + 16 * i), acc[4 * i + 1] ^ wordOf(sec, s + 16 * i + 4),
      acc[4 * i + 2] ^ wordOf(sec, s + 16 * i + 8), acc[4 * i + 3] ^ wordOf(sec, s + 16 * i + 12));
    add(lo, hi, r.lo, r.hi);
    lo = r.lo;
    hi = r.hi;
  }
  avalanche3(lo, hi);
}

/** The total length times a constant (`total` up to 2^53 - 1). */
function lenTimes(total, plo, phi) {
  fromNumber(total);
  mul64(r.lo, r.hi, plo, phi);
}

/** `seed ^ (bswap32(low 32 bits of seed) << 32)` */
function seedSwap(slo, shi) {
  r.lo = slo;
  r.hi = shi ^ bswap32(slo);
}

// ---- XXH3-64 ----------------------------------------------------------------

function short64(m, slo, shi) {
  const S = SECRET;
  const len = m.length;
  if (len === 0) {
    avalanche64(slo ^ wordOf(S, 56) ^ wordOf(S, 64), shi ^ wordOf(S, 60) ^ wordOf(S, 68));
    return;
  }
  if (len <= 3) {
    const c = (m.charCodeAt(0) << 16) | (m.charCodeAt(len >> 1) << 24) | m.charCodeAt(len - 1) | (len << 8);
    add(wordOf(S, 0) ^ wordOf(S, 4), 0, slo, shi);
    avalanche64(c ^ r.lo, r.hi);
    return;
  }
  if (len <= 8) {
    seedSwap(slo, shi);
    sub(wordOf(S, 8) ^ wordOf(S, 16), wordOf(S, 12) ^ wordOf(S, 20), r.lo, r.hi);
    const flo = r.lo;
    const fhi = r.hi;
    add(word(m, len - 4), 0, 0, word(m, 0));
    rrmxmx(r.lo ^ flo, r.hi ^ fhi, len);
    return;
  }
  if (len <= 16) {
    add(wordOf(S, 24) ^ wordOf(S, 32), wordOf(S, 28) ^ wordOf(S, 36), slo, shi);
    const lol = word(m, 0) ^ r.lo;
    const loh = word(m, 4) ^ r.hi;
    sub(wordOf(S, 40) ^ wordOf(S, 48), wordOf(S, 44) ^ wordOf(S, 52), slo, shi);
    const hil = word(m, len - 8) ^ r.lo;
    const hih = word(m, len - 4) ^ r.hi;
    fold64(lol, loh, hil, hih);
    const fl = r.lo;
    const fh = r.hi;
    add(len, 0, bswap32(loh), bswap32(lol));
    add(r.lo, r.hi, hil, hih);
    add(r.lo, r.hi, fl, fh);
    avalanche3(r.lo, r.hi);
    return;
  }
  lenTimes(len, P1L, P1H);
  let lo = r.lo;
  let hi = r.hi;
  const mix = (a, s) => {
    mix16(m, a, S, s, slo, shi);
    add(lo, hi, r.lo, r.hi);
    lo = r.lo;
    hi = r.hi;
  };
  if (len <= 128) {
    if (len > 32) {
      if (len > 64) {
        if (len > 96) {
          mix(48, 96);
          mix(len - 64, 112);
        }
        mix(32, 64);
        mix(len - 48, 80);
      }
      mix(16, 32);
      mix(len - 32, 48);
    }
    mix(0, 0);
    mix(len - 16, 16);
    avalanche3(lo, hi);
    return;
  }
  for (let i = 0; i < 8; i++) {
    mix(16 * i, 16 * i);
  }
  avalanche3(lo, hi);
  lo = r.lo;
  hi = r.hi;
  const rounds = Math.floor(len / 16);
  for (let i = 8; i < rounds; i++) {
    mix(16 * i, 16 * (i - 8) + 3);
  }
  mix(len - 16, 136 - 17);
  avalanche3(lo, hi);
}

function blocks(state, message, start, end) {
  const sec = secretOf(state.hash);
  const acc = state.hash;
  for (let p = start; p < end; p += BLOCK) {
    block(acc, message, p, sec);
  }
  state.counter += end - start;
}

export const xxh3 = {
  name: 'js',
  blocks: blocks,

  final(state, tail) {
    const total = state.counter + tail.length;
    if (total <= 240) {
      short64(tail, state.hash[16], state.hash[17]);
    } else {
      const sec = secretOf(state.hash);
      const acc = finishAcc(state, tail, sec);
      lenTimes(total, P1L, P1H);
      mergeAccs(acc, sec, 11, r.lo, r.hi);
    }
    return be32(r.hi) + be32(r.lo);
  }
};

// ---- XXH3-128 ---------------------------------------------------------------

// The two halves of the result of `short128` and `final`.
let outLo = [0, 0];
let outHi = [0, 0];

function mix32(acc, m, a, b, sec, s, slo, shi) {
  mix16(m, a, sec, s, slo, shi);
  add(acc[0], acc[1], r.lo, r.hi);
  let lo = r.lo;
  let hi = r.hi;
  add(word(m, b), word(m, b + 4), word(m, b + 8), word(m, b + 12));
  acc[0] = lo ^ r.lo;
  acc[1] = hi ^ r.hi;
  mix16(m, b, sec, s + 16, slo, shi);
  add(acc[2], acc[3], r.lo, r.hi);
  lo = r.lo;
  hi = r.hi;
  add(word(m, a), word(m, a + 4), word(m, a + 8), word(m, a + 12));
  acc[2] = lo ^ r.lo;
  acc[3] = hi ^ r.hi;
}

function short128(m, slo, shi) {
  const S = SECRET;
  const len = m.length;
  if (len === 0) {
    avalanche64(slo ^ wordOf(S, 64) ^ wordOf(S, 72), shi ^ wordOf(S, 68) ^ wordOf(S, 76));
    outLo = [r.lo, r.hi];
    avalanche64(slo ^ wordOf(S, 80) ^ wordOf(S, 88), shi ^ wordOf(S, 84) ^ wordOf(S, 92));
    outHi = [r.lo, r.hi];
    return;
  }
  if (len <= 3) {
    const cl = (m.charCodeAt(0) << 16) | (m.charCodeAt(len >> 1) << 24) | m.charCodeAt(len - 1) | (len << 8);
    rotl(bswap32(cl), 0, 13);
    // rotl32: the bits rotated past bit 31 are in r.hi.
    const ch = r.lo | r.hi;
    add(wordOf(S, 0) ^ wordOf(S, 4), 0, slo, shi);
    avalanche64(cl ^ r.lo, r.hi);
    outLo = [r.lo, r.hi];
    sub(wordOf(S, 8) ^ wordOf(S, 12), 0, slo, shi);
    avalanche64(ch ^ r.lo, r.hi);
    outHi = [r.lo, r.hi];
    return;
  }
  if (len <= 8) {
    seedSwap(slo, shi);
    add(wordOf(S, 16) ^ wordOf(S, 24), wordOf(S, 20) ^ wordOf(S, 28), r.lo, r.hi);
    const kl = word(m, 0) ^ r.lo;
    const kh = word(m, len - 4) ^ r.hi;
    add(P1L, P1H, len << 2, 0);
    mul128(kl, kh, r.lo, r.hi);
    let lo = r.lo;
    let lh = r.hi;
    const hl0 = r.lo2;
    const hh0 = r.hi2;
    shl(lo, lh, 1);
    add(hl0, hh0, r.lo, r.hi);
    const hl = r.lo;
    const hh = r.hi;
    shr(hl, hh, 3);
    lo ^= r.lo;
    lh ^= r.hi;
    shr(lo, lh, 35);
    mul64(lo ^ r.lo, lh ^ r.hi, MX2L, MX2H);
    lo = r.lo;
    lh = r.hi;
    shr(lo, lh, 28);
    outLo = [lo ^ r.lo, lh ^ r.hi];
    avalanche3(hl, hh);
    outHi = [r.lo, r.hi];
    return;
  }
  if (len <= 16) {
    sub(wordOf(S, 32) ^ wordOf(S, 40), wordOf(S, 36) ^ wordOf(S, 44), slo, shi);
    const fll = r.lo;
    const flh = r.hi;
    add(wordOf(S, 48) ^ wordOf(S, 56), wordOf(S, 52) ^ wordOf(S, 60), slo, shi);
    const fhl = r.lo;
    const fhh = r.hi;
    const inLl = word(m, 0);
    const inLh = word(m, 4);
    let inHl = word(m, len - 8);
    let inHh = word(m, len - 4);
    mul128(inLl ^ inHl ^ fll, inLh ^ inHh ^ flh, P1L, P1H);
    let ml = r.lo;
    let mlh = r.hi;
    let mh = r.lo2;
    let mhh = r.hi2;
    add(ml, mlh, 0, (len - 1) << 22);
    ml = r.lo;
    mlh = r.hi;
    inHl ^= fhl;
    inHh ^= fhh;
    mul32(inHl, P32_2 - 1);
    add(r.lo, r.hi, inHl, inHh);
    add(mh, mhh, r.lo, r.hi);
    mh = r.lo;
    mhh = r.hi;
    ml ^= bswap32(mhh);
    mlh ^= bswap32(mh);
    mul128(ml, mlh, P2L, P2H);
    const hl = r.lo;
    const hlh = r.hi;
    let hh = r.lo2;
    let hhh = r.hi2;
    mul64(mh, mhh, P2L, P2H);
    add(hh, hhh, r.lo, r.hi);
    hh = r.lo;
    hhh = r.hi;
    avalanche3(hl, hlh);
    outLo = [r.lo, r.hi];
    avalanche3(hh, hhh);
    outHi = [r.lo, r.hi];
    return;
  }
  lenTimes(len, P1L, P1H);
  const acc = [r.lo, r.hi, 0, 0];
  if (len <= 128) {
    if (len > 32) {
      if (len > 64) {
        if (len > 96) {
          mix32(acc, m, 48, len - 64, S, 96, slo, shi);
        }
        mix32(acc, m, 32, len - 48, S, 64, slo, shi);
      }
      mix32(acc, m, 16, len - 32, S, 32, slo, shi);
    }
    mix32(acc, m, 0, len - 16, S, 0, slo, shi);
  } else {
    for (let i = 0; i < 4; i++) {
      mix32(acc, m, 32 * i, 32 * i + 16, S, 32 * i, slo, shi);
    }
    avalanche3(acc[0], acc[1]);
    acc[0] = r.lo;
    acc[1] = r.hi;
    avalanche3(acc[2], acc[3]);
    acc[2] = r.lo;
    acc[3] = r.hi;
    const rounds = Math.floor(len / 32);
    for (let i = 4; i < rounds; i++) {
      mix32(acc, m, 32 * i, 32 * i + 16, S, 3 + 32 * (i - 4), slo, shi);
    }
    sub(0, 0, slo, shi);
    mix32(acc, m, len - 16, len - 32, S, 136 - 17 - 16, r.lo, r.hi);
  }
  add(acc[0], acc[1], acc[2], acc[3]);
  avalanche3(r.lo, r.hi);
  outLo = [r.lo, r.hi];
  mul64(acc[0], acc[1], P1L, P1H);
  let hl = r.lo;
  let hh = r.hi;
  mul64(acc[2], acc[3], P4L, P4H);
  add(hl, hh, r.lo, r.hi);
  hl = r.lo;
  hh = r.hi;
  sub(len, 0, slo, shi);
  mul64(r.lo, r.hi, P2L, P2H);
  add(hl, hh, r.lo, r.hi);
  avalanche3(r.lo, r.hi);
  sub(0, 0, r.lo, r.hi);
  outHi = [r.lo, r.hi];
}

export const xxh128 = {
  name: 'js',
  blocks: blocks,

  final(state, tail) {
    const total = state.counter + tail.length;
    if (total <= 240) {
      short128(tail, state.hash[16], state.hash[17]);
    } else {
      const sec = secretOf(state.hash);
      const acc = finishAcc(state, tail, sec);
      lenTimes(total, P1L, P1H);
      mergeAccs(acc, sec, 11, r.lo, r.hi);
      outLo = [r.lo, r.hi];
      lenTimes(total, P2L, P2H);
      mergeAccs(acc, sec, SECRET_LEN - STRIPE - 11, ~r.lo, ~r.hi);
      outHi = [r.lo, r.hi];
    }
    return be32(outHi[1]) + be32(outHi[0]) + be32(outLo[1]) + be32(outLo[0]);
  }
};
