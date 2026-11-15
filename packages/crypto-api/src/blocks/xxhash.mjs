// crypto-api-ng:facade
'use strict';

/*
 * XXH32 and XXH64 in plain JavaScript: the engines used when WebAssembly is not available, and
 * the reference the wasm engines are tested against. See src/blocks/base.mjs for how they are
 * used and src/hash/xxhash.zig for the algorithm.
 *
 * Engine interface (shared with src/wasm/blocks.mjs):
 *   blocks(state, message, start, end)  process the whole stripes message[start, end)
 *   final(state, tail)                  the hash (4 or 8 bytes, most significant first) of the last stripe `tail`
 *
 * XXH32: `state.hash` is the four accumulators and the seed (five int32). XXH64: the four
 * accumulators and the seed as 64-bit words, low half first (ten int32). `state.counter` is
 * the number of bytes processed so far.
 */

const TWO32 = 4294967296;

// ---- XXH32 ------------------------------------------------------------------

const P32_1 = 0x9E3779B1 | 0;
const P32_2 = 0x85EBCA77 | 0;
const P32_3 = 0xC2B2AE3D | 0;
const P32_4 = 0x27D4EB2F | 0;
const P32_5 = 0x165667B1 | 0;

const rotl32 = (x, n) => (x << n) | (x >>> (32 - n));

/** The accumulators for `seed` (0 to 2^32 - 1): the initial `state.hash` of XXH32. */
export function iv32(seed) {
  const s = seed | 0;
  return [(s + P32_1 + P32_2) | 0, (s + P32_2) | 0, s, (s - P32_1) | 0, s];
}

const word32 = (m, p) => m.charCodeAt(p) | (m.charCodeAt(p + 1) << 8) | (m.charCodeAt(p + 2) << 16) | (m.charCodeAt(p + 3) << 24);

const round32 = (acc, lane) => Math.imul(rotl32((acc + Math.imul(lane, P32_2)) | 0, 13), P32_1);

export const xxhash32 = {
  name: 'js',

  blocks(state, message, start, end) {
    const hash = state.hash;
    let v1 = hash[0];
    let v2 = hash[1];
    let v3 = hash[2];
    let v4 = hash[3];
    for (let p = start; p < end; p += 16) {
      v1 = round32(v1, word32(message, p));
      v2 = round32(v2, word32(message, p + 4));
      v3 = round32(v3, word32(message, p + 8));
      v4 = round32(v4, word32(message, p + 12));
    }
    hash[0] = v1;
    hash[1] = v2;
    hash[2] = v3;
    hash[3] = v4;
    state.counter += end - start;
  },

  final(state, tail) {
    let v1 = state.hash[0];
    let v2 = state.hash[1];
    let v3 = state.hash[2];
    let v4 = state.hash[3];
    let pos = 0;
    if (tail.length === 16) {
      v1 = round32(v1, word32(tail, 0));
      v2 = round32(v2, word32(tail, 4));
      v3 = round32(v3, word32(tail, 8));
      v4 = round32(v4, word32(tail, 12));
      pos = 16;
    }
    const total = state.counter + tail.length;
    let h = total >= 16 ?
      (rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)) | 0 :
      (state.hash[4] + P32_5) | 0;
    h = (h + (total % TWO32)) | 0;
    for (; pos + 4 <= tail.length; pos += 4) {
      h = Math.imul(rotl32((h + Math.imul(word32(tail, pos), P32_3)) | 0, 17), P32_4);
    }
    for (; pos < tail.length; pos++) {
      h = Math.imul(rotl32((h + Math.imul(tail.charCodeAt(pos), P32_5)) | 0, 11), P32_1);
    }
    h ^= h >>> 15;
    h = Math.imul(h, P32_2);
    h ^= h >>> 13;
    h = Math.imul(h, P32_3);
    h ^= h >>> 16;
    return String.fromCharCode((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff);
  }
};

// ---- XXH64 ------------------------------------------------------------------

// 64-bit constants as low and high int32.
const P1L = 0x85EBCA87 | 0;
const P1H = 0x9E3779B1 | 0;
const P2L = 0x27D4EB4F | 0;
const P2H = 0xC2B2AE3D | 0;
const P3L = 0x9E3779F9 | 0;
const P3H = 0x165667B1 | 0;
const P4L = 0xC2B2AE63 | 0;
const P4H = 0x85EBCA77 | 0;
const P5L = 0x165667C5 | 0;
const P5H = 0x27D4EB2F | 0;

// Results of the 64-bit helpers below (low and high int32).
let rl = 0;
let rh = 0;

function add(alo, ahi, blo, bhi) {
  const lo = (alo >>> 0) + (blo >>> 0);
  rl = lo | 0;
  rh = (ahi + bhi + (lo > 0xffffffff ? 1 : 0)) | 0;
}

function mul(alo, ahi, blo, bhi) {
  const a48 = ahi >>> 16;
  const a32 = ahi & 0xffff;
  const a16 = alo >>> 16;
  const a00 = alo & 0xffff;
  const b48 = bhi >>> 16;
  const b32 = bhi & 0xffff;
  const b16 = blo >>> 16;
  const b00 = blo & 0xffff;
  let c48 = 0;
  let c32 = 0;
  let c16 = 0;
  let c00 = a00 * b00;
  c16 += c00 >>> 16;
  c00 &= 0xffff;
  c16 += a16 * b00;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c16 += a00 * b16;
  c32 += c16 >>> 16;
  c16 &= 0xffff;
  c32 += a32 * b00;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c32 += a16 * b16;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c32 += a00 * b32;
  c48 += c32 >>> 16;
  c32 &= 0xffff;
  c48 += a48 * b00 + a32 * b16 + a16 * b32 + a00 * b48;
  c48 &= 0xffff;
  rl = (c16 << 16) | c00;
  rh = (c48 << 16) | c32;
}

/** Rotate left by `n`, 1 to 31. */
function rotl(lo, hi, n) {
  rl = (lo << n) | (hi >>> (32 - n));
  rh = (hi << n) | (lo >>> (32 - n));
}

/** Logical shift right by `n`, 1 to 63. */
function shr(lo, hi, n) {
  if (n >= 32) {
    rl = n === 32 ? hi : hi >>> (n - 32);
    rh = 0;
  } else {
    rl = (lo >>> n) | (hi << (32 - n));
    rh = hi >>> n;
  }
}

/** round(acc, lane) = rotl(acc + lane * P2, 31) * P1 */
function round64(alo, ahi, llo, lhi) {
  mul(llo, lhi, P2L, P2H);
  add(alo, ahi, rl, rh);
  rotl(rl, rh, 31);
  mul(rl, rh, P1L, P1H);
}

/** merge(h, v) = (h ^ round(0, v)) * P1 + P4 */
function merge64(hlo, hhi, vlo, vhi) {
  round64(0, 0, vlo, vhi);
  mul(hlo ^ rl, hhi ^ rh, P1L, P1H);
  add(rl, rh, P4L, P4H);
}

/** The accumulators and the seed for `seed` (0 to 2^53 - 1): the initial `state.hash` of XXH64. */
export function iv64(seed) {
  const slo = seed % TWO32 | 0;
  const shi = Math.floor(seed / TWO32) | 0;
  const out = [];
  add(slo, shi, P1L, P1H);
  add(rl, rh, P2L, P2H);
  out.push(rl, rh);
  add(slo, shi, P2L, P2H);
  out.push(rl, rh);
  out.push(slo, shi);
  // seed - P1 = seed + (2^64 - P1) = seed + ~P1 + 1
  add(slo, shi, ~P1L, ~P1H);
  add(rl, rh, 1, 0);
  out.push(rl, rh);
  out.push(slo, shi);
  return out;
}

const word64lo = word32;

export const xxhash64 = {
  name: 'js',

  blocks(state, message, start, end) {
    const hash = state.hash;
    for (let p = start; p < end; p += 32) {
      for (let i = 0; i < 4; i++) {
        round64(hash[2 * i], hash[2 * i + 1], word64lo(message, p + 8 * i), word32(message, p + 8 * i + 4));
        hash[2 * i] = rl;
        hash[2 * i + 1] = rh;
      }
    }
    state.counter += end - start;
  },

  final(state, tail) {
    const v = state.hash.slice(0, 8);
    let pos = 0;
    if (tail.length === 32) {
      for (let i = 0; i < 4; i++) {
        round64(v[2 * i], v[2 * i + 1], word32(tail, 8 * i), word32(tail, 8 * i + 4));
        v[2 * i] = rl;
        v[2 * i + 1] = rh;
      }
      pos = 32;
    }
    const total = state.counter + tail.length;
    let hlo;
    let hhi;
    if (total >= 32) {
      rotl(v[0], v[1], 1);
      hlo = rl;
      hhi = rh;
      for (const [i, n] of [[1, 7], [2, 12], [3, 18]]) {
        rotl(v[2 * i], v[2 * i + 1], n);
        add(hlo, hhi, rl, rh);
        hlo = rl;
        hhi = rh;
      }
      for (let i = 0; i < 4; i++) {
        merge64(hlo, hhi, v[2 * i], v[2 * i + 1]);
        hlo = rl;
        hhi = rh;
      }
    } else {
      add(state.hash[8], state.hash[9], P5L, P5H);
      hlo = rl;
      hhi = rh;
    }
    add(hlo, hhi, total % TWO32 | 0, Math.floor(total / TWO32) | 0);
    hlo = rl;
    hhi = rh;
    for (; pos + 8 <= tail.length; pos += 8) {
      round64(0, 0, word32(tail, pos), word32(tail, pos + 4));
      rotl(hlo ^ rl, hhi ^ rh, 27);
      mul(rl, rh, P1L, P1H);
      add(rl, rh, P4L, P4H);
      hlo = rl;
      hhi = rh;
    }
    if (pos + 4 <= tail.length) {
      mul(word32(tail, pos), 0, P1L, P1H);
      rotl(hlo ^ rl, hhi ^ rh, 23);
      mul(rl, rh, P2L, P2H);
      add(rl, rh, P3L, P3H);
      hlo = rl;
      hhi = rh;
      pos += 4;
    }
    for (; pos < tail.length; pos++) {
      mul(tail.charCodeAt(pos), 0, P5L, P5H);
      rotl(hlo ^ rl, hhi ^ rh, 11);
      mul(rl, rh, P1L, P1H);
      hlo = rl;
      hhi = rh;
    }
    // Avalanche.
    shr(hlo, hhi, 33);
    mul(hlo ^ rl, hhi ^ rh, P2L, P2H);
    hlo = rl;
    hhi = rh;
    shr(hlo, hhi, 29);
    mul(hlo ^ rl, hhi ^ rh, P3L, P3H);
    hlo = rl;
    hhi = rh;
    shr(hlo, hhi, 32);
    hlo ^= rl;
    hhi ^= rh;
    return String.fromCharCode(
      (hhi >>> 24) & 0xff, (hhi >>> 16) & 0xff, (hhi >>> 8) & 0xff, hhi & 0xff,
      (hlo >>> 24) & 0xff, (hlo >>> 16) & 0xff, (hlo >>> 8) & 0xff, hlo & 0xff
    );
  }
};
