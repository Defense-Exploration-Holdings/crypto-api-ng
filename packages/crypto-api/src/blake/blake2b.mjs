// crypto-api-ng:facade
'use strict';

/*
 * BLAKE2b in plain JavaScript (RFC 7693): the engine used when WebAssembly is
 * not available, and the reference the wasm engine is tested against. See
 * src/blake/blake2-base.mjs for how it is used. The interface is the one of
 * blake2s.mjs.
 *
 * 64-bit words are pairs of int32, the low half first: `state.hash` has
 * sixteen entries, `hash[2 * i]` and `hash[2 * i + 1]` being the low and high
 * halves of chaining word `i`. `state.counter` is the number of bytes
 * compressed so far (the 128-bit counter of BLAKE2b is only ever below 2^53).
 */

export const BLOCK = 128;
export const DIGEST = 64;
// [high, low] of the IV words (the SHA-512 initial hash value).
const IV_PAIRS = [
  [0x6a09e667, 0xf3bcc908], [0xbb67ae85, 0x84caa73b], [0x3c6ef372, 0xfe94f82b], [0xa54ff53a, 0x5f1d36f1],
  [0x510e527f, 0xade682d1], [0x9b05688c, 0x2b3e6c1f], [0x1f83d9ab, 0xfb41bd6b], [0x5be0cd19, 0x137e2179]
];
/** The IV as the int32 pairs `state.hash` uses, low half first. */
export const IV = [];
IV_PAIRS.forEach((p) => {
  IV.push(p[1] | 0, p[0] | 0);
});

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
];

const TWO32 = 4294967296;
// Working vector and message words: lo at 2 * i, hi at 2 * i + 1.
const v = new Int32Array(32);
const m = new Int32Array(32);

function g(a, b, c, d, x, y) {
  const a2 = 2 * a, b2 = 2 * b, c2 = 2 * c, d2 = 2 * d;
  const xl = m[2 * x], xh = m[2 * x + 1], yl = m[2 * y], yh = m[2 * y + 1];
  let al = v[a2], ah = v[a2 + 1], bl = v[b2], bh = v[b2 + 1];
  let cl = v[c2], ch = v[c2 + 1], dl = v[d2], dh = v[d2 + 1];
  let lo, t;

  // a = a + b + x
  lo = (al >>> 0) + (bl >>> 0) + (xl >>> 0);
  ah = (ah + bh + xh + Math.floor(lo / TWO32)) | 0;
  al = lo | 0;
  // d = (d ^ a) >>> 32
  t = dl ^ al;
  dl = dh ^ ah;
  dh = t;
  // c = c + d
  lo = (cl >>> 0) + (dl >>> 0);
  ch = (ch + dh + Math.floor(lo / TWO32)) | 0;
  cl = lo | 0;
  // b = (b ^ c) >>> 24
  bl ^= cl;
  bh ^= ch;
  t = (bl >>> 24) | (bh << 8);
  bh = (bh >>> 24) | (bl << 8);
  bl = t;
  // a = a + b + y
  lo = (al >>> 0) + (bl >>> 0) + (yl >>> 0);
  ah = (ah + bh + yh + Math.floor(lo / TWO32)) | 0;
  al = lo | 0;
  // d = (d ^ a) >>> 16
  dl ^= al;
  dh ^= ah;
  t = (dl >>> 16) | (dh << 16);
  dh = (dh >>> 16) | (dl << 16);
  dl = t;
  // c = c + d
  lo = (cl >>> 0) + (dl >>> 0);
  ch = (ch + dh + Math.floor(lo / TWO32)) | 0;
  cl = lo | 0;
  // b = (b ^ c) >>> 63, i.e. rotated left by one
  bl ^= cl;
  bh ^= ch;
  t = (bl << 1) | (bh >>> 31);
  bh = (bh << 1) | (bl >>> 31);
  bl = t;

  v[a2] = al; v[a2 + 1] = ah;
  v[b2] = bl; v[b2 + 1] = bh;
  v[c2] = cl; v[c2 + 1] = ch;
  v[d2] = dl; v[d2 + 1] = dh;
}

/**
 * The compression function F on the words `h`.
 *
 * @param {number[]} h - sixteen int32 (eight 64-bit words, low half first), updated in place
 * @param {number} t - bytes compressed including this block
 * @param {boolean} last
 */
function compress(h, t, last) {
  for (let i = 0; i < 16; i++) {
    v[i] = h[i] | 0;
    v[i + 16] = IV[i];
  }
  v[24] ^= t % TWO32;
  v[25] ^= Math.floor(t / TWO32);
  if (last) {
    v[28] = ~v[28];
    v[29] = ~v[29];
  }
  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r % 10];
    g(0, 4, 8, 12, s[0], s[1]);
    g(1, 5, 9, 13, s[2], s[3]);
    g(2, 6, 10, 14, s[4], s[5]);
    g(3, 7, 11, 15, s[6], s[7]);
    g(0, 5, 10, 15, s[8], s[9]);
    g(1, 6, 11, 12, s[10], s[11]);
    g(2, 7, 8, 13, s[12], s[13]);
    g(3, 4, 9, 14, s[14], s[15]);
  }
  for (let i = 0; i < 16; i++) {
    h[i] = (h[i] ^ v[i] ^ v[i + 16]) | 0;
  }
}

/** Load the 16 little-endian 64-bit words of `message[pos, pos + len)` into `m`, zero padded. */
function load(message, pos, len) {
  const e = pos + len;
  for (let i = 0; i < 32; i++) {
    const p = pos + 4 * i;
    m[i] = (p < e ? message.charCodeAt(p) : 0) |
      ((p + 1 < e ? message.charCodeAt(p + 1) : 0) << 8) |
      ((p + 2 < e ? message.charCodeAt(p + 2) : 0) << 16) |
      ((p + 3 < e ? message.charCodeAt(p + 3) : 0) << 24);
  }
}

export default {
  name: 'js',

  blocks(state, message, start, end) {
    const h = state.hash;
    for (let pos = start; pos < end; pos += BLOCK) {
      load(message, pos, BLOCK);
      state.counter += BLOCK;
      compress(h, state.counter, false);
    }
  },

  final(state, tail) {
    const h = state.hash.slice();
    load(tail, 0, tail.length);
    compress(h, state.counter + tail.length, true);
    let out = '';
    for (let i = 0; i < 16; i++) {
      const w = h[i];
      out += String.fromCharCode(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff);
    }
    return out;
  }
};
