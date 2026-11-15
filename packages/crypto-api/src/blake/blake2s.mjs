// crypto-api-ng:facade
'use strict';

/*
 * BLAKE2s in plain JavaScript (RFC 7693): the engine used when WebAssembly is
 * not available, and the reference the wasm engine is tested against. See
 * src/blake/blake2-base.mjs for how it is used.
 *
 * Engine interface (shared with src/wasm/blake2.mjs):
 *   blocks(state, message, start, end)  compress the whole blocks message[start, end)
 *   final(state, tail)                  the full 32-byte digest of the last block `tail`
 *
 * `state.hash` holds the eight chaining words as int32, `state.counter` the
 * number of bytes compressed so far.
 */

export const BLOCK = 64;
export const DIGEST = 32;
export const IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
].map((w) => w | 0);

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

const v = new Int32Array(16);
const m = new Int32Array(16);

function g(a, b, c, d, x, y) {
  let va = (v[a] + v[b] + x) | 0;
  let vd = v[d] ^ va;
  vd = (vd >>> 16) | (vd << 16);
  let vc = (v[c] + vd) | 0;
  let vb = v[b] ^ vc;
  vb = (vb >>> 12) | (vb << 20);
  va = (va + vb + y) | 0;
  vd ^= va;
  vd = (vd >>> 8) | (vd << 24);
  vc = (vc + vd) | 0;
  vb ^= vc;
  vb = (vb >>> 7) | (vb << 25);
  v[a] = va;
  v[b] = vb;
  v[c] = vc;
  v[d] = vd;
}

/**
 * The compression function F on the words `h`.
 *
 * @param {number[]} h - eight int32 chaining words, updated in place
 * @param {number} t - bytes compressed including this block
 * @param {boolean} last
 */
function compress(h, t, last) {
  for (let i = 0; i < 8; i++) {
    v[i] = h[i] | 0;
    v[i + 8] = IV[i];
  }
  v[12] ^= t % 4294967296;
  v[13] ^= Math.floor(t / 4294967296);
  if (last) {
    v[14] = ~v[14];
  }
  for (let r = 0; r < 10; r++) {
    const s = SIGMA[r];
    g(0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i++) {
    h[i] = (h[i] ^ v[i] ^ v[i + 8]) | 0;
  }
}

/** Load the 16 little-endian words of `message[pos, pos + len)` into `m`, zero padded. */
function load(message, pos, len) {
  for (let i = 0; i < 16; i++) {
    const p = pos + 4 * i;
    const e = pos + len;
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
    for (let i = 0; i < 8; i++) {
      const w = h[i];
      out += String.fromCharCode(w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, (w >>> 24) & 0xff);
    }
    return out;
  }
};
