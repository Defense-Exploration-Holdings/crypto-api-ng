// crypto-api-ng:facade
'use strict';

import blake2b, {IV} from "../blake/blake2b.mjs";

/*
 * Argon2d, Argon2i and Argon2id (RFC 9106, version 0x13) in plain JavaScript: the
 * engine used when WebAssembly is not available, and the reference the wasm module
 * (src/kdf/argon2.zig) is tested against. It follows the Zig core step by step.
 *
 * 64-bit words are int32 pairs, low half first: block `b` of the memory matrix is
 * `mem[256 b, 256 b + 256)`. The matrix is zeroed before `derive` returns.
 */

const TWO32 = 4294967296;
const SYNC_POINTS = 4;
const VERSION = 0x13;

// ---- BLAKE2b and H' over the plain-JavaScript BLAKE2b engine -----------------

/** BLAKE2b with an `outLen`-byte digest (1..64) of the binary string `msg`. */
function blake2bString(outLen, msg) {
  const state = {hash: IV.slice(), counter: 0};
  // Parameter block: digest length, no key, fanout 1, depth 1.
  state.hash[0] ^= outLen | 0x01010000;
  const tailStart = msg.length === 0 ? 0 : msg.length - ((msg.length - 1) % 128 + 1);
  blake2b.blocks(state, msg, 0, tailStart);
  return blake2b.final(state, msg.substr(tailStart)).substr(0, outLen);
}

function le32(x) {
  return String.fromCharCode(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff);
}

/** The variable-length hash H' of RFC 9106 section 3.3, as a binary string of `outLen` bytes. */
function hPrime(outLen, input) {
  let v = blake2bString(Math.min(outLen, 64), le32(outLen) + input);
  if (outLen <= 64) {
    return v;
  }
  const r = Math.ceil(outLen / 32) - 2;
  let out = v.substr(0, 32);
  for (let i = 1; i < r; i++) {
    v = blake2bString(64, v);
    out += v.substr(0, 32);
  }
  return out + blake2bString(outLen - 32 * r, v);
}

/** Binary string of a `Uint8Array`. */
function bytesToString(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  }
  return s;
}

// ---- the compression function G ----------------------------------------------

// Result of `bla`, the low and high halves.
let RL = 0;
let RH = 0;
// Result of `mulHi`.
let MH = 0;

/** High 32 bits of the 64-bit product of two unsigned 32-bit numbers, into `MH`; returns the low 32 bits. */
function mul(a, b) {
  const a0 = a & 0xffff, a1 = a >>> 16, b0 = b & 0xffff, b1 = b >>> 16;
  const p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
  const mid = (p00 >>> 16) + (p01 & 0xffff) + (p10 & 0xffff);
  MH = (p11 + (p01 >>> 16) + (p10 >>> 16) + (mid >>> 16)) >>> 0;
  return ((mid << 16) | (p00 & 0xffff)) >>> 0;
}

/** fBlaMka: x + y + 2 * lo(x) * lo(y) mod 2^64, into `RL`, `RH`. */
function bla(xl, xh, yl, yh) {
  const ml = mul(xl >>> 0, yl >>> 0);
  const mh = MH;
  const lo = (xl >>> 0) + (yl >>> 0) + ((ml << 1) >>> 0);
  RL = lo | 0;
  RH = (xh + yh + ((mh << 1) | (ml >>> 31)) + Math.floor(lo / TWO32)) | 0;
}

/** GB on the words at indices `a`, `b`, `c`, `d` of `R` (word `w` is `R[2w]`, `R[2w + 1]`). */
function gb(R, a, b, c, d) {
  a <<= 1;
  b <<= 1;
  c <<= 1;
  d <<= 1;
  let al = R[a], ah = R[a + 1], bl = R[b], bh = R[b + 1];
  let cl = R[c], ch = R[c + 1], dl = R[d], dh = R[d + 1];
  let t;
  // a = a + b + 2ab; d = (d ^ a) >>> 32
  bla(al, ah, bl, bh);
  al = RL;
  ah = RH;
  t = dl ^ al;
  dl = dh ^ ah;
  dh = t;
  // c = c + d + 2cd; b = (b ^ c) >>> 24
  bla(cl, ch, dl, dh);
  cl = RL;
  ch = RH;
  bl ^= cl;
  bh ^= ch;
  t = (bl >>> 24) | (bh << 8);
  bh = (bh >>> 24) | (bl << 8);
  bl = t;
  // a = a + b + 2ab; d = (d ^ a) >>> 16
  bla(al, ah, bl, bh);
  al = RL;
  ah = RH;
  dl ^= al;
  dh ^= ah;
  t = (dl >>> 16) | (dh << 16);
  dh = (dh >>> 16) | (dl << 16);
  dl = t;
  // c = c + d + 2cd; b = (b ^ c) >>> 63
  bla(cl, ch, dl, dh);
  cl = RL;
  ch = RH;
  bl ^= cl;
  bh ^= ch;
  t = (bl << 1) | (bh >>> 31);
  bh = (bh << 1) | (bl >>> 31);
  bl = t;
  R[a] = al;
  R[a + 1] = ah;
  R[b] = bl;
  R[b + 1] = bh;
  R[c] = cl;
  R[c + 1] = ch;
  R[d] = dl;
  R[d + 1] = dh;
}

/** P on 16 words of `R` given by `w(k)`, k = 0..15. */
function permute(R, w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15) {
  gb(R, w0, w4, w8, w12);
  gb(R, w1, w5, w9, w13);
  gb(R, w2, w6, w10, w14);
  gb(R, w3, w7, w11, w15);
  gb(R, w0, w5, w10, w15);
  gb(R, w1, w6, w11, w12);
  gb(R, w2, w7, w8, w13);
  gb(R, w3, w4, w9, w14);
}

const R = new Int32Array(256);
const T = new Int32Array(256);

/**
 * out[o, o + 256) = G(x[xo...], y[yo...]), XORed into the old value when `xor`.
 * `out` may be `y` (with `xor` false).
 */
function fillBlock(x, xo, y, yo, out, oo, xor) {
  for (let i = 0; i < 256; i++) {
    R[i] = x[xo + i] ^ y[yo + i];
  }
  if (xor) {
    for (let i = 0; i < 256; i++) {
      T[i] = R[i] ^ out[oo + i];
    }
  } else {
    T.set(R);
  }
  for (let i = 0; i < 8; i++) {
    const b = 16 * i;
    permute(R, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
      b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
  }
  for (let i = 0; i < 8; i++) {
    const b = 2 * i;
    permute(R, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
      b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
  }
  for (let i = 0; i < 256; i++) {
    out[oo + i] = T[i] ^ R[i];
  }
}

/** Load the 1024-byte binary string `s` as block words at `mem[o...]`. */
function loadBlock(mem, o, s) {
  for (let i = 0; i < 256; i++) {
    const p = 4 * i;
    mem[o + i] = s.charCodeAt(p) | (s.charCodeAt(p + 1) << 8) | (s.charCodeAt(p + 2) << 16) | (s.charCodeAt(p + 3) << 24);
  }
}

// ---- the memory matrix -------------------------------------------------------

const ZERO = new Int32Array(256);
const INPUT = new Int32Array(256);
const ADDRESS = new Int32Array(256);

function nextAddresses() {
  INPUT[12] = (INPUT[12] + 1) | 0;
  fillBlock(ZERO, 0, INPUT, 0, ADDRESS, 0, false);
  fillBlock(ZERO, 0, ADDRESS, 0, ADDRESS, 0, false);
}

function fillSegment(mem, blocks, t, p, mode, pass, lane, slice) {
  const laneLen = blocks / p;
  const segLen = laneLen / SYNC_POINTS;
  const independent = mode === 1 || (mode === 2 && pass === 0 && slice < 2);
  if (independent) {
    INPUT.fill(0);
    ADDRESS.fill(0);
    INPUT[0] = pass;
    INPUT[2] = lane;
    INPUT[4] = slice;
    INPUT[6] = blocks % TWO32 | 0;
    INPUT[7] = Math.floor(blocks / TWO32);
    INPUT[8] = t | 0;
    INPUT[10] = mode;
  }
  let start = 0;
  if (pass === 0 && slice === 0) {
    start = 2;
    if (independent) {
      nextAddresses();
    }
  }
  let cur = lane * laneLen + slice * segLen + start;
  let prev = cur % laneLen === 0 ? cur + laneLen - 1 : cur - 1;
  for (let i = start; i < segLen; i++, cur++, prev++) {
    if (cur % laneLen === 1) {
      prev = cur - 1;
    }
    let j1, j2;
    if (independent) {
      if (i % 128 === 0) {
        nextAddresses();
      }
      j1 = ADDRESS[2 * (i % 128)] >>> 0;
      j2 = ADDRESS[2 * (i % 128) + 1] >>> 0;
    } else {
      j1 = mem[256 * prev] >>> 0;
      j2 = mem[256 * prev + 1] >>> 0;
    }
    const refLane = pass === 0 && slice === 0 ? lane : j2 % p;
    const same = refLane === lane;
    let area;
    if (pass === 0) {
      if (slice === 0) {
        area = i - 1;
      } else if (same) {
        area = slice * segLen + i - 1;
      } else {
        area = slice * segLen - (i === 0 ? 1 : 0);
      }
    } else if (same) {
      area = laneLen - segLen + i - 1;
    } else {
      area = laneLen - segLen - (i === 0 ? 1 : 0);
    }
    mul(j1, j1);
    mul(area, MH);
    const rel = area - 1 - MH;
    const startPos = pass !== 0 && slice !== SYNC_POINTS - 1 ? (slice + 1) * segLen : 0;
    const ref = refLane * laneLen + (startPos + rel) % laneLen;
    fillBlock(mem, 256 * prev, mem, 256 * ref, mem, 256 * cur, pass !== 0);
  }
}

/**
 * Derive an Argon2 tag. The parameters are already checked by the caller (see
 * src/kdf/argon2.mjs): `t` >= 1, 1 <= `p` < 2^24, `m` >= 8 `p`, `outLen` >= 4.
 *
 * @param {number} mode - 0 Argon2d, 1 Argon2i, 2 Argon2id
 * @param {number} t - passes
 * @param {number} m - memory in KiB
 * @param {number} p - lanes
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {Uint8Array} secret
 * @param {Uint8Array} ad
 * @param {number} outLen - tag length in bytes
 * @returns {Uint8Array}
 * @throws {RangeError} when the memory matrix cannot be allocated
 */
export function derive(mode, t, m, p, password, salt, secret, ad, outLen) {
  const blocks = 4 * p * Math.floor(m / (4 * p));
  const laneLen = blocks / p;
  let mem;
  try {
    mem = new Int32Array(256 * blocks);
  } catch (e) {
    throw new RangeError('Argon2: cannot allocate ' + blocks + ' KiB');
  }
  try {
    const h0 = blake2bString(64, le32(p) + le32(outLen) + le32(m) + le32(t) + le32(VERSION) + le32(mode) +
      le32(password.length) + bytesToString(password) + le32(salt.length) + bytesToString(salt) +
      le32(secret.length) + bytesToString(secret) + le32(ad.length) + bytesToString(ad));
    for (let lane = 0; lane < p; lane++) {
      loadBlock(mem, 256 * lane * laneLen, hPrime(1024, h0 + le32(0) + le32(lane)));
      loadBlock(mem, 256 * (lane * laneLen + 1), hPrime(1024, h0 + le32(1) + le32(lane)));
    }
    for (let pass = 0; pass < t; pass++) {
      for (let slice = 0; slice < SYNC_POINTS; slice++) {
        for (let lane = 0; lane < p; lane++) {
          fillSegment(mem, blocks, t, p, mode, pass, lane, slice);
        }
      }
    }
    let c = '';
    for (let i = 0; i < 256; i++) {
      let w = 0;
      for (let lane = 0; lane < p; lane++) {
        w ^= mem[256 * (lane * laneLen + laneLen - 1) + i];
      }
      c += le32(w);
    }
    const tag = hPrime(outLen, c);
    const out = new Uint8Array(outLen);
    for (let i = 0; i < outLen; i++) {
      out[i] = tag.charCodeAt(i);
    }
    return out;
  } finally {
    mem.fill(0);
    R.fill(0);
    T.fill(0);
    INPUT.fill(0);
    ADDRESS.fill(0);
  }
}
