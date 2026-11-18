// crypto-api-ng:facade
'use strict';

/*
 * scrypt (RFC 7914) in plain JavaScript: the engine used when WebAssembly is not
 * available, and the reference the wasm module (src/kdf/scrypt.zig) is tested
 * against. It carries its own small SHA-256 so that an application importing only
 * scrypt does not also load the SHA-256 wasm module.
 *
 * The work memory (B, V, X, Y) is zeroed before `derive` returns.
 */

// ---- SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256 with one iteration -----------

const K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const W = new Int32Array(64);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

/** Compress the 64-byte block `bytes[o, o + 64)` into `h`. */
function compress(h, bytes, o) {
  for (let i = 0; i < 16; i++) {
    const p = o + 4 * i;
    W[i] = (bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3];
  }
  for (let i = 16; i < 64; i++) {
    const a = W[i - 15], b = W[i - 2];
    const s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3);
    const s1 = rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
  for (let i = 0; i < 64; i++) {
    const t1 = (k + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
    const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    k = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }
  h[0] = (h[0] + a) | 0;
  h[1] = (h[1] + b) | 0;
  h[2] = (h[2] + c) | 0;
  h[3] = (h[3] + d) | 0;
  h[4] = (h[4] + e) | 0;
  h[5] = (h[5] + f) | 0;
  h[6] = (h[6] + g) | 0;
  h[7] = (h[7] + k) | 0;
}

/** Streaming SHA-256 over `Uint8Array` input. */
class Sha {
  constructor() {
    this.h = new Int32Array(IV);
    this.buf = new Uint8Array(64);
    this.n = 0;
    this.length = 0;
  }

  clone() {
    const c = new Sha();
    c.h.set(this.h);
    c.buf.set(this.buf);
    c.n = this.n;
    c.length = this.length;
    return c;
  }

  update(bytes) {
    this.length += bytes.length;
    let i = 0;
    if (this.n > 0) {
      while (this.n < 64 && i < bytes.length) {
        this.buf[this.n++] = bytes[i++];
      }
      if (this.n < 64) {
        return;
      }
      compress(this.h, this.buf, 0);
      this.n = 0;
    }
    for (; i + 64 <= bytes.length; i += 64) {
      compress(this.h, bytes, i);
    }
    while (i < bytes.length) {
      this.buf[this.n++] = bytes[i++];
    }
  }

  /** The digest; the hasher is wiped. */
  digest() {
    const bits = this.length * 8;
    const pad = new Uint8Array((this.n < 56 ? 64 : 128) - this.n);
    pad[0] = 0x80;
    const hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
    const e = pad.length;
    pad[e - 8] = hi >>> 24;
    pad[e - 7] = hi >>> 16;
    pad[e - 6] = hi >>> 8;
    pad[e - 5] = hi;
    pad[e - 4] = lo >>> 24;
    pad[e - 3] = lo >>> 16;
    pad[e - 2] = lo >>> 8;
    pad[e - 1] = lo;
    this.update(pad);
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[4 * i] = this.h[i] >>> 24;
      out[4 * i + 1] = this.h[i] >>> 16;
      out[4 * i + 2] = this.h[i] >>> 8;
      out[4 * i + 3] = this.h[i];
    }
    this.h.fill(0);
    this.buf.fill(0);
    return out;
  }
}

/** PBKDF2-HMAC-SHA-256 with one iteration, `outLen` bytes. */
function pbkdf2(password, salt, outLen) {
  let key = password;
  if (key.length > 64) {
    const s = new Sha();
    s.update(key);
    key = s.digest();
  }
  const pad = new Uint8Array(64);
  const inner = new Sha();
  const outer = new Sha();
  pad.set(key);
  for (let i = 0; i < 64; i++) {
    pad[i] ^= 0x36;
  }
  inner.update(pad);
  for (let i = 0; i < 64; i++) {
    pad[i] ^= 0x36 ^ 0x5c;
  }
  outer.update(pad);
  pad.fill(0);
  if (key !== password) {
    key.fill(0);
  }
  inner.update(salt);
  const out = new Uint8Array(outLen);
  const counter = new Uint8Array(4);
  for (let block = 1, pos = 0; pos < outLen; block++, pos += 32) {
    counter[0] = block >>> 24;
    counter[1] = block >>> 16;
    counter[2] = block >>> 8;
    counter[3] = block;
    const i = inner.clone();
    i.update(counter);
    const ih = i.digest();
    const o = outer.clone();
    o.update(ih);
    ih.fill(0);
    const t = o.digest();
    out.set(t.subarray(0, Math.min(32, outLen - pos)), pos);
    t.fill(0);
  }
  inner.digest();
  outer.digest();
  return out;
}

// ---- Salsa20/8, BlockMix, ROMix ----------------------------------------------

const X16 = new Int32Array(16);

function rotl(x, n) {
  return (x << n) | (x >>> (32 - n));
}

/** Salsa20/8 core on `b[o, o + 16)`, in place. */
function salsa8(b, o) {
  const x = X16;
  for (let i = 0; i < 16; i++) {
    x[i] = b[o + i];
  }
  for (let i = 0; i < 8; i += 2) {
    x[4] ^= rotl(x[0] + x[12], 7); x[8] ^= rotl(x[4] + x[0], 9);
    x[12] ^= rotl(x[8] + x[4], 13); x[0] ^= rotl(x[12] + x[8], 18);
    x[9] ^= rotl(x[5] + x[1], 7); x[13] ^= rotl(x[9] + x[5], 9);
    x[1] ^= rotl(x[13] + x[9], 13); x[5] ^= rotl(x[1] + x[13], 18);
    x[14] ^= rotl(x[10] + x[6], 7); x[2] ^= rotl(x[14] + x[10], 9);
    x[6] ^= rotl(x[2] + x[14], 13); x[10] ^= rotl(x[6] + x[2], 18);
    x[3] ^= rotl(x[15] + x[11], 7); x[7] ^= rotl(x[3] + x[15], 9);
    x[11] ^= rotl(x[7] + x[3], 13); x[15] ^= rotl(x[11] + x[7], 18);
    x[1] ^= rotl(x[0] + x[3], 7); x[2] ^= rotl(x[1] + x[0], 9);
    x[3] ^= rotl(x[2] + x[1], 13); x[0] ^= rotl(x[3] + x[2], 18);
    x[6] ^= rotl(x[5] + x[4], 7); x[7] ^= rotl(x[6] + x[5], 9);
    x[4] ^= rotl(x[7] + x[6], 13); x[5] ^= rotl(x[4] + x[7], 18);
    x[11] ^= rotl(x[10] + x[9], 7); x[8] ^= rotl(x[11] + x[10], 9);
    x[9] ^= rotl(x[8] + x[11], 13); x[10] ^= rotl(x[9] + x[8], 18);
    x[12] ^= rotl(x[15] + x[14], 7); x[13] ^= rotl(x[12] + x[15], 9);
    x[14] ^= rotl(x[13] + x[12], 13); x[15] ^= rotl(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; i++) {
    b[o + i] = (b[o + i] + x[i]) | 0;
  }
  x.fill(0);
}

/** Y = BlockMix(X): `x` and `y` are 32 r words at `xo`, `yo` of `xy`. */
function blockMix(xy, xo, yo, r) {
  const s = new Int32Array(16);
  for (let k = 0; k < 16; k++) {
    s[k] = xy[xo + (2 * r - 1) * 16 + k];
  }
  for (let i = 0; i < 2 * r; i++) {
    for (let k = 0; k < 16; k++) {
      s[k] ^= xy[xo + i * 16 + k];
    }
    salsa8(s, 0);
    const at = yo + ((i >> 1) + (i & 1) * r) * 16;
    for (let k = 0; k < 16; k++) {
      xy[at + k] = s[k];
    }
  }
  s.fill(0);
}

function roMix(b, bo, v, xy, r, n) {
  const len = 32 * r;
  for (let k = 0; k < len; k++) {
    xy[k] = b[bo + k];
  }
  for (let i = 0; i < n; i++) {
    v.set(xy.subarray(0, len), i * len);
    blockMix(xy, 0, len, r);
    xy.copyWithin(0, len, 2 * len);
  }
  const lastLo = (2 * r - 1) * 16;
  for (let i = 0; i < n; i++) {
    // Integerify: N is a power of two below 2^32 here (V would not fit otherwise).
    const j = (xy[lastLo] >>> 0) % n;
    const vo = j * len;
    for (let k = 0; k < len; k++) {
      xy[k] ^= v[vo + k];
    }
    blockMix(xy, 0, len, r);
    xy.copyWithin(0, len, 2 * len);
  }
  for (let k = 0; k < len; k++) {
    b[bo + k] = xy[k];
  }
}

/**
 * Derive a scrypt key. The parameters are already checked by the caller (see
 * src/kdf/scrypt.mjs): `n` a power of two from 2, `r` and `p` from 1, r p < 2^30.
 *
 * @param {number} n - cost N
 * @param {number} r - block size
 * @param {number} p - parallelization
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} outLen - bytes
 * @returns {Uint8Array}
 * @throws {RangeError} when the work memory cannot be allocated
 */
export function derive(n, r, p, password, salt, outLen) {
  const len = 32 * r;
  let v, xy, b;
  try {
    v = new Int32Array(len * n);
    xy = new Int32Array(2 * len);
  } catch (e) {
    throw new RangeError('scrypt: cannot allocate ' + (128 * r * n) + ' bytes');
  }
  const bytes = pbkdf2(password, salt, 128 * r * p);
  try {
    b = new Int32Array(len * p);
    for (let i = 0; i < b.length; i++) {
      const o = 4 * i;
      b[i] = bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24);
    }
    for (let i = 0; i < p; i++) {
      roMix(b, i * len, v, xy, r, n);
    }
    for (let i = 0; i < b.length; i++) {
      const w = b[i], o = 4 * i;
      bytes[o] = w;
      bytes[o + 1] = w >>> 8;
      bytes[o + 2] = w >>> 16;
      bytes[o + 3] = w >>> 24;
    }
    return pbkdf2(password, bytes, outLen);
  } finally {
    v.fill(0);
    xy.fill(0);
    bytes.fill(0);
    if (b) {
      b.fill(0);
    }
  }
}
