// crypto-api-ng:facade
'use strict';

/*
 * 64-bit arithmetic on int32 pairs (low half, high half) for the plain-JavaScript engines of
 * XXH3, SipHash and MurmurHash3. Every function writes its result to `r` (`r.lo`, `r.hi`;
 * `mul128` also sets `r.lo2`, `r.hi2`, the high 64 bits of the product) and returns nothing, so
 * no objects are allocated in the inner loops. Callers copy the result out before the next call.
 */

/** The result of the last call. */
export const r = {lo: 0, hi: 0, lo2: 0, hi2: 0};

const TWO32 = 4294967296;

export function add(alo, ahi, blo, bhi) {
  const lo = (alo >>> 0) + (blo >>> 0);
  r.lo = lo | 0;
  r.hi = (ahi + bhi + (lo >= TWO32 ? 1 : 0)) | 0;
}

export function sub(alo, ahi, blo, bhi) {
  const lo = (alo >>> 0) - (blo >>> 0);
  r.lo = lo | 0;
  r.hi = (ahi - bhi - (lo < 0 ? 1 : 0)) | 0;
}

/** The full 64-bit product of two unsigned 32-bit numbers. */
export function mul32(a, b) {
  const a0 = a & 0xffff;
  const a1 = a >>> 16;
  const b0 = b & 0xffff;
  const b1 = b >>> 16;
  const mid = a1 * b0 + a0 * b1;
  const low = a0 * b0 + (mid % 65536) * 65536;
  r.lo = low | 0;
  r.hi = (a1 * b1 + Math.floor(mid / 65536) + Math.floor(low / TWO32)) | 0;
}

/** The low 64 bits of the product. */
export function mul64(alo, ahi, blo, bhi) {
  mul32(alo, blo);
  r.hi = (r.hi + Math.imul(alo, bhi) + Math.imul(ahi, blo)) | 0;
}

/** The full 128-bit product: low 64 bits in `r.lo`, `r.hi`, high 64 bits in `r.lo2`, `r.hi2`. */
export function mul128(alo, ahi, blo, bhi) {
  mul32(alo, blo);
  const w0 = r.lo;
  const ll1 = r.hi >>> 0;
  mul32(alo, bhi);
  const lh0 = r.lo >>> 0;
  const lh1 = r.hi >>> 0;
  mul32(ahi, blo);
  const hl0 = r.lo >>> 0;
  const hl1 = r.hi >>> 0;
  mul32(ahi, bhi);
  const hh0 = r.lo >>> 0;
  const hh1 = r.hi >>> 0;
  const s1 = ll1 + lh0 + hl0;
  const c1 = Math.floor(s1 / TWO32);
  const s2 = hh0 + lh1 + hl1 + c1;
  const c2 = Math.floor(s2 / TWO32);
  r.lo = w0;
  r.hi = s1 | 0;
  r.lo2 = s2 | 0;
  r.hi2 = (hh1 + c2) | 0;
}

/** Rotate left by `n`, 0 to 63. */
export function rotl(lo, hi, n) {
  if (n >= 32) {
    const t = lo;
    lo = hi;
    hi = t;
    n -= 32;
  }
  if (n === 0) {
    r.lo = lo;
    r.hi = hi;
    return;
  }
  r.lo = (lo << n) | (hi >>> (32 - n));
  r.hi = (hi << n) | (lo >>> (32 - n));
}

/** Logical shift right by `n`, 1 to 63. */
export function shr(lo, hi, n) {
  if (n >= 32) {
    r.lo = n === 32 ? hi : hi >>> (n - 32);
    r.hi = 0;
  } else {
    r.lo = (lo >>> n) | (hi << (32 - n));
    r.hi = hi >>> n;
  }
}

/** Shift left by `n`, 1 to 63. */
export function shl(lo, hi, n) {
  if (n >= 32) {
    r.hi = n === 32 ? lo : lo << (n - 32);
    r.lo = 0;
  } else {
    r.hi = (hi << n) | (lo >>> (32 - n));
    r.lo = lo << n;
  }
}

/** Reverse the bytes of a 32-bit number. */
export function bswap32(x) {
  return ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x >>> 8) & 0xff00) | (x >>> 24);
}

/** Little-endian 32-bit word of the binary string `m` at `p`. */
export function word(m, p) {
  return m.charCodeAt(p) | (m.charCodeAt(p + 1) << 8) | (m.charCodeAt(p + 2) << 16) | (m.charCodeAt(p + 3) << 24);
}

/** Little-endian 32-bit word of the byte array `b` at `p`. */
export function wordOf(b, p) {
  return b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24);
}

/** The number `n` (0 to 2^53 - 1) as `r.lo`, `r.hi`. */
export function fromNumber(n) {
  r.lo = n % TWO32 | 0;
  r.hi = Math.floor(n / TWO32) | 0;
}

/** The bytes of a 32-bit number, most significant first, as a binary string. */
export function be32(x) {
  return String.fromCharCode((x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff);
}

/** The bytes of a 32-bit number, least significant first, as a binary string. */
export function le32(x) {
  return String.fromCharCode(x & 0xff, (x >>> 8) & 0xff, (x >>> 16) & 0xff, (x >>> 24) & 0xff);
}
