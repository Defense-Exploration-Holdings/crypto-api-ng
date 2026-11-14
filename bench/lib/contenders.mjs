// Builds the things that get timed, for one named variant (test/harness/catalog.mjs VARIANTS):
//
//   orig   crypto-api 0.8.5 through its public API (string in, string out)
//   v1     this port through the same API
//   raw    the v1 wasm module called directly with a Uint8Array: the ceiling a
//          bytes-in/bytes-out v2 API could reach (not a v1 API; see docs/benchmarks.md)
//   node   node:crypto, where OpenSSL has the algorithm (a reference, not a competitor)
//
// Every contender is checked against the original's digest before it is timed.
import { VARIANTS } from '../../test/harness/catalog.mjs';

export { VARIANTS };

/** Wasm module family and init arguments for the `raw` contender. */
const RAW = {
  md2: ['md2', 'md2', [18], 16],
  md4: ['md', 'md4', [0], 16],
  md5: ['md', 'md5', [], 16],
  has160: ['has160', 'has160', [80], 20],
  ripemd128: ['ripemd', 'ripemd128', [0], 16],
  ripemd160: ['ripemd', 'ripemd160', [0], 20],
  ripemd256: ['ripemd', 'ripemd256', [0], 32],
  ripemd320: ['ripemd', 'ripemd320', [0], 40],
  sha0: ['sha1', 'sha0', [80], 20],
  sha1: ['sha1', 'sha1', [80], 20],
  sha224: ['sha256', 'sha256', [224, 64], 28],
  sha256: ['sha256', 'sha256', [256, 64], 32],
  sha384: ['sha512', 'sha512', [384, 160], 48],
  sha512: ['sha512', 'sha512', [512, 160], 64],
  'sha512-224': ['sha512', 'sha512', [224, 160], 28],
  'sha512-256': ['sha512', 'sha512', [256, 160], 32],
  sm3: ['sm3', 'sm3', [64], 32],
  'snefru128-2': ['snefru', 'snefru', [4, 2], 16],
  'snefru128-8': ['snefru', 'snefru', [4, 8], 16],
  'snefru256-4': ['snefru', 'snefru', [8, 4], 32],
  'snefru256-8': ['snefru', 'snefru', [8, 8], 32],
  whirlpool: ['whirlpool', 'whirlpool', [10], 64],
  'whirlpool-0': ['whirlpool', 'whirlpool0', [10], 64],
  'whirlpool-t': ['whirlpool', 'whirlpoolt', [10], 64],
};

/** wasmBytesOf(family) -> Uint8Array. Supplied by the runner (fs in Node, fetch in a browser). */
export function makeRaw(variant, wasmBytesOf) {
  const spec = RAW[variant.id];
  if (!spec) return null;
  const [family, prefix, args, digestLen] = spec;
  const inst = new WebAssembly.Instance(new WebAssembly.Module(wasmBytesOf(family)), {});
  const ex = inst.exports;
  const u8 = new Uint8Array(ex.memory.buffer);
  const base = ex.scratch_ptr();
  const inOff = base + 256;
  const cap = ex.scratch_len() - 256;
  const init = ex[`${prefix}_init`];
  const update = ex[`${prefix}_update`];
  const final = ex[`${prefix}_final`];
  return (bytes, chunk) => {
    init(base, ...args);
    const step = Math.min(chunk || cap, cap);
    for (let off = 0; off < bytes.length; off += step) {
      const n = Math.min(step, bytes.length - off);
      u8.set(bytes.subarray(off, off + n), inOff);
      update(base, inOff, n);
    }
    // `final` never reads the input region, and SHA-512/Whirlpool states overlap +128, so use +256.
    final(base, inOff);
    return u8.slice(inOff, inOff + digestLen);
  };
}

/** `() => Uint8Array digest` factory for node:crypto, or null. */
export function makeNode(variant, createHash) {
  if (!variant.openssl || !createHash) return null;
  try {
    createHash(variant.openssl);
  } catch {
    return null;
  }
  return (bytes, chunk) => {
    const h = createHash(variant.openssl);
    if (!chunk) h.update(bytes);
    else for (let off = 0; off < bytes.length; off += chunk) h.update(bytes.subarray(off, off + chunk));
    return h.digest();
  };
}

/** Deterministic pseudo-random bytes (xorshift32), identical in every run and environment. */
export function makeBytes(n, seed = 0x9e3779b9) {
  const u8 = new Uint8Array(n);
  let x = seed | 0;
  for (let i = 0; i < n; i++) {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    u8[i] = x & 0xff;
  }
  return u8;
}

/** The original API takes binary strings (one char per byte). */
export function binaryString(u8) {
  const parts = [];
  for (let i = 0; i < u8.length; i += 8192) {
    parts.push(String.fromCharCode.apply(null, u8.subarray(i, i + 8192)));
  }
  return parts.join('');
}

export function hexOfBinary(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) out += (s.charCodeAt(i) & 0xff).toString(16).padStart(2, '0');
  return out;
}

export function hexOfBytes(u8) {
  let out = '';
  for (let i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, '0');
  return out;
}

export function chunksOf(s, size) {
  const out = [];
  for (let i = 0; i < s.length; i += size) out.push(s.slice(i, i + size));
  return out;
}
