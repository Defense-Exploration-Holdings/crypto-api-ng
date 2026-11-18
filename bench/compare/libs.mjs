// The libraries compared in bench/compare, and how each one hashes a Uint8Array in one call.
//
// Every entry returns { algorithm id: (bytes: Uint8Array) => digest }. The digest can be any of
// the shapes `toHex()` below understands; it is converted to hex only to verify it, never while
// timing. Each function does what a user of that library writes for "hash these bytes", with the
// fastest documented call that takes a Uint8Array:
//
//   crypto-api-ng  new Hasher(options), update(bytes), digest()
//   node:crypto    createHash(name).update(bytes).digest()
//   hash-wasm      one hasher from createXXX() made up front, then init(), update(bytes),
//                  digest('binary') per call (its documented fast path; the async one-shot
//                  helpers cannot be timed synchronously)
//   @noble/hashes  sha256(bytes)
//   js-sha*, js-md5  sha256.arrayBuffer(bytes)
//   hash.js        hash.sha256().update(bytes).digest()
//   crypto-js      CryptoJS.SHA256(CryptoJS.lib.WordArray.create(bytes)); the conversion to a
//                  WordArray is included because crypto-js cannot take bytes any other way
//   xxhash-wasm    h32Raw(bytes) / h64Raw(bytes) from the instance made up front
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const NG = new URL('../../packages/crypto-api/src/hasher/', import.meta.url);

/** Algorithms in report order. `node` is the node:crypto name; `bits` the digest size. */
export const ALGORITHMS = [
  { id: 'md5', label: 'MD5', node: 'md5' },
  { id: 'sha1', label: 'SHA-1', node: 'sha1' },
  { id: 'sha256', label: 'SHA-256', node: 'sha256' },
  { id: 'sha512', label: 'SHA-512', node: 'sha512' },
  { id: 'sha3-256', label: 'SHA3-256', node: 'sha3-256' },
  { id: 'keccak256', label: 'Keccak-256' },
  { id: 'blake2b512', label: 'BLAKE2b-512', node: 'blake2b512' },
  { id: 'blake2s256', label: 'BLAKE2s-256', node: 'blake2s256' },
  { id: 'blake3', label: 'BLAKE3' },
  { id: 'ripemd160', label: 'RIPEMD-160', node: 'ripemd160' },
  { id: 'md4', label: 'MD4', node: 'md4' },
  { id: 'sm3', label: 'SM3', node: 'sm3' },
  { id: 'whirlpool', label: 'Whirlpool', node: 'whirlpool' },
  { id: 'crc32', label: 'CRC-32' },
  { id: 'xxhash64', label: 'xxHash64' },
];

const version = (pkg) => {
  try {
    return require(`${pkg}/package.json`).version;
  } catch {
    return null;
  }
};

const ngHasher = async (file, options) => {
  const Cls = (await import(new URL(`${file}.mjs`, NG).href)).default;
  return options ? (b) => { const h = new Cls({ ...options }); h.update(b); return h.digest(); }
    : (b) => { const h = new Cls(); h.update(b); return h.digest(); };
};

export const LIBRARIES = [
  {
    name: 'crypto-api-ng',
    kind: 'wasm',
    subject: true,
    version: () => require('../../packages/crypto-api/package.json').version,
    async setup() {
      return {
        md5: await ngHasher('md5'),
        sha1: await ngHasher('sha1'),
        sha256: await ngHasher('sha256'),
        sha512: await ngHasher('sha512'),
        'sha3-256': await ngHasher('sha3', { length: 256 }),
        keccak256: await ngHasher('keccak', { length: 256 }),
        blake2b512: await ngHasher('blake2b'),
        blake2s256: await ngHasher('blake2s'),
        blake3: await ngHasher('blake3'),
        ripemd160: await ngHasher('ripemd'),
        md4: await ngHasher('md4'),
        sm3: await ngHasher('sm3'),
        whirlpool: await ngHasher('whirlpool'),
        crc32: await ngHasher('crc32'),
        xxhash64: await ngHasher('xxhash64'),
      };
    },
  },
  {
    // Not a public API: the same wasm modules called directly with a Uint8Array (bench/lib/contenders.mjs
    // makeRaw). It shows how much of crypto-api-ng's time is the JavaScript around the wasm.
    name: 'crypto-api-ng wasm core',
    short: 'ng core',
    kind: 'wasm',
    informational: true,
    version: () => require('../../packages/crypto-api/package.json').version,
    async setup() {
      const { makeRaw } = await import('../lib/contenders.mjs');
      const bytesOf = {};
      const wasmBytesOf = (family) => bytesOf[family];
      const out = {};
      const map = { md5: 'md5', sha1: 'sha1', sha256: 'sha256', sha512: 'sha512', ripemd160: 'ripemd160', md4: 'md4', sm3: 'sm3', whirlpool: 'whirlpool' };
      const family = { md5: 'md', md4: 'md', sha1: 'sha1', sha256: 'sha256', sha512: 'sha512', ripemd160: 'ripemd', sm3: 'sm3', whirlpool: 'whirlpool' };
      for (const [id, variant] of Object.entries(map)) {
        const f = family[id];
        bytesOf[f] ??= (await import(new URL(`../../packages/crypto-api/wasm/${f}.mjs`, import.meta.url).href)).wasmBytes();
        const fn = makeRaw({ id: variant }, wasmBytesOf);
        if (fn) out[id] = (b) => fn(b, 0);
      }
      return out;
    },
  },
  {
    name: 'node:crypto',
    kind: 'native',
    reference: true,
    version: () => (typeof Deno !== 'undefined' ? `deno ${Deno.version.deno}`
      : typeof Bun !== 'undefined' ? `bun ${Bun.version}` : `node ${process.versions.node}`),
    async setup() {
      let createHash;
      try {
        ({ createHash } = await import('node:crypto'));
      } catch {
        return {};
      }
      const out = {};
      for (const a of ALGORITHMS) {
        if (!a.node) continue;
        try {
          createHash(a.node).update(new Uint8Array(1)).digest();
        } catch {
          continue; // not in this runtime's OpenSSL/BoringSSL build (or a legacy provider is off)
        }
        out[a.id] = (b) => createHash(a.node).update(b).digest();
      }
      return out;
    },
  },
  {
    name: 'hash-wasm',
    kind: 'wasm',
    version: () => version('hash-wasm'),
    async setup() {
      const hw = await import('hash-wasm');
      const reuse = async (p) => {
        const h = await p;
        return (b) => { h.init(); h.update(b); return h.digest('binary'); };
      };
      return {
        md5: await reuse(hw.createMD5()),
        sha1: await reuse(hw.createSHA1()),
        sha256: await reuse(hw.createSHA256()),
        sha512: await reuse(hw.createSHA512()),
        'sha3-256': await reuse(hw.createSHA3(256)),
        keccak256: await reuse(hw.createKeccak(256)),
        blake2b512: await reuse(hw.createBLAKE2b(512)),
        blake2s256: await reuse(hw.createBLAKE2s(256)),
        blake3: await reuse(hw.createBLAKE3(256)),
        ripemd160: await reuse(hw.createRIPEMD160()),
        md4: await reuse(hw.createMD4()),
        sm3: await reuse(hw.createSM3()),
        whirlpool: await reuse(hw.createWhirlpool()),
        crc32: await reuse(hw.createCRC32()),
        xxhash64: await reuse(hw.createXXHash64()),
      };
    },
  },
  {
    name: '@noble/hashes',
    kind: 'js',
    version: () => version('@noble/hashes'),
    async setup() {
      const sha2 = await import('@noble/hashes/sha2.js');
      const sha3 = await import('@noble/hashes/sha3.js');
      const blake2 = await import('@noble/hashes/blake2.js');
      const blake3 = await import('@noble/hashes/blake3.js');
      const legacy = await import('@noble/hashes/legacy.js');
      return {
        md5: legacy.md5,
        sha1: legacy.sha1,
        sha256: sha2.sha256,
        sha512: sha2.sha512,
        'sha3-256': sha3.sha3_256,
        keccak256: sha3.keccak_256,
        blake2b512: blake2.blake2b,
        blake2s256: blake2.blake2s,
        blake3: blake3.blake3,
        ripemd160: legacy.ripemd160,
      };
    },
  },
  {
    name: 'js-sha256 / js-sha512 / js-sha3 / js-sha1 / js-md5',
    short: 'js-sha*',
    kind: 'js',
    version: () => ['js-sha256', 'js-sha512', 'js-sha3', 'js-sha1', 'js-md5'].map((p) => `${p} ${version(p)}`).join(', '),
    async setup() {
      const { sha256 } = require('js-sha256');
      const { sha512 } = require('js-sha512');
      const { sha3_256: s3, keccak256 } = require('js-sha3');
      const sha1 = require('js-sha1');
      const md5 = require('js-md5');
      return {
        md5: (b) => md5.arrayBuffer(b),
        sha1: (b) => sha1.arrayBuffer(b),
        sha256: (b) => sha256.arrayBuffer(b),
        sha512: (b) => sha512.arrayBuffer(b),
        'sha3-256': (b) => s3.arrayBuffer(b),
        keccak256: (b) => keccak256.arrayBuffer(b),
      };
    },
  },
  {
    name: 'hash.js',
    kind: 'js',
    version: () => version('hash.js'),
    async setup() {
      const hash = require('hash.js');
      return {
        sha1: (b) => hash.sha1().update(b).digest(),
        sha256: (b) => hash.sha256().update(b).digest(),
        sha512: (b) => hash.sha512().update(b).digest(),
        ripemd160: (b) => hash.ripemd160().update(b).digest(),
      };
    },
  },
  {
    name: 'crypto-js',
    kind: 'js',
    version: () => version('crypto-js'),
    async setup() {
      const C = require('crypto-js');
      const wa = (b) => C.lib.WordArray.create(b);
      return {
        md5: (b) => C.MD5(wa(b)),
        sha1: (b) => C.SHA1(wa(b)),
        sha256: (b) => C.SHA256(wa(b)),
        sha512: (b) => C.SHA512(wa(b)),
        // CryptoJS.SHA3 is Keccak with the original padding, not FIPS 202 SHA-3.
        keccak256: (b) => C.SHA3(wa(b), { outputLength: 256 }),
        ripemd160: (b) => C.RIPEMD160(wa(b)),
      };
    },
  },
  {
    name: 'xxhash-wasm',
    kind: 'wasm',
    version: () => version('xxhash-wasm'),
    async setup() {
      const x = await (await import('xxhash-wasm')).default();
      return { xxhash64: (b) => x.h64Raw(b) };
    },
  },
];

/** Normalizes any library's digest to lowercase hex. */
export function toHex(d) {
  if (typeof d === 'bigint') return d.toString(16).padStart(16, '0');
  if (typeof d === 'number') return (d >>> 0).toString(16).padStart(8, '0');
  if (typeof d === 'string') return d.toLowerCase();
  if (d && Array.isArray(d.words) && typeof d.sigBytes === 'number') return d.toString(); // crypto-js
  let u8;
  if (d instanceof ArrayBuffer) u8 = new Uint8Array(d);
  else if (ArrayBuffer.isView(d)) u8 = new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  else if (Array.isArray(d)) u8 = Uint8Array.from(d);
  else throw new TypeError(`unknown digest shape: ${Object.prototype.toString.call(d)}`);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0');
  return s;
}
