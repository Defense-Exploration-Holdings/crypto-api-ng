// The per-algorithm entry points of the npm package (the `exports` map of packages/crypto-api/package.json).
//
// `exports` is the source of truth for what exists. This file adds what the README table and the tests need:
// which algorithms each entry covers. test/package/exports.test.js fails when the three disagree, so a new
// algorithm cannot ship without an entry, a description and a README row.
//
// Adding an algorithm: add `"./<name>"` to `exports` (and `typesVersions`) in packages/crypto-api/package.json,
// add its line below, then `node scripts/size-report.mjs --write` to refresh the README table.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const PKG_ROOT = join(REPO_ROOT, 'packages', 'crypto-api');

/** Entry (subpath without `./`) -> what it provides. Row order of the README table. */
export const ENTRY_ALGORITHMS = {
  md2: 'MD2',
  md4: 'MD4',
  md5: 'MD5',
  has160: 'HAS-160',
  ripemd: 'RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320',
  sha0: 'SHA-0',
  sha1: 'SHA-1',
  sha256: 'SHA-224, SHA-256',
  sha512: 'SHA-384, SHA-512, SHA-512/224, SHA-512/256',
  sha3: 'SHA3-224, SHA3-256, SHA3-384, SHA3-512',
  shake: 'SHAKE128, SHAKE256',
  keccak: 'Keccak-224, Keccak-256, Keccak-384, Keccak-512',
  blake2b: 'BLAKE2b',
  blake2s: 'BLAKE2s',
  blake3: 'BLAKE3',
  sm3: 'SM3',
  snefru: 'Snefru 128/256',
  whirlpool: 'Whirlpool, Whirlpool-0, Whirlpool-T',
  hmac: 'HMAC (takes any hasher object)',
  'encoder/hex': 'toHex',
  'encoder/base64': 'toBase64',
  'encoder/utf': 'fromUtf',
  'encoder/array-buffer': 'fromArrayBuffer',
};

export function readPackageJson() {
  return JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8'));
}

/** The named entry points in `exports`: `{ name, target }` for every `./<name>` that is not a pattern or a file path. */
export function entriesFromExports(pkg = readPackageJson()) {
  const out = [];
  for (const [key, value] of Object.entries(pkg.exports)) {
    if (key === '.' || key.includes('*') || /\.(json|js|mjs|cjs|ts|mts)$/.test(key)) continue;
    const target = typeof value === 'string' ? value : value.default;
    out.push({ name: key.slice(2), target, types: typeof value === 'string' ? undefined : value.types });
  }
  return out;
}
