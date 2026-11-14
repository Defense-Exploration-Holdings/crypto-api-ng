// Loads the two implementations being compared, without any resolve hook:
//
//   orig  crypto-api 0.8.5, the `crypto-api/` checkout copied to bench/.cache with ".mjs"
//         appended to relative import specifiers (the only change; same rewrite as
//         scripts/vendor-legacy.mjs, and what a bundler does for real users). Node's
//         loader hook is avoided on purpose: it adds a per-import cost the original
//         would not pay in a bundled app, which would skew the cold-start numbers.
//   v1    packages/crypto-api (facades over wasm, verbatim legacy engines as fallback)
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { rewriteSpecifiers, listOriginalFiles } from '../../scripts/vendor-legacy.mjs';

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const ORIG_SRC = join(REPO, 'bench', '.cache', 'crypto-api-0.8.5', 'src');
export const V1_SRC = join(REPO, 'packages', 'crypto-api', 'src');

export const HASHER_FILES = [
  'has160', 'md2', 'md4', 'md5', 'ripemd', 'sha0', 'sha1', 'sha256', 'sha512', 'sm3', 'snefru', 'whirlpool',
];

/** Writes bench/.cache/crypto-api-0.8.5/src. Returns its path. */
export function prepareOriginal() {
  const srcDir = join(REPO, 'crypto-api', 'src');
  if (!existsSync(join(srcDir, 'hasher', 'md5.mjs'))) {
    throw new Error('crypto-api/ checkout missing. Run: scripts/fetch-upstream.sh');
  }
  for (const rel of listOriginalFiles()) {
    const dest = join(ORIG_SRC, rel);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, rewriteSpecifiers(readFileSync(join(srcDir, rel), 'utf8'), rel, 'src'));
  }
  return ORIG_SRC;
}

export function assertV1Built() {
  if (!existsSync(join(REPO, 'packages', 'crypto-api', 'wasm', 'md.mjs'))) {
    throw new Error('Embedded wasm missing. Run: zig build js --release=small');
  }
}

const url = (p) => pathToFileURL(p).href;

/** Loads one tree: { hashers: {file -> class}, Hmac, CryptoApi, fromUtf, toHex }. */
export async function loadTree(srcDir, importer = (p) => import(url(p))) {
  const imp = (rel) => importer(join(srcDir, rel));
  const hashers = {};
  for (const f of HASHER_FILES) hashers[f] = (await imp(`hasher/${f}.mjs`)).default;
  return {
    dir: srcDir,
    hashers,
    Hmac: (await imp('mac/hmac.mjs')).default,
    CryptoApi: (await imp('crypto-api.mjs')).default,
    fromUtf: (await imp('encoder/utf.mjs')).fromUtf,
    toHex: (await imp('encoder/hex.mjs')).toHex,
  };
}

export async function loadBoth() {
  prepareOriginal();
  assertV1Built();
  return { orig: await loadTree(ORIG_SRC), v1: await loadTree(V1_SRC) };
}
