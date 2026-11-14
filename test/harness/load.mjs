// Loads the oracle (original crypto-api) and the target (implementation under
// test) through the same resolve hook, exposing both with the same shape.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ensureHook } from './register.mjs';
import {
  ORACLE_SRC, targetRoot, assertOracleCheckedOut, assertTargetExists,
} from './paths.mjs';
import { FAMILIES, BASE_CLASSES } from './catalog.mjs';

ensureHook();

async function loadTree(srcDir, label) {
  const imp = (rel) => import(pathToFileURL(join(srcDir, rel)).href);
  const hashers = {};
  for (const f of FAMILIES) hashers[f.className] = (await imp(`hasher/${f.file}.mjs`)).default;
  const bases = {};
  for (const b of BASE_CLASSES) bases[b.className] = (await imp(`hasher/${b.file}.mjs`)).default;
  return {
    label,
    srcDir,
    hashers,
    bases,
    Hmac: (await imp('mac/hmac.mjs')).default,
    fromUtf: (await imp('encoder/utf.mjs')).fromUtf,
    fromArrayBuffer: (await imp('encoder/array-buffer.mjs')).fromArrayBuffer,
    toHex: (await imp('encoder/hex.mjs')).toHex,
    toBase64: (await imp('encoder/base64.mjs')).toBase64,
    tools: await imp('tools/tools.mjs'),
    CryptoApi: (await imp('crypto-api.mjs')).default,
    imp,
  };
}

let oraclePromise;
let targetPromise;

/** The untouched original crypto-api 0.8.5. */
export function loadOracle() {
  assertOracleCheckedOut();
  return (oraclePromise ??= loadTree(ORACLE_SRC, 'oracle'));
}

/** The implementation under test (CRYPTO_API_TARGET, default packages/crypto-api). */
export function loadTarget() {
  assertTargetExists();
  return (targetPromise ??= loadTree(join(targetRoot(), 'src'), 'target'));
}

export async function loadBoth() {
  return { oracle: await loadOracle(), target: await loadTarget() };
}

/** Construct a hasher. Callers pass a fresh object: the original mutates (and keeps) its options argument. */
export function make(api, family, options) {
  const Cls = api.hashers[family.className];
  return options === undefined ? new Cls() : new Cls(options);
}
