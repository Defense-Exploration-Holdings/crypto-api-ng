// Shared locations for the parity harness.
//
// ORACLE  = the untouched original crypto-api 0.8.5 (the upstream checkout `crypto-api/`).
// TARGET  = the implementation under test: a package root that contains `src/`
//           with the same layout as the original. Defaults to
//           `packages/crypto-api`; override with CRYPTO_API_TARGET.
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const REPO_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
export const ORACLE_ROOT = join(REPO_ROOT, 'crypto-api');
export const ORACLE_SRC = join(ORACLE_ROOT, 'src');
export const ORACLE_TEST = join(ORACLE_ROOT, 'test');
export const VECTORS_DIR = join(REPO_ROOT, 'test', 'vectors');
export const DEFAULT_TARGET = join(REPO_ROOT, 'packages', 'crypto-api');

export function targetRoot() {
  const env = process.env.CRYPTO_API_TARGET;
  return env ? resolve(REPO_ROOT, env) : DEFAULT_TARGET;
}

export function assertOracleCheckedOut() {
  if (!existsSync(join(ORACLE_SRC, 'hasher', 'md5.mjs'))) {
    throw new Error(
      'The upstream crypto-api checkout is missing. Run: scripts/fetch-upstream.sh'
    );
  }
}

export function assertTargetExists() {
  const root = targetRoot();
  if (!existsSync(join(root, 'src', 'hasher', 'md5.mjs'))) {
    throw new Error(
      `No implementation under test at ${root} (expected src/hasher/md5.mjs). ` +
      'Run `node scripts/vendor-legacy.mjs` or set CRYPTO_API_TARGET.'
    );
  }
}

export const fileUrl = (p) => pathToFileURL(p).href;
