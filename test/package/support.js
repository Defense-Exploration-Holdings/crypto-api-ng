// Shared helpers for the packaging tests (test/package/*.test.js).
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import { REPO_ROOT } from '../harness/paths.mjs';

export const PKG_ROOT = join(REPO_ROOT, 'packages', 'crypto-api');
export const SCRIPTS = join(REPO_ROOT, 'scripts');

/**
 * Generate the bundles and example vectors in packages/crypto-api (idempotent, a few seconds).
 * Needs the embedded wasm modules: `zig build js --release=small`.
 */
export async function ensureBuilt() {
  if (!existsSync(join(PKG_ROOT, 'wasm', 'md.mjs'))) {
    throw new Error('packages/crypto-api/wasm is missing. Run: zig build js --release=small');
  }
  const { buildInPlace } = await import(join(SCRIPTS, 'build-package.mjs'));
  await buildInPlace();
}
