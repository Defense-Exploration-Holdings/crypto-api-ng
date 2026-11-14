// Node module-customization hooks (run on the loader thread via module.register).
//
// 1. The original crypto-api sources and tests import each other without
//    extensions ("./hasher32le"), which Node's ESM resolver rejects (upstream
//    relies on babel). Importers inside `crypto-api/` get ".mjs" appended.
// 2. `chai/register-assert` (used by the original tests) maps to a zero
//    dependency shim backed by node:assert.
// 3. In legacy-suite mode (CRYPTO_API_LEGACY_SUITE=1) imports from the original
//    test files into `crypto-api/src/` are redirected to the target package,
//    so the unmodified original tests run against the implementation under test.
import { existsSync, statSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join, resolve, sep } from 'node:path';

const here = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = resolve(here, '..', '..');
const oracleRoot = join(repoRoot, 'crypto-api') + sep;
const oracleSrc = join(repoRoot, 'crypto-api', 'src') + sep;
const oracleTest = join(repoRoot, 'crypto-api', 'test') + sep;
const chaiShim = pathToFileURL(join(here, 'chai-shim.mjs')).href;

const legacySuite = process.env.CRYPTO_API_LEGACY_SUITE === '1';
const targetSrc = join(
  process.env.CRYPTO_API_TARGET
    ? resolve(repoRoot, process.env.CRYPTO_API_TARGET)
    : join(repoRoot, 'packages', 'crypto-api'),
  'src'
) + sep;

const isFile = (p) => existsSync(p) && statSync(p).isFile();

function parentPath(parentURL) {
  if (!parentURL || !parentURL.startsWith('file:')) return null;
  return fileURLToPath(parentURL);
}

export async function resolve_(specifier, context, nextResolve) {
  const parent = parentPath(context.parentURL);
  const inOracle = parent !== null && parent.startsWith(oracleRoot);

  if (inOracle) {
    if (specifier === 'chai/register-assert') {
      return { url: chaiShim, shortCircuit: true };
    }
    if (specifier.startsWith('./') || specifier.startsWith('../')) {
      let path = resolve(parent, '..', specifier);
      if (!/\.[cm]?js$/.test(path) && isFile(path + '.mjs')) path += '.mjs';
      if (legacySuite && parent.startsWith(oracleTest) && path.startsWith(oracleSrc)) {
        path = join(targetSrc, path.slice(oracleSrc.length));
      }
      return { url: pathToFileURL(path).href, shortCircuit: true };
    }
  }
  return nextResolve(specifier, context);
}

// Node looks the hook up by the export name `resolve`.
export { resolve_ as resolve };
