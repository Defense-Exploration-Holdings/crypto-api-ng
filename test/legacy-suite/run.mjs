// Runs the ORIGINAL crypto-api 0.8.5 mocha suite (crypto-api/test/test.mjs,
// unmodified) with node:test standing in for mocha and node:assert for chai.
//
// Default target is the untouched original itself (a harness self-check that
// must report 286 passing). Set CRYPTO_API_TARGET to run the same tests with
// every `../src/...` import redirected into another package root.
//
//   node test/legacy-suite/run.mjs                      # oracle against itself
//   CRYPTO_API_TARGET=packages/crypto-api node test/legacy-suite/run.mjs
//
// The oracle/target choice is made with the first CLI argument: `oracle`
// (default) or `target`.
import { describe, it } from 'node:test';
import { register } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ORACLE_TEST, assertOracleCheckedOut, assertTargetExists } from '../harness/paths.mjs';

const mode = process.argv[2] === 'target' ? 'target' : 'oracle';
assertOracleCheckedOut();
if (mode === 'target') {
  assertTargetExists();
  process.env.CRYPTO_API_LEGACY_SUITE = '1';
}

// The hook reads CRYPTO_API_LEGACY_SUITE when it starts, so set it first.
register('../harness/hook.mjs', import.meta.url);

globalThis.describe = describe;
globalThis.it = it;

await import(pathToFileURL(join(ORACLE_TEST, 'test.mjs')).href);
