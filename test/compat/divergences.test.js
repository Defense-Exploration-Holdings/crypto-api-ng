// The complete list of intentional v1 divergences (see "Differences from crypto-api 0.8.5" in packages/crypto-api/README.md).
// Everything else must be identical to 0.8.5; anything not listed here that differs
// is a bug in the port.
//
//   1. Configurations where the original never returns throw RangeError instead.
//   2. setState(obj) no longer keeps a live reference to obj (see quirks.test.js).
//   3. main / index.js exists (checked in test/package/).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { HANGS } from '../harness/catalog.mjs';
import { targetRoot, REPO_ROOT } from '../harness/paths.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const probe = join(here, '..', 'harness', 'hang-probe.mjs');

function run(which, family, options, timeout) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return spawnSync(process.execPath, [probe, which, family, JSON.stringify(options)], {
    env, encoding: 'utf8', timeout, cwd: REPO_ROOT,
  });
}

describe('divergence 1: configurations that hang in 0.8.5', () => {
  for (const h of HANGS) {
    const label = `${h.family} ${JSON.stringify(h.options)} (${h.note})`;

    it(`the original really never returns: ${label}`, () => {
      const r = run('oracle', h.family, h.options, 2000);
      assert.equal(r.error?.code, 'ETIMEDOUT', `expected the oracle to hang, got status ${r.status} stdout ${r.stdout}`);
    });

    it(`the target throws RangeError instead: ${label}`, () => {
      const r = run('target', h.family, h.options, 4000);
      assert.equal(r.error?.code, undefined, 'target hung');
      assert.match(r.stdout, /^RangeError\b/, `target (${targetRoot()}) answered: ${r.stdout}`);
    });
  }
});
