// Seeded differential fuzzer: target vs the original crypto-api 0.8.5 with the
// v2 fixes applied (test/harness/v2-model.mjs), for every hasher family and
// every option cell in the catalog. Thrown errors are compared by class.
//
//   FUZZ_ITERS=200   iterations per cell (CI default; use 100000 for release gates)
//   FUZZ_SEED=1      base seed; failures print everything needed to replay
//   FUZZ_ONLY=sha256 only run families whose id contains this substring
//   FUZZ_REFERENCE=v1 compare against the plain original instead (error messages
//                    included); the harness self-test uses it for mutants of 0.8.5
//
// Per iteration: one scenario (random bytes split over random update() calls,
// finalize, optional reset and second message, hostile inputs 8% of the time) is
// run on both implementations and every observable result is compared: return
// values, thrown errors, and JSON.stringify(getState()) after every step. The same
// scenario is then re-run with state handed over mid-stream (oracle -> target and
// target -> oracle) and must continue exactly like the oracle did.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { loadBoth } from '../harness/load.mjs';
import { v2Model } from '../harness/v2-model.mjs';
import { FAMILIES, OPTION_CELLS, cellLabel } from '../harness/catalog.mjs';
import { Rng } from '../harness/prng.mjs';
import {
  generateScenario, runScenario, runHandoff, diffRuns, diffHandoff, reproduction,
} from '../harness/diff.mjs';

const ITERS = Number(process.env.FUZZ_ITERS ?? 200);
const SEED = Number(process.env.FUZZ_SEED ?? 1);
const ONLY = process.env.FUZZ_ONLY ?? '';
const V1 = process.env.FUZZ_REFERENCE === 'v1';
const loose = { loose: !V1 };

let oracle;
let target;
before(async () => {
  const both = await loadBoth();
  oracle = V1 ? both.oracle : v2Model(both.oracle);
  target = both.target;
});

for (const family of FAMILIES) {
  if (ONLY && !family.id.includes(ONLY)) continue;
  describe(`differential: ${family.id}`, () => {
    for (const cell of OPTION_CELLS[family.id]) {
      const label = cellLabel(family.id, cell);
      it(label, () => {
        const rng = new Rng(SEED, label);
        for (let iteration = 0; iteration < ITERS; iteration++) {
          const hostile = rng.chance(0.08);
          const scenario = generateScenario(rng, family, { hostile });

          const expected = runScenario(oracle, family, cell, scenario);
          const actual = runScenario(target, family, cell, scenario);
          const d = diffRuns(expected, actual, loose);
          assert.equal(d, null, `${d}\n${reproduction({ seed: SEED, label, iteration, options: cell, scenario })}`);

          if (expected.ctor !== 'ok') continue;
          const cut = rng.int(scenario.steps.length + 1);
          // JSON cannot carry NaN (what a non-string update() leaves in `length`), so a
          // handoff after such an input is not expected to be lossless in any implementation.
          if (scenario.steps.slice(0, cut).some((s) => s.op === 'update' && s.input.t !== 's')) continue;
          for (const [from, to, name] of [[oracle, target, 'oracle->target'], [target, oracle, 'target->oracle']]) {
            const moved = runHandoff(from, to, family, cell, scenario, cut);
            const hd = diffHandoff(expected, moved, cut, loose);
            assert.equal(hd, null, `${name}: ${hd}\n${reproduction({ seed: SEED, label, iteration, options: cell, scenario, cut })}`);
          }
        }
      });
    }
  });
}
