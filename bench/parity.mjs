// Correctness score: runs the parity harness and records the counts, so every benchmark
// result carries the proof that v1 still hashes like 0.8.5.
import { spawnSync } from 'node:child_process';
import { REPO } from './lib/trees.mjs';

const count = (text, key) => {
  const m = text.match(new RegExp(`^# ${key} (\\d+)`, 'm'));
  return m ? Number(m[1]) : null;
};

export function run({ log = () => {} } = {}) {
  const out = {};
  for (const [name, script] of [['legacy_suite', 'test:legacy-suite'], ['compat', 'test:compat']]) {
    const r = spawnSync('npm', ['run', '--silent', script], { cwd: REPO, encoding: 'utf8', maxBuffer: 1 << 28 });
    const text = `${r.stdout}\n${r.stderr}`;
    out[name] = {
      tests: count(text, 'tests'), pass: count(text, 'pass'), fail: count(text, 'fail'),
      todo: count(text, 'todo'), skipped: count(text, 'skipped'), exit: r.status,
    };
    log(`parity ${name}: ${out[name].pass}/${out[name].tests} pass, ${out[name].fail} fail`);
  }
  return out;
}
