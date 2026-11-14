// Cold start: time from `import` of a module to its first digest, in a fresh process each run,
// orig and v1 alternating. Includes the wasm compile for v1 (it is synchronous and lazy).
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ORIG_SRC, V1_SRC, HASHER_FILES, prepareOriginal, assertV1Built } from './lib/trees.mjs';
import { median, quantile } from './lib/stats.mjs';

const child = join(dirname(fileURLToPath(import.meta.url)), 'startup-child.mjs');

function once(file, kind) {
  const t = performance.now();
  const r = spawnSync(process.execPath, [child, file, kind], { encoding: 'utf8' });
  const wall = performance.now() - t;
  if (r.status !== 0) throw new Error(`startup child failed: ${r.stderr}`);
  return { ...JSON.parse(r.stdout.trim().split('\n').pop()), wall };
}

const summarize = (runs) => {
  const col = (k) => runs.map((r) => r[k]).sort((a, b) => a - b);
  const out = {};
  for (const k of ['import', 'first', 'second', 'wall']) out[k] = { median: median(col(k)), p95: quantile(col(k), 0.95) };
  out.import_plus_first_median = median(runs.map((r) => r.import + r.first));
  out.runs = runs.length;
  return out;
};

export function run({ log = () => {}, runs = 15 } = {}) {
  prepareOriginal();
  assertV1Built();
  const targets = [
    ...HASHER_FILES.map((f) => ({ id: f, rel: `hasher/${f}.mjs`, kind: 'hasher' })),
    { id: 'crypto-api (all hashers)', rel: 'crypto-api.mjs', kind: 'api' },
  ];
  const rows = [];
  for (const t of targets) {
    const o = [];
    const n = [];
    once(join(ORIG_SRC, t.rel), t.kind); // discard: first spawn warms the OS file cache
    once(join(V1_SRC, t.rel), t.kind);
    for (let i = 0; i < runs; i++) {
      o.push(once(join(ORIG_SRC, t.rel), t.kind));
      n.push(once(join(V1_SRC, t.rel), t.kind));
    }
    const row = { id: t.id, orig: summarize(o), v1: summarize(n) };
    rows.push(row);
    log(`startup ${t.id}: orig ${row.orig.import_plus_first_median.toFixed(1)} ms, v1 ${row.v1.import_plus_first_median.toFixed(1)} ms`);
  }
  return rows;
}
