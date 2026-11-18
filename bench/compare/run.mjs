#!/usr/bin/env node
// crypto-api-ng against other hash libraries: one call over a Uint8Array, per algorithm and size.
//
//   node bench/compare/run.mjs [--quick] [--algorithms md5,sha256] [--sizes 32,1024] [--label name] [--out file]
//   bun  bench/compare/run.mjs ...
//   deno run -A bench/compare/run.mjs ...
//
// Prerequisites: `npm ci --prefix bench/compare` (the libraries) and `zig build js --release=small`
// (the wasm crypto-api-ng imports). bench/compare/run-all.mjs runs every installed runtime.
// Details: bench/compare/README.md.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { measureGroup, geomean } from '../lib/stats.mjs';
import { makeBytes } from '../lib/contenders.mjs';
import { ALGORITHMS, LIBRARIES, toHex } from './libs.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const argv = typeof Deno !== 'undefined' ? Deno.args : process.argv.slice(2);
const flag = (name) => argv.includes(`--${name}`);
const opt = (name, dflt) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : dflt;
};
const log = (m) => console.error(m);

const quick = flag('quick');
const SIZES = (opt('sizes') ?? (quick ? '1024,1048576' : '32,1024,65536,1048576')).split(',').map(Number);
const only = opt('algorithms') ? new Set(opt('algorithms').split(',')) : null;
const algorithms = only ? ALGORITHMS.filter((a) => only.has(a.id)) : ALGORITHMS;
const measure = quick
  ? { samples: 9, minSampleMs: 15, warmupMs: 40, slowSamples: 5 }
  : { samples: 15, minSampleMs: 25, warmupMs: 100, slowSamples: 7 };

const runtime = typeof Deno !== 'undefined' ? 'deno' : typeof Bun !== 'undefined' ? 'bun' : 'node';
const runtimeVersion = runtime === 'deno' ? Deno.version.deno : runtime === 'bun' ? Bun.version : process.versions.node;
const sh = (cmd, args) => {
  try {
    return execFileSync(cmd, args, { cwd: REPO, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
};
const cpus = os.cpus();
const environment = {
  runtime,
  runtime_version: runtimeVersion,
  v8: runtime === 'deno' ? Deno.version.v8 : process.versions?.v8 ?? null,
  platform: `${os.platform()} ${os.arch()} ${os.release()}`,
  cpu: cpus[0]?.model ?? 'unknown',
  cpu_count: cpus.length,
  memory_mb: Math.round(os.totalmem() / 1048576),
  commit: sh('git', ['rev-parse', '--short', 'HEAD']),
  note: opt('note', null),
};
const label = opt('label', runtime);
const date = new Date().toISOString().slice(0, 10);
const outFile = opt('out', join(REPO, 'bench', 'results', `compare-${date}-${label}${quick ? '-quick' : ''}.json`));

log(`${runtime} ${runtimeVersion} on ${environment.cpu} (${environment.cpu_count} threads)`);

// Load every library; one that fails to load (missing package, runtime without wasm) is recorded and skipped.
const libs = [];
for (const L of LIBRARIES) {
  try {
    const fns = await L.setup();
    libs.push({ name: L.name, short: L.short ?? L.name, kind: L.kind, subject: !!L.subject, informational: !!L.informational, version: L.version(), fns });
  } catch (e) {
    log(`  ${L.name}: not loaded (${e.message})`);
    libs.push({ name: L.name, short: L.short ?? L.name, kind: L.kind, version: null, fns: {}, error: e.message });
  }
}

const rows = [];
const t0 = Date.now();
for (const a of algorithms) {
  for (const size of SIZES) {
    const bytes = makeBytes(size);
    // Verify: every contender's digest must equal the majority digest. crypto-api-ng disagreeing aborts.
    const candidates = libs.filter((l) => l.fns[a.id]);
    const hex = new Map();
    for (const l of candidates) {
      try {
        hex.set(l.name, toHex(l.fns[a.id](bytes)));
      } catch (e) {
        hex.set(l.name, `error: ${e.message}`);
      }
    }
    const votes = new Map();
    for (const h of hex.values()) votes.set(h, (votes.get(h) ?? 0) + 1);
    const expected = [...votes.entries()].sort((x, y) => y[1] - x[1])[0]?.[0];
    const row = { algorithm: a.id, size, expected, dropped: {} };
    const timed = [];
    for (const l of candidates) {
      if (hex.get(l.name) === expected) timed.push(l);
      else {
        row.dropped[l.name] = hex.get(l.name);
        log(`  ${a.id} ${size} B: ${l.name} gives ${hex.get(l.name)}, expected ${expected}; not timed`);
        if (l.subject) throw new Error(`crypto-api-ng digest mismatch for ${a.id} at ${size} B`);
      }
    }
    if (timed.length < 2 && !(votes.get(expected) >= 2)) row.note = 'single implementation, digest not cross-checked';
    const res = measureGroup(timed.map((l) => ({ name: l.name, fn: () => l.fns[a.id](bytes) })), measure);
    row.results = {};
    for (const l of timed) {
      const r = res[l.name];
      row.results[l.name] = {
        median_ms: r.median, p95_ms: r.p95, samples: r.samples, iters: r.iters,
        mb_per_s: size / 1e6 / (r.median / 1000),
        ops_per_s: 1000 / r.median,
      };
    }
    rows.push(row);
    const ng = row.results['crypto-api-ng'];
    const fmt = (l) => {
      const r = row.results[l.name];
      return `${l.short} ${size >= 65536 ? `${r.mb_per_s.toFixed(0)} MB/s` : `${(r.ops_per_s / 1000).toFixed(0)}k/s`}${ng && !l.subject ? ` (${(r.median_ms / ng.median_ms).toFixed(2)}x)` : ''}`;
    };
    log(`${a.label.padEnd(12)} ${String(size).padStart(8)} B  ${timed.map(fmt).join(' | ')}`);
  }
}

// Summary: geomean over all cells of (other / crypto-api-ng) time, per library. >1 = crypto-api-ng is faster.
const summary = {};
for (const l of libs) {
  if (l.subject || l.informational) continue;
  const ratios = rows.filter((r) => r.results[l.name] && r.results['crypto-api-ng'])
    .map((r) => r.results[l.name].median_ms / r.results['crypto-api-ng'].median_ms);
  if (ratios.length) summary[l.name] = { cells: ratios.length, geomean_time_ratio: geomean(ratios) };
}

const result = {
  schema: 1,
  kind: 'compare',
  label,
  date,
  mode: quick ? 'quick' : 'default',
  environment,
  measure,
  input_sizes: SIZES,
  libraries: libs.map(({ name, short, kind, subject, informational, version, error }) => ({ name, short, kind, subject, informational, version, error })),
  rows,
  summary,
  duration_s: Math.round((Date.now() - t0) / 1000),
};
mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, JSON.stringify(result, null, 1) + '\n');
log(`\nwrote ${outFile} (${result.duration_s} s)`);
