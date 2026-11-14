#!/usr/bin/env node
// Benchmark runner: crypto-api 0.8.5 vs this port (v1), plus startup, sizes and the correctness score.
//
//   node bench/run.mjs [--quick | --full] [--suites throughput,construct,api,hmac,state,startup,sizes,parity]
//                      [--variants md5,sha256] [--label name] [--out file.json]
//
//   (default)  sizes 0 B .. 1 MiB, 15 samples          ~10 min
//   --quick    sizes 64 B, 64 KiB, 1 MiB, 10 samples    a couple of minutes, smoke test
//   --full     adds 16 MiB                               ~20 min
//
// Prerequisites: `scripts/fetch-upstream.sh` and `zig build js --release=small`.
// Works under Node 22+ and Bun (`bun bench/run.mjs`). Details: bench/README.md.
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadBoth, REPO } from './lib/trees.mjs';
import { VARIANTS } from './lib/contenders.mjs';
import * as suites from './lib/suites.mjs';
import { environment } from './lib/env.mjs';

const args = process.argv.slice(2);
const flag = (name) => args.includes(`--${name}`);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : dflt;
};

const quick = flag('quick');
const full = flag('full');
const all = ['throughput', 'construct', 'api', 'hmac', 'state', 'startup', 'sizes', 'parity'];
const wanted = (opt('suites', all.join(',')) || '').split(',').filter(Boolean);
const only = opt('variants') ? new Set(opt('variants').split(',')) : null;
const variants = only ? VARIANTS.filter((v) => only.has(v.id)) : VARIANTS;

const sizes = quick ? [64, 65536, 1048576] : full ? suites.SIZES : suites.SIZES.filter((s) => s <= 1048576);
const measure = quick
  ? { samples: 10, minSampleMs: 15, warmupMs: 40, slowSamples: 5 }
  : { samples: 15, minSampleMs: 25, warmupMs: 80, slowSamples: full ? 5 : 7 };

const log = (m) => console.error(m);
const env = await environment();
const label = opt('label', env.runtime === 'bun' ? 'bun' : 'node');
const date = new Date().toISOString().slice(0, 10);
const outFile = opt('out', join(REPO, 'bench', 'results', `${date}-${label}${quick ? '-quick' : ''}.json`));

let createHash = null;
try {
  createHash = (await import('node:crypto')).createHash;
} catch { /* browser */ }

// The raw contender calls the exact wasm bytes the facades embed (`zig build js`).
const embedded = {};
for (const family of ['md', 'md2', 'has160', 'ripemd', 'sha1', 'sha256', 'sha512', 'sm3', 'snefru', 'whirlpool']) {
  embedded[family] = (await import(pathToFileURL(join(REPO, 'packages', 'crypto-api', 'wasm', `${family}.mjs`)).href)).wasmBytes();
}
const ctx = { ...(await loadBoth()), createHash, wasmBytesOf: (family) => embedded[family], measure, log };

const result = {
  schema: 1, label, date, mode: quick ? 'quick' : full ? 'full' : 'default', environment: env, measure, input_sizes: sizes,
};

const t0 = Date.now();
for (const name of wanted) {
  log(`\n== ${name}`);
  switch (name) {
    case 'throughput': result.throughput = suites.throughput(ctx, { sizes, variants }); break;
    case 'construct': result.construct = suites.construct(ctx, { variants }); break;
    case 'api': result.api = suites.api(ctx); break;
    case 'hmac': result.hmac = suites.hmac(ctx); break;
    case 'state': result.state = suites.state(ctx); break;
    case 'startup': result.startup = (await import('./startup.mjs')).run({ log, runs: quick ? 7 : 15 }); break;
    case 'sizes': result.sizes_report = (await import('./sizes.mjs')).run({ log }); break;
    case 'parity': result.parity = (await import('./parity.mjs')).run({ log }); break;
    default: throw new Error(`unknown suite ${name}`);
  }
}
result.duration_s = Math.round((Date.now() - t0) / 1000);
mkdirSync(join(REPO, 'bench', 'results'), { recursive: true });
writeFileSync(outFile, JSON.stringify(result, null, 1) + '\n');
log(`\nwrote ${outFile} (${result.duration_s} s)`);
