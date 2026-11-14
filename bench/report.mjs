#!/usr/bin/env node
// Turns bench/results/*.json into docs/benchmarks.md and docs/benchmarks/speedup.svg.
//
//   node bench/report.mjs [--label node22] [--also bun] [file.json ...]
//
// With no files, every non-quick result with the given label is used; when several runs of
// the same cell exist, the median of their medians is reported.
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { REPO } from './lib/trees.mjs';
import { geomean, median } from './lib/stats.mjs';
import { VARIANTS } from './lib/contenders.mjs';
import { renderChart } from './chart.mjs';

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : d; };
const files = args.filter((a, i) => a.endsWith('.json') && args[i - 1] !== '--out');
const label = opt('label', 'node22');
const also = opt('also', null);

const resultsDir = join(REPO, 'bench', 'results');
const load = (lab) => readdirSync(resultsDir)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({ f, r: JSON.parse(readFileSync(join(resultsDir, f), 'utf8')) }))
  .filter(({ r }) => r.label === lab && r.mode !== 'quick')
  .map(({ r }) => r);
const runs = files.length ? files.map((f) => JSON.parse(readFileSync(f, 'utf8'))) : load(label);
if (!runs.length) throw new Error(`no results for label ${label}; run node bench/run.mjs first`);
const env = runs[0].environment;

// ---------------------------------------------------------------- aggregation
/** Median of medians across runs for a [{key, results}] list. */
function merge(listOfLists, keyOf) {
  const cells = new Map();
  for (const list of listOfLists) {
    for (const row of list ?? []) {
      const k = keyOf(row);
      if (!cells.has(k)) cells.set(k, []);
      cells.get(k).push(row);
    }
  }
  return [...cells.entries()].map(([k, rows]) => ({ ...rows[0], key: k, n: rows.length, results: mergeResults(rows) }));
}
function mergeResults(rows) {
  const out = {};
  if (!rows[0].results) return out;
  for (const name of Object.keys(rows[0].results)) {
    const rs = rows.map((r) => r.results[name]).filter(Boolean);
    const m = median(rs.map((r) => r.median_ms));
    out[name] = {
      median_ms: m,
      p95_ms: Math.max(...rs.map((r) => r.p95_ms)),
      mb_per_s: rs[0].mb_per_s === null ? null : (rs[0].mb_per_s * rs[0].median_ms) / m,
      ops_per_s: 1000 / m,
      samples: rs.reduce((a, r) => a + r.samples, 0),
    };
  }
  return out;
}

const tp = merge(runs.map((r) => r.throughput), (r) => `${r.variant}|${r.size}|${r.mode}`).filter((r) => r.status === 'ok');
const ratio = (row, a = 'orig', b = 'v1') => row.results[a].median_ms / row.results[b].median_ms;
const cell = (variant, size, mode = 'oneshot') => tp.find((r) => r.variant === variant && r.size === size && r.mode === mode);
const sizesAll = [...new Set(tp.map((r) => r.size))].sort((a, b) => a - b);
const sizeName = (n) => (n === 0 ? '0 B' : n < 1024 ? `${n} B` : n < 1048576 ? `${n / 1024} KiB` : `${n / 1048576} MiB`);
const x = (v) => (v >= 10 ? v.toFixed(1) : v.toFixed(2)) + '×';
const fmtTime = (ms) => (ms >= 1 ? `${ms.toFixed(2)} ms` : ms >= 0.001 ? `${(ms * 1000).toFixed(2)} µs` : `${(ms * 1e6).toFixed(0)} ns`);
const mbs = (v) => (v >= 100 ? v.toFixed(0) : v.toFixed(1));
const row = (...cols) => `| ${cols.join(' | ')} |`;
const table = (head, rows, align) => [
  row(...head),
  row(...head.map((_, i) => (align?.[i] === 'l' ? ':---' : '---:'))),
  ...rows.map((r) => row(...r)),
].join('\n');
const names = VARIANTS.map((v) => v.id);
const FAMILY_ALGOS = {
  md: 'MD4, MD5', md2: 'MD2', has160: 'HAS-160', ripemd: 'RIPEMD-128/160/256/320', sha1: 'SHA-0, SHA-1',
  sha256: 'SHA-224/256', sha512: 'SHA-384/512, SHA-512/224, /256', sm3: 'SM3', snefru: 'Snefru', whirlpool: 'Whirlpool, -0, -T',
};


// Run-to-run spread of the v1/0.8.5 ratio for the same cell (only meaningful with 2+ runs).
let spreadText = '';
if (runs.length > 1) {
  const byRun = runs.map((r) => new Map((r.throughput ?? []).filter((c) => c.status === 'ok').map((c) => [`${c.variant}|${c.size}|${c.mode}`, c.results.orig.median_ms / c.results.v1.median_ms])));
  const spreads = [];
  for (const k of byRun[0].keys()) {
    const vs = byRun.map((m) => m.get(k)).filter(Boolean);
    if (vs.length > 1) spreads.push(Math.max(...vs) / Math.min(...vs));
  }
  spreads.sort((a, b) => a - b);
  const q = (f) => spreads[Math.min(spreads.length - 1, Math.floor(spreads.length * f))];
  spreadText = `Between runs the same cell's ratio differs by ${((q(0.5) - 1) * 100).toFixed(0)}% at the median, ${((q(0.95) - 1) * 100).toFixed(0)}% at p95 and ${((spreads[spreads.length - 1] - 1) * 100).toFixed(0)}% at worst (${spreads.length} cells), so read single-cell ratios as good to within roughly 30% on this machine.`;
}

// ---------------------------------------------------------------- sections
const out = [];
const p = (s = '') => out.push(s);

p('# Benchmarks: v1 against crypto-api 0.8.5');
p();
p('Generated by `node bench/report.mjs` from `bench/results/*.json`. Do not edit by hand; rerun the benchmark (see [Reproduce](#reproduce)).');
p();
p('Every number compares the **same public API** on both sides: `new Hasher(options)`, `update(string)`, `finalize()` with binary strings, exactly as 0.8.5 users call it. The 0.8.5 side is the untouched upstream checkout in `crypto-api/`; the v1 side is `packages/crypto-api`. Before a case is timed, both sides (and the extra reference contenders) must produce identical digests, so no number comes from code that computes something else.');
p();

// Environment
p('## Environment');
p();
p(table(['', ''], [
  ['Runtime', `${env.runtime} ${env.runtime_version}${env.v8 ? ` (V8 ${env.v8})` : ''}`],
  ['CPU', `${env.cpu} × ${env.cpu_count}`],
  ['Platform', env.platform],
  ['Memory', `${env.memory_mb} MB`],
  ['Build', `Zig ${env.zig}, \`--release=small\``],
  ['Commit', `\`${env.commit}\` (crypto-api 0.8.5 at \`${env.original}\`)`],
  ['Runs', `${runs.length} run${runs.length > 1 ? 's' : ''} (${runs.map((r) => r.mode).join(', ')}); cells report the median of medians. ${spreadText}`],
  ['Samples per cell', `${runs[0].measure.samples} (${runs[0].measure.slowSamples} for operations over 0.5 s), interleaved between contenders, each sample ≥ ${runs[0].measure.minSampleMs} ms`],
], ['l', 'l']));
p();
p(`${env.note} Absolute numbers move with the machine; read the ratios.`);
p();

// Headline
p('## Headline');
p();
const oneshot = (size) => names.map((n) => cell(n, size)).filter(Boolean);
const gm = (size) => geomean(oneshot(size).map((r) => ratio(r)));
const bigSize = sizesAll.includes(1048576) ? 1048576 : sizesAll[sizesAll.length - 1];
const head = [];
for (const s of [64, 1024, 65536, 1048576]) if (sizesAll.includes(s)) head.push([sizeName(s), x(gm(s)), `${x(Math.min(...oneshot(s).map((r) => ratio(r))))} (${oneshot(s).sort((a, b) => ratio(a) - ratio(b))[0].variant})`, `${x(Math.max(...oneshot(s).map((r) => ratio(r))))} (${oneshot(s).sort((a, b) => ratio(b) - ratio(a))[0].variant})`]);
p('Speedup of v1 over 0.8.5 for one `new` + `update` + `finalize()`, across all 24 named variants:');
p();
p(table(['Input', 'Geometric mean', 'Smallest', 'Largest'], head, ['l', 'r', 'r', 'r']));
p();
const slower = tp.filter((r) => ratio(r) < 1);
p(slower.length
  ? `**${slower.length} of ${tp.length} throughput cells are slower than 0.8.5:** ${slower.map((r) => `${r.variant} ${sizeName(r.size)} ${r.mode} (${x(ratio(r))})`).join(', ')}.`
  : `**No throughput cell is slower than 0.8.5** (${tp.length} cells: 24 variants, ${sizesAll.length} sizes, single call and 4 KiB chunks).`);
p();
p('![Speedup of v1 over 0.8.5 per algorithm](benchmarks/speedup.svg)');
p();

// Per variant speedup table
p('## Speedup by algorithm and input size');
p();
p('v1 time ÷ 0.8.5 time, single `update()` call. Higher is better; `n/a` means 0.8.5 itself throws on that input (Snefru cannot finalize an empty message).');
p();
p(table(['Variant', ...sizesAll.map(sizeName)], names.map((n) => [n, ...sizesAll.map((s) => { const c = cell(n, s); return c ? x(ratio(c)) : 'n/a'; })]), ['l']));
p();

// Absolute throughput
p('## Throughput at 1 MiB (MB/s)');
p();
p('One `update()` call over a 1 MiB binary string. **raw wasm** calls the v1 wasm module directly with a `Uint8Array` and no string handling: the ceiling a bytes-in/bytes-out v2 API can approach, not something v1 exposes. **node:crypto** (OpenSSL) is a reference, not a contender: a native, hardware-accelerated library.');
p();
const mb = (c, k) => (c?.results[k] ? mbs(c.results[k].mb_per_s) : '–');
p(table(['Variant', '0.8.5', 'v1', 'v1 ÷ 0.8.5', 'raw wasm', 'node:crypto'], names.map((n) => {
  const c = cell(n, 1048576);
  return c ? [n, mb(c, 'orig'), mb(c, 'v1'), x(ratio(c)), mb(c, 'raw'), mb(c, 'node')] : [n, '–', '–', '–', '–', '–'];
}), ['l']));
p();
p('For the fast algorithms (MD4, MD5, SHA-1/2, HAS-160, RIPEMD) v1 sits well below raw wasm: the 0.8.5 API forces a string-to-bytes copy (a `charCodeAt` per byte) and the facade moves state in and out of wasm. For MD2, Snefru and Whirlpool the compression dominates and v1 is within a few percent of raw wasm. Bytes-in APIs are v2 work.');
p();

// Streamed
p('## Streamed in 4 KiB chunks (the `hasher-file` pattern)');
p();
const streamSizes = sizesAll.filter((s) => s >= 65536);
p(table(['Variant', ...streamSizes.map((s) => `${sizeName(s)}`)], names.map((n) => [n, ...streamSizes.map((s) => { const c = cell(n, s, 'stream'); return c ? x(ratio(c)) : 'n/a'; })]), ['l']));
p();

// Other runtimes
const bunRuns = also === 'none' ? [] : load(also ?? 'bun');
if (bunRuns.length) {
  const be = bunRuns[0].environment;
  const btp = merge(bunRuns.map((r) => r.throughput), (r) => `${r.variant}|${r.size}|${r.mode}`).filter((r) => r.status === 'ok');
  const bc = (v, s) => btp.find((r) => r.variant === v && r.size === s && r.mode === 'oneshot');
  const bsizes = [64, 1024, 65536, 1048576].filter((s) => btp.some((r) => r.size === s));
  p(`## Bun ${be.runtime_version}`);
  p();
  const bmd2 = bsizes.map((sz) => bc('md2', sz)).filter(Boolean).map((c) => ratio(c));
  const bgm = bsizes.map((sz) => geomean(names.map((n) => bc(n, sz)).filter(Boolean).map((c) => ratio(c))));
  const bsha = ['sha224', 'sha256', 'sm3'].flatMap((n) => bsizes.map((sz) => bc(n, sz)).filter(Boolean).map((c) => ratio(c)));
  p(`The same benchmark under Bun (JavaScriptCore), ${bunRuns.length} run${bunRuns.length > 1 ? 's' : ''}. JavaScriptCore runs the original JavaScript faster than V8 does for several algorithms (0.8.5 MD5 runs about 3× faster than under Node), so the margin is smaller: the geometric mean is ${Math.min(...bgm).toFixed(1)} to ${Math.max(...bgm).toFixed(1)}×, SHA-224/256 and SM3 gain only ${Math.min(...bsha).toFixed(2)} to ${Math.max(...bsha).toFixed(2)}×, and **MD2 is ${Math.min(...bmd2).toFixed(2)} to ${Math.max(...bmd2).toFixed(2)}×**, i.e. at best a few percent faster and in some cells slower than 0.8.5. MD2 is a serial chain of table lookups; the likely cause is that JavaScriptCore compiles that loop as well as it compiles wasm, leaving only the facade overhead. Cells near 1× are within the run-to-run noise of a shared machine. Single \`update()\` call, v1 time ÷ 0.8.5 time.`);
  p();
  p(table(['Variant', ...bsizes.map(sizeName)], [
    ...names.map((n) => [n, ...bsizes.map((s) => { const c = bc(n, s); return c ? x(ratio(c)) : 'n/a'; })]),
    ['**geometric mean**', ...bsizes.map((s) => x(geomean(names.map((n) => bc(n, s)).filter(Boolean).map((c) => ratio(c)))))],
  ], ['l']));
  p();
  const bslow = btp.filter((r) => ratio(r) < 1);
  p(bslow.length ? `Cells slower than 0.8.5 under Bun: ${bslow.map((r) => `${r.variant} ${sizeName(r.size)} ${r.mode} (${x(ratio(r))})`).join(', ')}.` : `No cell is slower than 0.8.5 under Bun (${btp.length} cells).`);
  const bs = bunRuns.find((r) => r.startup)?.startup;
  if (bs) {
    p();
    p(`Cold start under Bun (import plus first digest, median): ${bs.map((r) => `${r.id} ${r.orig.import_plus_first_median.toFixed(1)} → ${r.v1.import_plus_first_median.toFixed(1)} ms`).join('; ')}.`);
  }
  p();
}

// Small ops
p('## Per-call costs');
p();
const construct = merge(runs.map((r) => r.construct), (r) => r.variant);
const api = merge(runs.map((r) => r.api), (r) => r.name);
const hmac = merge(runs.map((r) => r.hmac), (r) => `${r.variant}|${r.size}`);
const state = runs[0].state ? runs[0].state : [];
if (construct.length) {
  p('### Construction (`new Hasher(options)`)');
  p();
  p(table(['Variant', '0.8.5', 'v1', 'v1 ÷ 0.8.5'], construct.map((r) => [r.variant, fmtTime(r.results.orig.median_ms), fmtTime(r.results.v1.median_ms), x(ratio(r))]), ['l']));
  p();
}
if (api.length) {
  p('### `CryptoApi.hash(name, message)` (43-byte message, hex output)');
  p();
  p(table(['Name', '0.8.5 ops/s', 'v1 ops/s', 'v1 ÷ 0.8.5'], api.map((r) => [r.name, Math.round(r.results.orig.ops_per_s).toLocaleString('en-US'), Math.round(r.results.v1.ops_per_s).toLocaleString('en-US'), x(ratio(r))]), ['l']));
  p();
}
if (hmac.length) {
  p('### HMAC (`new Hmac(key, hasher)`, `update`, `finalize`)');
  p();
  const hs = [...new Set(hmac.map((r) => r.variant))];
  const hz = [...new Set(hmac.map((r) => r.size))];
  p(table(['Variant', ...hz.flatMap((z) => [`${sizeName(z)} 0.8.5 ops/s`, `v1 ops/s`, '×'])], hs.map((v) => [v, ...hz.flatMap((z) => {
    const r = hmac.find((q) => q.variant === v && q.size === z);
    return [Math.round(r.results.orig.ops_per_s).toLocaleString('en-US'), Math.round(r.results.v1.ops_per_s).toLocaleString('en-US'), x(ratio(r))];
  })]), ['l']));
  p();
  p('HMAC is the original JavaScript class in both trees, wrapping a hasher: the gain comes entirely from the hashing underneath (an inner and an outer hash plus key handling), so it follows the hasher speedup, diluted by the unchanged key padding and string handling.');
  p();
}
if (state.length) {
  p('### `getState()` / `setState()` after 1 KiB');
  p();
  p('Same JavaScript in both trees, so this should be 1×. It is here to show the facades add no cost to state handling.');
  p();
  p(table(['Variant', 'getState 0.8.5', 'v1', '×', 'setState 0.8.5', 'v1', '×'], state.map((r) => [r.variant, fmtTime(r.getState.orig.median_ms), fmtTime(r.getState.v1.median_ms), x(r.getState.orig.median_ms / r.getState.v1.median_ms), fmtTime(r.setState.orig.median_ms), fmtTime(r.setState.v1.median_ms), x(r.setState.orig.median_ms / r.setState.v1.median_ms)]), ['l']));
  p();
}

// Startup
const startup = runs.find((r) => r.startup)?.startup;
if (startup) {
  p('## Cold start');
  p();
  p('Fresh process per measurement (alternating 0.8.5 and v1). *Import* is the dynamic `import()` of the module; *first digest* is `new` + `update("hello")` + `finalize()` and includes the one-time synchronous compile of the wasm module for v1. Median of the runs, milliseconds, process boot excluded.');
  p();
  p(table(['Module', 'import 0.8.5', 'import v1', 'first digest 0.8.5', 'first digest v1', 'total 0.8.5', 'total v1', 'Δ'], startup.map((r) => [
    r.id, r.orig.import.median.toFixed(1), r.v1.import.median.toFixed(1), r.orig.first.median.toFixed(1), r.v1.first.median.toFixed(1),
    r.orig.import_plus_first_median.toFixed(1), r.v1.import_plus_first_median.toFixed(1), `+${(r.v1.import_plus_first_median - r.orig.import_plus_first_median).toFixed(1)}`,
  ]), ['l']));
  p();
}

// Sizes
const sizes = runs.find((r) => r.sizes_report)?.sizes_report;
if (sizes) {
  p('## Size');
  p();
  p('### wasm modules (bytes)');
  p();
  const fams = Object.keys(sizes.wasm.small ?? {}).sort();
  const modes = Object.keys(sizes.wasm);
  p(table(['Family', ...modes.flatMap((m) => [`${m}`, `${m} gzip`]), 'Algorithms'], fams.map((f) => [f, ...modes.flatMap((m) => [sizes.wasm[m][f]?.raw ?? '–', sizes.wasm[m][f]?.gzip ?? '–']), FAMILY_ALGOS[f] ?? '']), ['l']));
  const tot = (m) => fams.reduce((a, f) => a + (sizes.wasm[m]?.[f]?.raw ?? 0), 0);
  p();
  p(`All families together: ${modes.map((m) => `${(tot(m) / 1024).toFixed(1)} KiB (${m})`).join(', ')}. v1 ships \`small\`; \`fast\` is not faster end to end. Each family is its own module and is only instantiated when a hasher of that family first processes data.`);
  p();
  p('### JavaScript per import (unminified module closure, bytes)');
  p();
  p('Everything reachable from the deep import `crypto-api/src/hasher/<name>.mjs`, concatenated. v1 includes the verbatim original engine (the fallback), the facade, the shared glue and the wasm module embedded as base64. No minifier was run; `node scripts/size-report.mjs` reports minified sizes.');
  p();
  p(table(['Import', 'files 0.8.5', 'files v1', '0.8.5', '0.8.5 gzip', 'v1', 'v1 gzip', 'v1 ÷ 0.8.5 (gzip)'], sizes.js.map((r) => [r.id, r.orig.files, r.v1.files, r.orig.raw, r.orig.gzip, r.v1.raw, r.v1.gzip, x(r.v1.gzip / r.orig.gzip)]), ['l']));
  p();
}

// Correctness
const parity = runs.find((r) => r.parity)?.parity;
p('## Correctness score');
p();
p('Speed numbers only mean something next to this. The same commit passes:');
p();
const verified = runs[0].throughput?.filter((r) => r.status === 'ok').reduce((a, r) => a + r.verified, 0);
p(table(['Check', 'Result'], [
  ...(parity ? [
    ['Original 0.8.5 test suite, unmodified, run against v1', `${parity.legacy_suite.pass}/${parity.legacy_suite.tests} pass, ${parity.legacy_suite.fail} fail`],
    ['Differential fuzz, quirk probes, OpenSSL cross-checks, `getState()` JSON round trips (`npm run test:compat`)', `${parity.compat.pass}/${parity.compat.tests} pass, ${parity.compat.fail} fail`],
  ] : [['Parity suites', 'not run in this result (use `--suites parity`)']]),
  ['Digests compared inside this benchmark before timing', `${verified?.toLocaleString('en-US')} (every cell: 0.8.5 = v1 = raw wasm = node:crypto where available)`],
], ['l', 'l']));
p();

p(STATIC_TAIL(runs));
mkdirSync(join(REPO, 'docs', 'benchmarks'), { recursive: true });
writeFileSync(join(REPO, 'docs', 'benchmarks.md'), out.join('\n') + '\n');
writeFileSync(join(REPO, 'docs', 'benchmarks', 'speedup.svg'), renderChart({
  rows: names.map((n) => ({ name: n, a: cell(n, 1024) ? ratio(cell(n, 1024)) : null, b: cell(n, 1048576) ? ratio(cell(n, 1048576)) : null })),
  labelA: '1 KiB', labelB: '1 MiB',
}));
console.error(`wrote docs/benchmarks.md from ${runs.length} run(s)`);

// ---------------------------------------------------------------- static text
function STATIC_TAIL(runs) {
  return [
    '## How the numbers are made',
    '',
    '- **Operation:** `new Hasher(options)`, `update(input)`, `finalize()`; the result is the binary digest string. Inputs are deterministic pseudo-random binary strings (one character per byte, the 0.8.5 API), so the wasm path is used in full. Inputs with characters above 0xFF, other option values and odd states run the original JavaScript in v1 and cost the same as 0.8.5.',
    '- **Timing:** `bench/lib/stats.mjs`. Each contender is warmed up, its iteration count is calibrated so a sample takes about 25 ms, and samples are taken round-robin between contenders so drift hits all of them equally. Reported: median per operation, plus p95 in the JSON.',
    '- **Not measured here:** browsers and other runtimes (the harness runs under Bun too, results labeled separately), third-party libraries (`hash-wasm`, `@noble/hashes`, `crypto-js`), a quiet dedicated machine. These are follow-ups.',
    '',
    '## Reading the results honestly',
    '',
    '- The big wins are where 0.8.5 does the most JavaScript work per byte (SHA-512 and its relatives: 64-bit arithmetic emulated with pairs of 32-bit integers; MD5/MD4; Whirlpool). Algorithms whose original JavaScript is already close to a plain loop (HAS-160, RIPEMD) gain less, and the serial S-box chains of MD2 and Snefru gain least, because the bottleneck is a dependent load chain that wasm and JavaScript run at the same speed.',
    '- Construction costs the same (about 100 ns) on both sides, so small-input gains come from `update`/`finalize` (padding and the last compression), not from `new`. The one exception is SHA-512/224 and SHA-512/256: 0.8.5 hashes `"SHA-512/t"` on every construction to derive the IV (about 11 µs); v1 writes the constants, hence the 18 to 24× at 0 to 64 B.',
    '- Cold start is **slower** in v1, by about 1.5 to 3 ms per family (5.8 ms for the whole facade). About 1 to 2 ms is `import`: v1 loads more files (the facade, the shared glue and the original engine it keeps as the fallback) and parses the embedded base64 module. About 0.4 to 1 ms more is in the first digest: the synchronous wasm compile and instantiation, which happens lazily on first use, per family. For a long-running server that is irrelevant; for a short-lived function that hashes once it is the whole story. Trimming it (smaller embedded form, lazy fallback import) is v1.x work.',
    '- Raw wasm numbers are what bytes-in/bytes-out can reach and are why v2 changes the API; they are not claims about v1.',
    '',
    '## Reproduce',
    '',
    '```sh',
    'scripts/fetch-upstream.sh',
    'scripts/install-zig.sh && export PATH="$HOME/.local/bin:$PATH"',
    'zig build js --release=small          # embeds the wasm the facades import',
    'node bench/run.mjs --full             # about 20 minutes; --quick for a smoke test',
    'node bench/report.mjs                 # rewrites this file and the chart',
    '```',
    '',
    'Raw results (every cell, p95, iteration counts, environment) are in `bench/results/*.json`. See `bench/README.md`.',
  ].join('\n');
}
