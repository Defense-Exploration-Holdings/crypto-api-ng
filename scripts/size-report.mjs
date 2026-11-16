// Bundle-size report: every deep import and the full facade, minified and gzipped, for the original
// crypto-api 0.8.5 (the `crypto-api/` checkout) and this port. Needs `npm ci` and `zig build js --release=small`.
//
//   node scripts/size-report.mjs            Markdown table on stdout
//   node scripts/size-report.mjs --json
//   node scripts/size-report.mjs --entries  size of every `exports` entry point of the package (no 0.8.5 needed)
//   node scripts/size-report.mjs --write    same, and rewrite the table in packages/crypto-api/README.md
import { build } from 'esbuild';
import { gzipSync } from 'node:zlib';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { FAMILIES } from '../test/harness/catalog.mjs';
import { ENTRY_ALGORITHMS, PKG_ROOT, entriesFromExports } from './package-entries.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const trees = { original: join(root, 'crypto-api', 'src'), port: join(root, 'packages', 'crypto-api', 'src') };

async function size(entry) {
  const r = await build({
    entryPoints: [entry], bundle: true, minify: true, format: 'esm', write: false,
    platform: 'neutral', mainFields: ['module', 'main'], logLevel: 'silent',
    loader: { '.mjs': 'js' }, resolveExtensions: ['.mjs', '.js', '.json'],
  });
  const code = r.outputFiles[0].contents;
  return { min: code.length, gzip: gzipSync(code, { level: 9 }).length };
}

export const README_MARKERS = ['<!-- entry-sizes:start -->', '<!-- entry-sizes:end -->'];

/** Markdown table of every per-algorithm entry point: minified and gzipped size of the bundle of that import alone. */
export async function entryTable() {
  const kb = (n) => (n / 1024).toFixed(1);
  const rows = [['crypto-api-ng', 'Everything: the `CryptoApi` object with every hasher, HMAC and the encoders', './src/index.mjs']];
  const order = Object.keys(ENTRY_ALGORITHMS);
  const entries = entriesFromExports();
  for (const { name } of entries) {
    if (!(name in ENTRY_ALGORITHMS)) throw new Error(`exports has "./${name}", but scripts/package-entries.mjs has no description for it`);
  }
  entries.sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name));
  for (const { name, target } of entries) rows.push([`crypto-api-ng/${name}`, ENTRY_ALGORITHMS[name], target]);
  const lines = ['| Import | Provides | Minified | Min + gzip |', '|---|---|---:|---:|'];
  for (const [label, provides, target] of rows) {
    const { min, gzip } = await size(join(PKG_ROOT, target));
    lines.push(`| \`${label}\` | ${provides} | ${kb(min)} KB | ${kb(gzip)} KB |`);
  }
  return lines.join('\n');
}

if (process.argv.includes('--entries') || process.argv.includes('--write')) {
  const table = await entryTable();
  if (process.argv.includes('--write')) {
    const file = join(PKG_ROOT, 'README.md');
    const text = readFileSync(file, 'utf8');
    const [open, close] = README_MARKERS;
    const a = text.indexOf(open);
    const b = text.indexOf(close);
    if (a < 0 || b < a) throw new Error(`${file} has no ${open} ... ${close} block`);
    writeFileSync(file, text.slice(0, a + open.length) + '\n' + table + '\n' + text.slice(b));
    console.log(`updated ${file}`);
  } else {
    console.log(table);
  }
  process.exit(0);
}

const rows = [];
const entries = [
  ...FAMILIES.map((f) => [`hasher/${f.file}.mjs`, f.className]),
  ['mac/hmac.mjs', 'Hmac'],
  ['crypto-api.mjs', 'full facade (all hashers, HMAC, encoders)'],
];
for (const [rel, label] of entries) {
  const row = { label, rel };
  for (const [name, dir] of Object.entries(trees)) {
    const file = join(dir, rel);
    row[name] = existsSync(file) ? await size(file) : null;
  }
  rows.push(row);
}

if (process.argv.includes('--json')) {
  console.log(JSON.stringify(rows, null, 2));
} else {
  const kb = (n) => (n / 1024).toFixed(1);
  console.log('| Import | 0.8.5 min | 0.8.5 gzip | port min | port gzip | gzip ratio |');
  console.log('|---|---:|---:|---:|---:|---:|');
  for (const r of rows) {
    const o = r.original, p = r.port;
    console.log(`| ${r.label} | ${o ? kb(o.min) : '-'} KB | ${o ? kb(o.gzip) : '-'} KB | ${p ? kb(p.min) : '-'} KB | ${p ? kb(p.gzip) : '-'} KB | ${o && p ? (p.gzip / o.gzip).toFixed(2) + 'x' : '-'} |`);
  }
}
