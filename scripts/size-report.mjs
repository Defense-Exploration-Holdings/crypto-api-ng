// Bundle-size report: every deep import and the full facade, minified and gzipped, for the original
// crypto-api 0.8.5 (the `crypto-api/` submodule) and this port. Needs `npm ci` and `zig build js --release=small`.
//
//   node scripts/size-report.mjs            Markdown table on stdout
//   node scripts/size-report.mjs --json
import { build } from 'esbuild';
import { gzipSync } from 'node:zlib';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { FAMILIES } from '../test/harness/catalog.mjs';

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
