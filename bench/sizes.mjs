// Size report: wasm bytes per family (small vs fast, raw and compressed) and the JS a user
// downloads per deep import (unminified module closure), original vs v1.
import { readFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { gzipSync, brotliCompressSync } from 'node:zlib';
import { ORIG_SRC, V1_SRC, HASHER_FILES, REPO, prepareOriginal, assertV1Built } from './lib/trees.mjs';

const comp = (buf) => ({
  raw: buf.length,
  gzip: gzipSync(buf, { level: 9 }).length,
  brotli: brotliCompressSync(buf).length,
});

function buildWasm(mode) {
  const prefix = join(REPO, 'bench', '.cache', `zig-${mode}`);
  mkdirSync(prefix, { recursive: true });
  const r = spawnSync('zig', ['build', 'families', `--release=${mode}`, '-p', prefix], { cwd: REPO, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`zig build families --release=${mode} failed:\n${r.stderr}`);
  const dir = join(prefix, 'wasm');
  const out = {};
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.wasm'))) {
    out[f.replace(/\.wasm$/, '')] = comp(readFileSync(join(dir, f)));
  }
  return out;
}

const IMPORT_RE = /(?:from|import)\s*["'](\.{1,2}\/[^"']+)["']/g;

/** Every file reachable from `entry` through relative imports. */
export function closure(entry) {
  const seen = new Set();
  const walk = (p) => {
    if (seen.has(p)) return;
    seen.add(p);
    const text = readFileSync(p, 'utf8');
    for (const m of text.matchAll(IMPORT_RE)) walk(resolve(dirname(p), m[1]));
  };
  walk(entry);
  return [...seen];
}

function jsSize(entry) {
  const files = closure(entry);
  const buf = Buffer.concat(files.map((f) => readFileSync(f)));
  return { files: files.length, ...comp(buf) };
}

export function run({ log = () => {} } = {}) {
  prepareOriginal();
  assertV1Built();
  const out = { wasm: {}, js: [] };
  for (const mode of ['small', 'fast']) {
    try {
      out.wasm[mode] = buildWasm(mode);
    } catch (e) {
      log(`wasm ${mode}: ${e.message}`);
    }
  }
  const targets = [
    ...HASHER_FILES.map((f) => ({ id: f, rel: `hasher/${f}.mjs` })),
    { id: 'crypto-api (all hashers)', rel: 'crypto-api.mjs' },
  ];
  for (const t of targets) {
    out.js.push({ id: t.id, orig: jsSize(join(ORIG_SRC, t.rel)), v1: jsSize(join(V1_SRC, t.rel)) });
  }
  log(`sizes: ${Object.keys(out.wasm.small ?? {}).length} wasm families, ${out.js.length} import closures`);
  return out;
}
