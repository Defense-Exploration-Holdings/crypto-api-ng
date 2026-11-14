#!/usr/bin/env node
// Vendors the original crypto-api 0.8.5 sources (git submodule `crypto-api/`)
// into packages/crypto-api, changing nothing but relative import specifiers
// (an explicit ".mjs" is appended so Node's native ESM resolver accepts them).
//
//   packages/crypto-api/legacy/hasher/<algo>.mjs
//       the 12 original hasher engines, verbatim. They import the base classes and
//       tools from the single copy in src/ (specifiers become "../../src/..."), so a
//       facade class extending an engine still satisfies `instanceof Hasher32le`.
//   packages/crypto-api/src/
//       the verbatim public tree: base classes, hmac, encoders, tools,
//       crypto-api.mjs, index.mjs and, until a facade replaces them, the 12 hasher
//       files (specifiers get an explicit ".mjs")
//
// Files under src/ that contain the line `// crypto-api-ng:facade` are hand-written
// facades: this script never overwrites them and the verbatim check skips them.
//
//   node scripts/vendor-legacy.mjs           write the files
//   node scripts/vendor-legacy.mjs --check   exit 1 if anything would change
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { join, relative, dirname, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FACADE_MARKER = '// crypto-api-ng:facade';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const oracleSrc = join(repoRoot, 'crypto-api', 'src');
const pkgRoot = join(repoRoot, 'packages', 'crypto-api');

export const SPECIFIER_RE = /(\b(?:from|import)\s*)(["'])(\.{1,2}\/[^"']*)\2/g;

/**
 * Rewrite relative import specifiers of an original file `rel` (path under
 * crypto-api/src, e.g. "hasher/md5.mjs"). Nothing else in the text changes.
 *   kind "src":    append ".mjs"
 *   kind "legacy": point at the same module in the package's src/ tree
 */
export function rewriteSpecifiers(text, rel, kind) {
  return text.replace(SPECIFIER_RE, (m, kw, q, spec) => {
    const target = posix.normalize(posix.join(posix.dirname(rel), spec));
    const withExt = /\.[cm]?js$/.test(target) ? target : `${target}.mjs`;
    let out;
    if (kind === 'src') {
      out = /\.[cm]?js$/.test(spec) ? spec : `${spec}.mjs`;
    } else {
      out = posix.relative(posix.join('legacy', posix.dirname(rel)), posix.join('src', withExt));
      if (!out.startsWith('.')) out = `./${out}`;
    }
    return `${kw}${q}${out}${q}`;
  });
}

export function listOriginalFiles() {
  const out = [];
  (function walk(dir) {
    for (const name of readdirSync(dir).sort()) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (name.endsWith('.mjs')) out.push(relative(oracleSrc, p));
    }
  })(oracleSrc);
  return out;
}

// The 12 algorithm engines. Base classes (hasher*.mjs) and tools stay in src/ only.
export const BASE_CLASSES = ['hasher.mjs', 'hasher8.mjs', 'hasher32be.mjs', 'hasher32le.mjs'];
export const isLegacyFile = (rel) =>
  rel.startsWith('hasher/') && !BASE_CLASSES.includes(rel.slice('hasher/'.length));

export function isFacade(path) {
  return existsSync(path) && readFileSync(path, 'utf8').split('\n').some((l) => l.trim() === FACADE_MARKER);
}

/** Every (destination → expected content) pair this script manages. */
export function plan() {
  const entries = [];
  for (const rel of listOriginalFiles()) {
    const original = readFileSync(join(oracleSrc, rel), 'utf8');
    if (isLegacyFile(rel)) {
      entries.push({ rel, dest: join(pkgRoot, 'legacy', rel), content: rewriteSpecifiers(original, rel, 'legacy'), kind: 'legacy' });
    }
    entries.push({ rel, dest: join(pkgRoot, 'src', rel), content: rewriteSpecifiers(original, rel, 'src'), kind: 'src' });
  }
  return entries;
}

function main() {
  if (!existsSync(oracleSrc)) {
    console.error('crypto-api submodule missing. Run: git submodule update --init crypto-api');
    process.exit(2);
  }
  const check = process.argv.includes('--check');
  let changed = 0;
  let skipped = 0;
  for (const e of plan()) {
    if (e.kind === 'src' && isFacade(e.dest)) { skipped++; continue; }
    const current = existsSync(e.dest) ? readFileSync(e.dest, 'utf8') : null;
    if (current === e.content) continue;
    changed++;
    if (check) {
      console.error(`out of date: ${relative(repoRoot, e.dest)}`);
    } else {
      mkdirSync(dirname(e.dest), { recursive: true });
      writeFileSync(e.dest, e.content);
    }
  }
  const verb = check ? 'out of date' : 'written';
  console.log(`vendor-legacy: ${changed} file(s) ${verb}, ${skipped} facade(s) left alone`);
  if (check && changed) process.exit(1);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
