#!/usr/bin/env node
// Stages the JSR (jsr.io) package from packages/crypto-api.
//
//   node scripts/build-jsr.mjs --sync            rewrite packages/crypto-api/jsr.json (version, license, exports) from package.json
//   node scripts/build-jsr.mjs --check           fail when jsr.json disagrees with package.json
//   node scripts/build-jsr.mjs --out <dir>       stage the package into <dir> (created, must be empty or missing)
//       [--package-root <dir>] [--config <jsr.json>]   stage another checkout's packages/crypto-api, for example a release tag
//
// jsr.json is committed, but package.json stays the source of truth for the version, the license and the
// per-algorithm entry points. JSR exports are plain file paths, so the entries of the npm `exports` map become
// `./<name>` -> the `default` file, and `.` -> ./src/index.mjs (the facade with the default export). The npm
// patterns (`./src/*`, the 0.8.5 deep paths) cannot be expressed; JSR users import the named entries.
//
// Staging copies the files JSR needs into a directory outside the repository (so no .gitignore applies to the
// generated wasm/ modules) and puts `// @ts-self-types="./x.d.mts"` on the first line of every module that has a
// sibling declaration file. JSR does not look for .d.mts files by itself, and without the directive every entry
// point is a JavaScript module without types ("slow types"). The files in the repository are not touched.
//
// Prerequisite: `zig build js --release=small` (writes packages/crypto-api/wasm/, which the facades import).
// Nothing here publishes anything; `deno publish` in the staged directory does, in .github/workflows/publish-jsr.yml.
import { readFileSync, writeFileSync, mkdirSync, cpSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { entriesFromExports, PKG_ROOT } from './package-entries.mjs';

const JSR_JSON = join(PKG_ROOT, 'jsr.json');
/** What goes into the JSR package, relative to packages/crypto-api. */
export const STAGED = ['src', 'legacy', 'wasm', 'README.md', 'LICENSE', 'CHANGELOG.md'];
/** The shared declarations (`import type ... from "../types.js"` in every .d.mts), staged as a .d.mts file. */
const TYPES_SOURCE = 'types.d.ts';
const TYPES_STAGED = 'types.d.mts';

export function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

/** `exports` of jsr.json derived from the npm `exports` map. */
export function jsrExports(pkg) {
  const out = { '.': './src/index.mjs' };
  for (const { name, target } of entriesFromExports(pkg)) out[`./${name}`] = target;
  return out;
}

/** The jsr.json fields that follow package.json. */
export function derived(pkg, current) {
  return { ...current, version: pkg.version, license: pkg.license, exports: jsrExports(pkg) };
}

export function checkConfig() {
  const pkg = readJson(join(PKG_ROOT, 'package.json'));
  const jsr = readJson(JSR_JSON);
  const want = derived(pkg, jsr);
  const problems = [];
  if (jsr.version !== want.version) problems.push(`version ${jsr.version} in jsr.json, ${want.version} in package.json`);
  if (jsr.license !== want.license) problems.push(`license ${jsr.license} in jsr.json, ${want.license} in package.json`);
  if (JSON.stringify(jsr.exports) !== JSON.stringify(want.exports)) problems.push('exports in jsr.json differ from the entries of the npm exports map');
  if (!/^@[a-z0-9-]+\/[a-z0-9-]+$/.test(jsr.name || '')) problems.push(`jsr.json name ${jsr.name} is not @scope/name`);
  for (const [key, file] of Object.entries(jsr.exports)) {
    if (!existsSync(join(PKG_ROOT, file))) problems.push(`${key}: ${file} does not exist`);
  }
  return problems;
}

export function sync() {
  const pkg = readJson(join(PKG_ROOT, 'package.json'));
  writeFileSync(JSR_JSON, JSON.stringify(derived(pkg, readJson(JSR_JSON)), null, 2) + '\n');
}

/**
 * Stage the package; returns the staged jsr.json.
 *
 * `packageRoot` is the packages/crypto-api directory to publish (default: this checkout). `config` is the jsr.json
 * that supplies the name and the file list (default: the one in `packageRoot`). The version, the license and the
 * exports always come from the package.json being published, so an older release tag, which has no jsr.json
 * of its own, can be staged with the jsr.json of a newer checkout.
 */
export function stage({ out, packageRoot = PKG_ROOT, config = join(packageRoot, 'jsr.json') }) {
  const pkg = readJson(join(packageRoot, 'package.json'));
  const jsr = derived(pkg, readJson(config));
  if (!/^@[a-z0-9-]+\/[a-z0-9-]+$/.test(jsr.name || '')) throw new Error(`jsr.json name ${jsr.name} is not @scope/name`);
  if (existsSync(out) && readdirSync(out).length) throw new Error(`${out} is not empty`);
  for (const entry of STAGED) {
    if (!existsSync(join(packageRoot, entry))) {
      throw new Error(`missing ${entry} in ${packageRoot} (run: zig build js --release=small)`);
    }
  }
  for (const [key, file] of Object.entries(jsr.exports)) {
    if (!existsSync(join(packageRoot, file))) throw new Error(`${key}: ${file} does not exist in ${packageRoot}`);
  }
  mkdirSync(out, { recursive: true });
  for (const entry of STAGED) cpSync(join(packageRoot, entry), join(out, entry), { recursive: true });

  // Deno resolves `../types.js` to nothing: there is no types.js, and the declaration lives in types.d.ts.
  if (!existsSync(join(packageRoot, TYPES_SOURCE))) throw new Error(`${TYPES_SOURCE} is missing: JSR needs the TypeScript declarations (1.2.0 or later)`);
  cpSync(join(packageRoot, TYPES_SOURCE), join(out, TYPES_STAGED));
  jsr.publish = { ...jsr.publish, include: [...jsr.publish.include, TYPES_STAGED] };
  writeFileSync(join(out, 'jsr.json'), JSON.stringify(jsr, null, 2) + '\n');

  const declarations = [];
  (function walk(dir) {
    for (const name of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, name.name);
      if (name.isDirectory()) walk(path);
      else if (name.name.endsWith('.d.mts')) declarations.push(path);
    }
  })(join(out, 'src'));
  for (const decl of declarations) {
    const text = readFileSync(decl, 'utf8');
    const rewritten = text.replace(/(["'])((?:\.\.\/)+)types\.js\1/g, `$1$2${TYPES_STAGED}$1`);
    if (rewritten !== text) writeFileSync(decl, rewritten);
    const source = decl.replace(/\.d\.mts$/, '.mjs');
    if (existsSync(source)) {
      writeFileSync(source, `// @ts-self-types="./${basename(decl)}"\n${readFileSync(source, 'utf8')}`);
    }
  }
  for (const file of Object.values(jsr.exports)) {
    if (!readFileSync(join(out, file), 'utf8').startsWith('// @ts-self-types=')) {
      throw new Error(`${file} has no declaration file next to it`);
    }
  }
  return jsr;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args[0] === '--sync') {
    sync();
    console.log('jsr.json updated');
  } else if (args[0] === '--check') {
    const problems = checkConfig();
    if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
    console.log('jsr.json matches package.json');
  } else if (args[0] === '--out' && args[1]) {
    const opts = { out: resolve(args[1]) };
    for (let i = 2; i < args.length; i += 2) {
      if (args[i] === '--package-root' && args[i + 1]) opts.packageRoot = resolve(args[i + 1]);
      else if (args[i] === '--config' && args[i + 1]) opts.config = resolve(args[i + 1]);
      else { console.error(`unknown argument ${args[i]}`); process.exit(2); }
    }
    const jsr = stage(opts);
    console.log(`staged ${jsr.name}@${jsr.version} in ${opts.out}`);
  } else {
    console.error('usage: build-jsr.mjs --sync | --check | --out <dir> [--package-root <packages/crypto-api>] [--config <jsr.json>]');
    process.exit(2);
  }
}
