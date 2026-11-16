// The JSR package (jsr.io): jsr.json follows package.json, the staged package has declarations for every module,
// and `deno publish --dry-run` (publish checks and the slow-types check) passes on it when Deno is installed
// (CI installs it from npm: `npm install --no-save deno@<version>`).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, mkdirSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO_ROOT } from '../harness/paths.mjs';
import { SCRIPTS, PKG_ROOT, ensureBuilt } from './support.js';

const { checkConfig, jsrExports, stage } = await import(join(SCRIPTS, 'build-jsr.mjs'));
const pkg = JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8'));
const jsr = JSON.parse(readFileSync(join(PKG_ROOT, 'jsr.json'), 'utf8'));
const DENO = [join(REPO_ROOT, 'node_modules', '.bin', 'deno'), 'deno'].find((c) => spawnSync(c, ['--version']).status === 0);

let work;
before(async () => {
  await ensureBuilt();
  work = mkdtempSync(join(tmpdir(), 'crypto-api-jsr-'));
});
after(() => rmSync(work, { recursive: true, force: true }));

describe('jsr.json', () => {
  it('matches package.json (run: node scripts/build-jsr.mjs --sync)', () => {
    assert.deepEqual(checkConfig(), []);
  });

  it('exports the main entry and every per-algorithm entry of the npm exports map', () => {
    const npmEntries = Object.keys(pkg.exports).filter((k) => k !== '.' && !k.includes('*') && !/\.(json|js|mjs)$/.test(k));
    assert.deepEqual(Object.keys(jsr.exports).sort(), ['.', ...npmEntries].sort());
    assert.equal(jsr.exports['.'], './src/index.mjs');
    assert.equal(jsr.exports['./md5'], './src/hasher/md5.mjs');
    assert.deepEqual(jsrExports(pkg), jsr.exports);
  });

  it('is published under a scoped name, with the license of the package', () => {
    assert.match(jsr.name, /^@[a-z0-9-]+\/[a-z0-9-]+$/);
    assert.equal(jsr.license, pkg.license);
  });
});

describe('staged JSR package', () => {
  let out;
  before(() => {
    out = join(work, 'stage');
    stage({ out });
  });

  it('has the files the entry points load, the generated wasm modules and the declarations', () => {
    for (const f of ['jsr.json', 'README.md', 'LICENSE', 'CHANGELOG.md', 'types.d.mts', 'wasm/md.mjs', 'legacy/hasher/md5.mjs', 'src/hasher/hasher.mjs']) {
      assert.ok(existsSync(join(out, f)), f);
    }
    for (const f of Object.values(jsr.exports)) {
      assert.ok(readFileSync(join(out, f), 'utf8').startsWith(`// @ts-self-types="./${f.split('/').pop().replace('.mjs', '.d.mts')}"\n`), f);
    }
  });

  it('does not contain the CommonJS bundle, tests or examples', () => {
    for (const f of ['index.js', 'crypto-api.js', 'crypto-api.min.js', 'package.json', 'example']) assert.ok(!existsSync(join(out, f)), f);
  });

  it('points every type import at the staged declarations', () => {
    const text = readFileSync(join(out, 'src/hasher/blake2b.d.mts'), 'utf8');
    assert.ok(text.includes('types.d.mts"') && !text.includes('types.js"'));
  });

  it('can be staged from another checkout with the JSR settings of this one (release tags that predate jsr.json)', () => {
    const other = join(work, 'other', 'packages', 'crypto-api');
    mkdirSync(other, { recursive: true });
    for (const f of ['src', 'legacy', 'wasm', 'README.md', 'LICENSE', 'CHANGELOG.md', 'types.d.ts', 'package.json']) cpSync(join(PKG_ROOT, f), join(other, f), { recursive: true });
    writeFileSync(join(other, 'package.json'), JSON.stringify({ ...pkg, version: '9.9.9' }));
    const o = join(work, 'stage-other');
    const staged = stage({ out: o, packageRoot: other, config: join(PKG_ROOT, 'jsr.json') });
    assert.equal(staged.version, '9.9.9');
    assert.equal(staged.name, jsr.name);
  });

  it('refuses a package without TypeScript declarations', () => {
    const other = join(work, 'old', 'packages', 'crypto-api');
    mkdirSync(other, { recursive: true });
    for (const f of ['src', 'legacy', 'wasm', 'README.md', 'LICENSE', 'CHANGELOG.md', 'package.json']) cpSync(join(PKG_ROOT, f), join(other, f), { recursive: true });
    assert.throws(() => stage({ out: join(work, 'stage-old'), packageRoot: other, config: join(PKG_ROOT, 'jsr.json') }), /types\.d\.ts is missing/);
  });

  it('passes deno publish --dry-run, slow types included', { skip: DENO ? false : 'deno is not installed' }, () => {
    const r = spawnSync(DENO, ['publish', '--dry-run'], { cwd: out, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stderr + r.stdout, /Dry run complete/);
    assert.ok(!/warning\[|error\[/.test(r.stderr + r.stdout), r.stderr + r.stdout);
  });

  it('hashes in Deno', { skip: DENO ? false : 'deno is not installed' }, () => {
    const code = `import S from ${JSON.stringify('file://' + join(out, 'src/hasher/sha256.mjs'))};
      const h = new S(); h.update('abc'); console.log(h.digest('hex'));`;
    const file = join(work, 'run.mjs');
    writeFileSync(file, code);
    const r = spawnSync(DENO, ['run', '--no-prompt', file], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});
