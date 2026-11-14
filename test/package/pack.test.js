// `npm pack` of the staged package: tarball contents, configurable package name, and smoke tests that
// consume the extracted tarball the way users do (require, native ESM deep imports, a bundler resolving
// extensionless paths, the shipped Node examples).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, posix } from 'node:path';
import { execFileSync } from 'node:child_process';
import { build } from 'esbuild';
import { SCRIPTS, ensureBuilt } from './support.js';

let work;
let buildPackage;
const packed = {}; // name -> { tarball, files, dir }

const NAMES = ['crypto-api-ng', 'crypto-api'];

before(async () => {
  await ensureBuilt();
  buildPackage = await import(join(SCRIPTS, 'build-package.mjs'));
  work = mkdtempSync(join(tmpdir(), 'crypto-api-pack-'));
  for (const name of NAMES) {
    const out = join(work, name.replace('/', '_'));
    const stageDir = join(out, 'stage');
    buildPackage.stage({ out: stageDir, name });
    const res = buildPackage.pack({ stageDir, dest: out });
    // Install like a package manager: extract into <project>/node_modules/<name>.
    const project = join(out, 'project');
    const dir = join(project, 'node_modules', name);
    mkdirSync(dir, { recursive: true });
    execFileSync('tar', ['-xzf', res.tarball, '-C', dir, '--strip-components=1']);
    packed[name] = { ...res, project, dir, stageDir };
  }
});

after(() => rmSync(work, { recursive: true, force: true }));

const node = (cwd, args, opts = {}) => execFileSync(process.execPath, args, { cwd, encoding: 'utf8', ...opts });

function walk(dir) {
  const out = [];
  (function rec(d) {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) rec(p); else out.push(p);
    }
  })(dir);
  return out;
}

describe('tarball contents', () => {
  it('has exactly the files package.json lists, and nothing else', () => {
    const { files } = packed['crypto-api-ng'];
    const top = new Set(files.map((f) => f.split('/')[0]));
    assert.deepEqual([...top].sort(), [
      'CHANGELOG.md', 'LICENSE', 'README.md', 'crypto-api.js', 'crypto-api.min.js', 'crypto-api.min.js.map',
      'example', 'index.js', 'legacy', 'package.json', 'src', 'wasm',
    ]);
  });

  it('has every public path of crypto-api 0.8.5 (with the .mjs extension)', () => {
    const { files } = packed['crypto-api-ng'];
    const original = walk(join(SCRIPTS, '..', 'crypto-api', 'src'))
      .map((p) => 'src/' + p.split('/crypto-api/src/')[1])
      .filter((p) => p !== 'src/index.mjs');
    for (const rel of original) assert.ok(files.includes(rel), `missing ${rel}`);
    assert.ok(files.includes('src/index.mjs'));
    assert.ok(files.includes('index.js'));
  });

  it('ships no sources, tests, toolchain files or build output', () => {
    const { files } = packed['crypto-api-ng'];
    for (const f of files) {
      assert.doesNotMatch(f, /(^|\/)(test|node_modules|zig-out|\.zig-cache|dist)\//, f);
      assert.doesNotMatch(f, /\.(zig|zon|tgz|wasm)$/, f);
    }
  });

  it('every relative import in the shipped modules resolves inside the tarball', () => {
    const { dir } = packed['crypto-api-ng'];
    const re = /(?:from|import)\s*(["'])(\.{1,2}\/[^"']+)\1/g;
    let checked = 0;
    for (const file of walk(dir).filter((f) => f.endsWith('.mjs') && !f.includes('/example/'))) {
      for (const m of readFileSync(file, 'utf8').matchAll(re)) {
        const target = join(dirname(file), m[2]);
        assert.ok(existsSync(target), `${file.slice(dir.length)} imports ${m[2]}`);
        checked++;
      }
    }
    assert.ok(checked > 50);
  });

  // The budget is for the shipped wasm (small, fast). release-gates.sh sets this for debug and safe builds.
  it('stays small', { skip: process.env.CRYPTO_API_SKIP_SIZE_BUDGET === '1' }, () => {
    const { size, unpackedSize } = packed['crypto-api-ng'];
    assert.ok(size < 1.5 * 1024 * 1024, `tarball ${size} bytes`);
    assert.ok(unpackedSize < 3 * 1024 * 1024, `unpacked ${unpackedSize} bytes`);
  });
});

describe('package name is configurable', () => {
  for (const name of NAMES) {
    it(`${name}: package.json, README and examples use it`, () => {
      const { dir } = packed[name];
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
      assert.equal(pkg.name, name);
      assert.equal(pkg.main, 'index.js');
      assert.equal(pkg.private, true, 'stays private until the release gate');
      assert.equal(pkg.exports, undefined, 'no exports map in v1: deep paths must stay reachable');
      assert.equal(pkg.type, undefined);
      for (const f of walk(dir).filter((p) => /\.(md|html|mjs|cjs|json)$/.test(p) && !p.includes('/wasm/') && !p.includes('/legacy/'))) {
        assert.doesNotMatch(readFileSync(f, 'utf8'), /\{\{name\}\}/, f);
      }
      assert.match(readFileSync(join(dir, 'README.md'), 'utf8'), new RegExp(`npm install ${name}\\n`));
      assert.match(readFileSync(join(dir, 'README.md'), 'utf8'), new RegExp(`from "${name}/src/hasher/sha256\\.mjs"`));
    });
  }

  it('--public drops "private"; an invalid name is rejected', () => {
    const out = join(work, 'public');
    const staged = buildPackage.stage({ out, name: 'crypto-api-ng', publicPackage: true });
    assert.equal(staged.private, undefined);
    assert.throws(() => buildPackage.stage({ out: join(work, 'bad'), name: 'Not A Name' }), /invalid package name/);
  });
});

describe('consuming the extracted tarball', () => {
  for (const name of NAMES) {
    describe(name, () => {
      const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
      const MD5_ABC = '900150983cd24fb0d6963f7d28e17f72';

      it('require() returns CryptoApi (the repaired main)', () => {
        const { project } = packed[name];
        const out = node(project, ['-e', `
          const C = require(${JSON.stringify(name)});
          console.log(C.hash('sha256', 'abc'), C.hash('md5', 'abc'), typeof C.getHasher, Object.keys(C.encoder).join());
        `]).trim();
        assert.equal(out, `${SHA256_ABC} ${MD5_ABC} function fromUtf,fromArrayBuffer,toHex,toBase64`);
      });

      it('native ESM deep imports work, and the default import is CryptoApi', () => {
        const { project } = packed[name];
        writeFileSync(join(project, 'deep.mjs'), `
          import Sha256 from '${name}/src/hasher/sha256.mjs';
          import Md5 from '${name}/src/hasher/md5.mjs';
          import Hmac from '${name}/src/mac/hmac.mjs';
          import Hasher32be from '${name}/src/hasher/hasher32be.mjs';
          import { toHex } from '${name}/src/encoder/hex.mjs';
          import { fromUtf } from '${name}/src/encoder/utf.mjs';
          import FromIndex from '${name}/src/index.mjs';
          import FromMain from '${name}';
          const h = new Sha256(); h.update(fromUtf('abc'));
          const m = new Hmac(fromUtf('key'), new Md5()); m.update(fromUtf('The quick brown fox jumps over the lazy dog'));
          console.log(toHex(h.finalize()), toHex(m.finalize()), h instanceof Hasher32be,
            FromIndex.hash('md5', 'abc') === FromMain.hash('md5', 'abc'), FromIndex.hash('md5', 'abc'));
        `);
        const out = node(project, ['deep.mjs']).trim();
        assert.equal(out, `${SHA256_ABC} 80070713463e7749b90c2dc24911e275 true true ${MD5_ABC}`);
      });

      it('a bundler resolving the extensionless 0.8.5 paths builds a working bundle', async () => {
        const { project } = packed[name];
        writeFileSync(join(project, 'entry.js'), `
          import Sha256 from '${name}/src/hasher/sha256';
          import Md5 from '${name}/src/hasher/md5';
          import {toHex} from '${name}/src/encoder/hex';
          const a = new Sha256(); a.update('abc');
          const b = new Md5(); b.update('abc');
          console.log(toHex(a.finalize()), toHex(b.finalize()));
        `);
        await build({
          entryPoints: [join(project, 'entry.js')], bundle: true, format: 'iife', platform: 'browser',
          resolveExtensions: ['.mjs', '.js'], // what webpack does by default
          outfile: join(project, 'bundled.js'), logLevel: 'error',
        });
        assert.equal(node(project, ['bundled.js']).trim(), `${SHA256_ABC} ${MD5_ABC}`);
      });

      it('the shipped Node examples run', () => {
        const { dir } = packed[name];
        const mjs = node(dir, ['example/node.mjs']);
        const cjs = node(dir, ['example/node.cjs']);
        assert.match(mjs, /^sha256: ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d\nhmac-md5: [0-9a-f]{32}\n$/);
        assert.match(cjs, /^sha256: ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d\nhmac-md5: [0-9a-f]{32}\n$/);
        // Both examples compute the same HMAC.
        assert.equal(mjs.split('\n')[1], cjs.split('\n')[1]);
      });
    });
  }
});
