// The `exports` map: per-algorithm entry points that keep a bundle to what it imports, and the guarantee that
// every path that worked without an `exports` map (0.8.5 deep paths, the main entry) still resolves to the same file.
//
// Consumes a staged copy of the package installed as <project>/node_modules/crypto-api-ng, like a package manager would.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { build } from 'esbuild';
import { REPO_ROOT } from '../harness/paths.mjs';
import { SCRIPTS, PKG_ROOT, ensureBuilt } from './support.js';

const { ENTRY_ALGORITHMS, entriesFromExports } = await import(join(SCRIPTS, 'package-entries.mjs'));
const TSC = join(REPO_ROOT, 'node_modules', 'typescript', 'bin', 'tsc');
const NAME = 'crypto-api-ng';

let work;
let project;
let dir; // <project>/node_modules/crypto-api-ng
let pkg;
const entries = entriesFromExports(JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8')));

before(async () => {
  await ensureBuilt();
  const { stage } = await import(join(SCRIPTS, 'build-package.mjs'));
  work = mkdtempSync(join(tmpdir(), 'crypto-api-exports-'));
  project = join(work, 'project');
  dir = join(project, 'node_modules', NAME);
  mkdirSync(project, { recursive: true });
  pkg = stage({ out: dir, name: NAME });
  writeFileSync(join(project, 'package.json'), '{"name":"consumer","private":true,"type":"module"}\n');
});

after(() => rmSync(work, { recursive: true, force: true }));

/** Resolve specifiers the way Node's ESM loader does from inside the project; returns { specifier: file path | error code }. */
function resolveAll(specifiers) {
  const script = `
    const out = {};
    for (const s of ${JSON.stringify(specifiers)}) {
      try { out[s] = new URL(import.meta.resolve(s)).pathname; } catch (e) { out[s] = e.code || String(e); }
    }
    console.log(JSON.stringify(out));`;
  return JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', script], { cwd: project, encoding: 'utf8' }));
}

describe('exports map', () => {
  it('has an entry, a description and a README row for every algorithm, and nothing else', () => {
    const names = entries.map((e) => e.name).sort();
    assert.deepEqual(names, Object.keys(ENTRY_ALGORITHMS).sort(), 'exports and scripts/package-entries.mjs disagree');

    // Every concrete hasher class under src/hasher (the shared bases are not entries) has an entry.
    const bases = new Set(['hasher', 'sponge']);
    const hashers = readdirSync(join(PKG_ROOT, 'src', 'hasher'))
      .filter((f) => f.endsWith('.d.mts'))
      .map((f) => f.slice(0, -'.d.mts'.length))
      .filter((n) => !bases.has(n));
    for (const h of hashers) assert.ok(names.includes(h), `src/hasher/${h}.mjs has no entry "./${h}" in exports`);
    assert.ok(names.includes('hmac'));

    const readme = readFileSync(join(PKG_ROOT, 'README.md'), 'utf8');
    const table = readme.slice(readme.indexOf('<!-- entry-sizes:start -->'), readme.indexOf('<!-- entry-sizes:end -->'));
    for (const n of names) assert.ok(table.includes(`\`${NAME}/${n}\``), `README table has no row for ${n} (node scripts/size-report.mjs --write)`);
  });

  it('every entry points at a file and a declaration that are in the package, and typesVersions agrees', () => {
    for (const { name, target, types } of entries) {
      assert.ok(existsSync(join(dir, target)), `${name} -> ${target}`);
      assert.ok(types && existsSync(join(dir, types)), `${name} has no declaration (${types})`);
      assert.deepEqual(pkg.typesVersions['*'][name], [types.replace(/^\.\//, '')], `typesVersions for ${name}`);
    }
    assert.deepEqual(Object.keys(pkg.typesVersions['*']).sort(), entries.map((e) => e.name).sort());
  });

  it('each entry is the same module as its deep path, so instanceof agrees between the two', () => {
    const specifiers = entries.flatMap((e) => [`${NAME}/${e.name}`, `${NAME}/${e.target.slice(2)}`]);
    const resolved = resolveAll(specifiers);
    for (const e of entries) {
      const a = resolved[`${NAME}/${e.name}`];
      const b = resolved[`${NAME}/${e.target.slice(2)}`];
      assert.ok(a.endsWith(e.target.slice(1)), `${e.name} resolved to ${a}`);
      assert.equal(a, b, e.name);
    }
  });

  it('the main entry and every path of 0.8.5 resolve as they did without an exports map', () => {
    const originalSrc = join(REPO_ROOT, 'crypto-api', 'src');
    const originals = [];
    (function walk(d, rel) {
      for (const f of readdirSync(join(originalSrc, d), { withFileTypes: true })) {
        if (f.isDirectory()) walk(join(d, f.name), `${rel}${f.name}/`);
        else originals.push(`src/${rel}${f.name}`);
      }
    })('', '');
    const files = originals.filter((p) => p.endsWith('.mjs') && p !== 'src/index.mjs').concat('src/index.mjs');

    const specifiers = [NAME, `${NAME}/package.json`, `${NAME}/crypto-api.min.js`, `${NAME}/index.d.ts`, `${NAME}/types.d.ts`,
      `${NAME}/legacy/hasher/md5.mjs`, `${NAME}/wasm/md.mjs`, `${NAME}/example/node.mjs`, `${NAME}/src/wasm/family.mjs`,
      ...files.map((f) => `${NAME}/${f}`),
      // Extensionless, which webpack and friends resolved in 0.8.5 and Node cannot without help from the exports map.
      ...files.map((f) => `${NAME}/${f.slice(0, -'.mjs'.length)}`)];
    const resolved = resolveAll(specifiers);
    for (const f of files) {
      const withExt = resolved[`${NAME}/${f}`];
      assert.equal(withExt, join(dir, f), `${f}`);
      assert.equal(resolved[`${NAME}/${f.slice(0, -4)}`], withExt, `${f} without extension`);
    }
    // The main entry for Node (ESM import and require) is the CommonJS bundle, exactly as `main` was.
    assert.equal(resolved[NAME], join(dir, 'index.js'));
    assert.equal(createRequire(join(project, 'x.js')).resolve(NAME), join(dir, 'index.js'));
    for (const s of ['package.json', 'crypto-api.min.js', 'index.d.ts', 'legacy/hasher/md5.mjs', 'wasm/md.mjs', 'example/node.mjs']) {
      assert.equal(resolved[`${NAME}/${s}`], join(dir, s), s);
    }
  });

  it('an unknown name fails to load', () => {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(`${NAME}/not-an-algorithm`)})`], { cwd: project, encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /ERR_MODULE_NOT_FOUND/);
  });

  it('Node can require() an entry (ES module) and import it', () => {
    const out = execFileSync(process.execPath, ['-e', `
      const m = require(${JSON.stringify(`${NAME}/sha256`)});
      const Sha256 = m.default;
      const h = new Sha256({length: 224}); h.update('abc');
      import(${JSON.stringify(`${NAME}/sha256`)}).then((n) => console.log(n.default === Sha256, Buffer.from(h.finalize(), 'latin1').toString('hex')));
    `], { cwd: project, encoding: 'utf8' }).trim();
    assert.equal(out, 'true 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7');
  });
});

describe('bundling a single entry', () => {
  /** base64 payload of each embedded wasm module, by family file name. */
  const wasmB64 = () => {
    const out = {};
    for (const f of readdirSync(join(dir, 'wasm'))) {
      out[f.replace(/\.mjs$/, '')] = /const b64 = '([^']+)'/.exec(readFileSync(join(dir, 'wasm', f), 'utf8'))[1];
    }
    return out;
  };

  const bundle = async (code, opts = {}) => {
    writeFileSync(join(project, 'entry.js'), code);
    const r = await build({
      entryPoints: [join(project, 'entry.js')], bundle: true, write: false, minify: true, format: 'iife',
      platform: 'browser', logLevel: 'error', metafile: true, ...opts,
    });
    return { text: r.outputFiles[0].text, inputs: Object.keys(r.metafile.inputs) };
  };

  it('contains the wasm of that algorithm and no other, for every hasher entry', async () => {
    const modules = wasmB64();
    const names = Object.keys(modules);
    assert.ok(names.length >= 14, `only ${names.length} wasm modules`);
    const used = {};
    for (const { name } of entries.filter((e) => e.target.includes('/hasher/'))) {
      const { text } = await bundle(`import H from '${NAME}/${name}'; console.log(typeof H);`);
      const present = names.filter((n) => text.includes(modules[n]));
      assert.equal(present.length, 1, `${name}: expected exactly one wasm module in the bundle, found [${present}]`);
      used[name] = present[0];
    }
    // Families that share a module say so here: (md5, md4 or has160 would change this if they were merged).
    assert.equal(used.sha256, 'sha256');
    assert.notEqual(used.sha256, used.sha512);
    assert.equal(new Set(Object.values(used)).size >= 12, true, JSON.stringify(used));
  });

  it('a bundle of the sha256 entry has no other hasher and is small, and its digest is right', async () => {
    const { text, inputs } = await bundle(`
      import Sha256 from '${NAME}/sha256';
      import {toHex} from '${NAME}/encoder/hex';
      const h = new Sha256(); h.update('abc'); console.log(toHex(h.finalize()));`);
    assert.ok(inputs.every((i) => !/\/(md5|sha512|whirlpool|snefru|blake3|keccak|crypto-api)\.mjs$/.test(i)), inputs.join('\n'));
    assert.ok(inputs.some((i) => i.endsWith('/wasm/sha256.mjs')));
    assert.ok(!inputs.some((i) => i.endsWith('/src/crypto-api.mjs')));
    // Whole package, minified, is ~240 KB; one entry is a small fraction (debug wasm builds are bigger, hence the loose bound).
    if (process.env.CRYPTO_API_SKIP_SIZE_BUDGET !== '1') assert.ok(text.length < 120 * 1024, `bundle is ${text.length} bytes`);
    writeFileSync(join(project, 'bundled.js'), text);
    assert.equal(execFileSync(process.execPath, ['bundled.js'], { cwd: project, encoding: 'utf8' }).trim(),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('importing several entries adds only those wasm modules', async () => {
    const modules = wasmB64();
    const { text } = await bundle(`
      import Sha256 from '${NAME}/sha256';
      import Blake3 from '${NAME}/blake3';
      import Hmac from '${NAME}/hmac';
      console.log(Sha256, Blake3, Hmac);`);
    const present = Object.keys(modules).filter((n) => text.includes(modules[n]));
    assert.deepEqual(present.sort(), ['blake3', 'sha256']);
  });

  it('the main entry still carries every hasher, via the ES module for bundlers and the CommonJS bundle for Node', async () => {
    const modules = wasmB64();
    const esm = await bundle(`import C from '${NAME}'; console.log(C.hash('md5', 'abc'));`);
    assert.ok(esm.inputs.some((i) => i.endsWith('/src/index.mjs')), esm.inputs.join('\n'));
    for (const n of Object.keys(modules)) assert.ok(esm.text.includes(modules[n]), `main entry lacks ${n}`);
    const node = await bundle(`import C from '${NAME}'; console.log(C.hash('md5', 'abc'));`, { platform: 'node', format: 'cjs' });
    assert.ok(node.inputs.some((i) => i.endsWith('/index.js')), node.inputs.join('\n'));
  });

  it('the 0.8.5 deep paths still bundle, with and without the extension', async () => {
    for (const ext of ['.mjs', '']) {
      const { text } = await bundle(`
        import Sha256 from '${NAME}/src/hasher/sha256${ext}';
        import {toHex} from '${NAME}/src/encoder/hex${ext}';
        const h = new Sha256(); h.update('abc'); console.log(toHex(h.finalize()));`);
      writeFileSync(join(project, 'bundled.js'), text);
      assert.equal(execFileSync(process.execPath, ['bundled.js'], { cwd: project, encoding: 'utf8' }).trim(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', `extension "${ext}"`);
    }
  });
});

describe('TypeScript', () => {
  const SOURCE = `
import Sha256 from "${NAME}/sha256";
import Sha512 from "${NAME}/sha512";
import Blake3 from "${NAME}/blake3";
import Hmac from "${NAME}/hmac";
import Shake from "${NAME}/shake";
import { toHex } from "${NAME}/encoder/hex";
import { toBase64 } from "${NAME}/encoder/base64";
import { fromUtf } from "${NAME}/encoder/utf";
import { fromArrayBuffer } from "${NAME}/encoder/array-buffer";
import Deep from "${NAME}/src/hasher/sha256.mjs";

const h = new Sha256({ length: 224 });
h.update(fromUtf("a"));
const hex: string = toHex(h.finalize());
const same: typeof Deep = Sha256;
new Sha512({ length: 256 });
new Blake3({ length: 256 });
new Shake({ strength: 128, length: 64 });
const mac = new Hmac("key", new Sha256());
const b64: string = toBase64(mac.finalize()) + fromArrayBuffer(new ArrayBuffer(1));
// @ts-expect-error length 123 is not a SHA-2 size
new Sha256({ length: 123 });
`;
  const compile = (resolution, extra, file) => {
    const src = join(project, file);
    writeFileSync(src, SOURCE);
    return spawnSync(process.execPath, [TSC, '--noEmit', '--strict', '--target', 'es2022', '--moduleResolution', resolution, ...extra, src],
      { cwd: project, encoding: 'utf8' });
  };

  for (const [resolution, extra, file] of [
    ['nodenext', ['--module', 'nodenext'], 'consumer-nodenext.mts'],
    ['bundler', ['--module', 'esnext'], 'consumer-bundler.ts'],
    ['node10', ['--module', 'esnext'], 'consumer-node10.ts'],
  ]) {
    it(`every entry type-checks under moduleResolution ${resolution}`, () => {
      // node10 does not read `exports`: the deep import in SOURCE is an exact path with typesVersions-free resolution,
      // so it is the entries (through typesVersions) that are being checked, and the deep path is skipped there.
      const r = compile(resolution, extra, file);
      const text = (r.stdout + r.stderr).split('\n').filter((l) => !(resolution === 'node10' && /sha256\.mjs/.test(l))).join('\n').trim();
      assert.equal(text, '');
    });
  }
});
