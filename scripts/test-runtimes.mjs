// Runs the packed tarball through the module resolution of Node, Bun and Deno, the way a user installs it.
//
//   node scripts/test-runtimes.mjs                          every runtime found on PATH (node is the control)
//   node scripts/test-runtimes.mjs --runtime bun,deno       only these
//   node scripts/test-runtimes.mjs --tarball dist/crypto-api-ng-1.2.2.tgz --runtime deno
//
// Needs the embedded wasm (`zig build js --release=small`). Without --tarball it builds and packs the package first.
//
// Per runtime it installs the tarball into a temporary project:
//   node   npm install <tarball>
//   bun    bun add <tarball>
//   deno   `npm:crypto-api-ng@<version>` through an import map, served by a throwaway local npm registry that
//          holds only this tarball (Deno has no way to install from a file)
// and runs test/runtimes/consumer.mjs (ESM, bare specifiers through the `exports` map) and consumer.cjs
// (require) with WebAssembly and with it removed. Expected values come from the source tree, computed here under
// Node, plus the original suite's vectors. See test/runtimes/consumer.mjs for what is checked.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const run = promisify(execFile);
const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkgSrc = join(repo, 'packages', 'crypto-api', 'src');
const NAME = 'crypto-api-ng';
const RUNTIMES = {
  node: { bin: process.execPath, versionArgs: ['--version'] },
  bun: { bin: 'bun', versionArgs: ['--version'] },
  deno: { bin: 'deno', versionArgs: ['--version'] },
};

function parseArgs(argv) {
  const args = { runtimes: null, tarball: null, keep: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--runtime') args.runtimes = argv[++i].split(',');
    else if (a === '--tarball') args.tarball = resolve(argv[++i]);
    else if (a === '--keep') args.keep = true;
    else throw new Error(`unknown argument ${a}`);
  }
  return args;
}

const imp = (rel) => import(pathToFileURL(join(pkgSrc, rel)).href);

/** Everything the consumer test compares against, computed from the source tree (the parity-tested engines). */
async function buildExpected(version) {
  const { FAMILIES, VARIANTS, HMAC_VARIANTS } = await import(pathToFileURL(join(repo, 'test', 'harness', 'catalog.mjs')).href);
  const { entriesFromExports } = await import(pathToFileURL(join(repo, 'scripts', 'package-entries.mjs')).href);
  const { toHex } = await imp('encoder/hex.mjs');
  const { toBase64 } = await imp('encoder/base64.mjs');
  const { fromUtf } = await imp('encoder/utf.mjs');
  const CryptoApi = (await imp('index.mjs')).default;
  const Hmac = (await imp('mac/hmac.mjs')).default;
  const Pbkdf2 = (await imp('kdf/pbkdf2.mjs')).default;
  const Hkdf = (await imp('kdf/hkdf.mjs')).default;
  const Argon2 = (await imp('kdf/argon2.mjs')).default;
  const Scrypt = (await imp('kdf/scrypt.mjs')).default;
  const vectors = (name) => JSON.parse(readFileSync(join(repo, 'test', 'vectors', `${name}.json`), 'utf8'));

  const inputs = [['empty', ''], ['abc', 'abc'], ['1000 bytes', 'xyz'.repeat(333) + 'x']];
  const classes = {};
  const hashers = [];
  // Hashers that cannot be built without options (SipHash needs a 16-byte key, KMAC a key).
  const required = { siphash: { key: '0123456789abcdef' }, siphash13: { key: '0123456789abcdef' }, kmac: { key: 'key' } };
  const pkg = JSON.parse(readFileSync(join(repo, 'packages', 'crypto-api', 'package.json'), 'utf8'));
  for (const e of entriesFromExports(pkg).filter((x) => x.target.includes('/hasher/'))) {
    classes[e.name] = (await imp(`hasher/${e.name}.mjs`)).default;
    const cases = inputs.map(([label, input]) => {
      const options = required[e.name] || {};
      const h = new classes[e.name](structuredClone(options));
      h.update(input);
      return { label, input, options, hex: toHex(h.finalize()) };
    });
    hashers.push({ name: e.name, cases });
  }

  const variants = VARIANTS.map((v) => ({
    id: v.id, file: FAMILIES.find((f) => f.id === v.family).file, options: v.options, vectors: vectors(v.id),
  }));
  const hmac = HMAC_VARIANTS.map((id) => {
    const v = VARIANTS.find((x) => x.id === id);
    return { id, file: FAMILIES.find((f) => f.id === v.family).file, options: v.options, vectors: vectors(`hmac-${id}`) };
  });
  void Hmac;

  const sha256 = () => new classes.sha256({ length: 256 });
  const big = 'abcdefghij'.repeat(30000);
  const bigHasher = sha256();
  bigHasher.update(big);
  return {
    version,
    main: {
      sha256abc: CryptoApi.hash('sha256', 'abc'),
      md5abc: CryptoApi.hash('md5', 'abc'),
      blake3abc: CryptoApi.hash('blake3', 'abc'),
    },
    hashers,
    variants,
    hmac,
    kdf: {
      pbkdf2: new Pbkdf2('password', sha256(), { salt: 'salt', iterations: 10, length: 160 }).finalize(),
      hkdf: new Hkdf('input key material', sha256(), { salt: 'salt', info: 'info', length: 320 }).finalize(),
      argon2: new Argon2('password', { salt: 'somesalt', iterations: 2, memory: 4096, parallelism: 2 }).finalize(),
      scrypt: new Scrypt('password', { salt: 'NaCl', cost: 1024, blockSize: 8, parallelization: 2 }).finalize(),
    },
    encoders: { base64: toBase64('abcÿ'), utf: toHex(fromUtf('héllo €')) },
    big: { sha256: toHex(bigHasher.finalize()) },
  };
}

/** A local npm registry that serves one package, enough for `deno run` with an `npm:` specifier. */
function startRegistry(tarball) {
  const data = readFileSync(tarball);
  const manifest = JSON.parse(execFileSync('tar', ['-xzOf', tarball, 'package/package.json'], { encoding: 'utf8' }));
  const file = `${manifest.name}-${manifest.version}.tgz`;
  return new Promise((ok) => {
    const server = createServer((req, res) => {
      const base = `http://127.0.0.1:${server.address().port}`;
      const url = decodeURIComponent(req.url.split('?')[0]);
      if (url === `/${manifest.name}`) {
        const packument = {
          name: manifest.name,
          'dist-tags': { latest: manifest.version },
          versions: {
            [manifest.version]: {
              ...manifest,
              dist: {
                tarball: `${base}/${manifest.name}/-/${file}`,
                integrity: `sha512-${createHash('sha512').update(data).digest('base64')}`,
                shasum: createHash('sha1').update(data).digest('hex'),
              },
            },
          },
        };
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(packument));
      } else if (url === `/${manifest.name}/-/${file}`) {
        res.setHeader('content-type', 'application/octet-stream');
        res.end(data);
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
    server.listen(0, '127.0.0.1', () => ok({ server, url: `http://127.0.0.1:${server.address().port}/`, manifest }));
  });
}

async function exec(bin, args, opts) {
  try {
    const { stdout, stderr } = await run(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? String(e.message) };
  }
}

async function available(name) {
  const r = await exec(RUNTIMES[name].bin, RUNTIMES[name].versionArgs);
  return r.code === 0 ? r.stdout.trim().split('\n')[0] : null;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  let tarball = args.tarball;
  if (!tarball) {
    const { buildInPlace, stage, pack } = await import(pathToFileURL(join(repo, 'scripts', 'build-package.mjs')).href);
    await buildInPlace();
    const out = mkdtempSync(join(tmpdir(), 'crypto-api-runtimes-pack-'));
    const stageDir = join(out, 'stage');
    stage({ out: stageDir, name: NAME });
    tarball = pack({ stageDir, dest: out }).tarball;
  }

  const registry = await startRegistry(tarball);
  const version = registry.manifest.version;
  const expected = await buildExpected(version);
  const wanted = args.runtimes ?? Object.keys(RUNTIMES);
  const results = [];
  const work = mkdtempSync(join(tmpdir(), 'crypto-api-runtimes-'));

  // Each runtime installs the way its users do. Deno gets two projects: an import map with an `npm:` specifier
  // (ESM only: require() does not see import maps) and a package.json dependency installed into node_modules.
  const setups = {
    node: [{ label: 'node', modes: ['wasm', 'no-wasm', 'cjs'], install: (dir, env) =>
      exec('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', tarball], { cwd: dir, env }) }],
    bun: [{ label: 'bun', modes: ['wasm', 'no-wasm', 'cjs'], install: (dir, env) => exec('bun', ['add', tarball], { cwd: dir, env }) }],
    deno: [
      { label: 'deno npm:', modes: ['wasm', 'no-wasm'], install: (dir, env) => {
        writeFileSync(join(dir, 'deno.json'), JSON.stringify({
          imports: { [NAME]: `npm:${NAME}@${version}`, [`${NAME}/`]: `npm:/${NAME}@${version}/` },
        }, null, 2));
        return exec('deno', ['cache', '--no-lock', 'consumer.mjs'], { cwd: dir, env });
      } },
      { label: 'deno pkg', modes: ['wasm', 'no-wasm', 'cjs'], install: (dir, env) => {
        writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'consumer', private: true, type: 'module', dependencies: { [NAME]: version } }));
        return exec('deno', ['install', '--no-lock'], { cwd: dir, env });
      } },
    ],
  };

  for (const name of wanted) {
    if (!RUNTIMES[name]) throw new Error(`unknown runtime ${name}`);
    const found = await available(name);
    if (!found) {
      if (args.runtimes) throw new Error(`${name} is not installed`);
      console.log(`skip ${name}: not installed`);
      continue;
    }
    for (const setup of setups[name]) {
      const project = join(work, setup.label.replace(/\W+/g, '-'));
      mkdirSync(project, { recursive: true });
      for (const f of ['consumer.mjs', 'consumer.cjs']) copyFileSync(join(repo, 'test', 'runtimes', f), join(project, f));
      writeFileSync(join(project, 'expected.json'), JSON.stringify(expected));
      if (name !== 'deno') writeFileSync(join(project, 'package.json'), '{"name":"consumer","private":true,"type":"module"}\n');
      const env = { ...process.env, NPM_CONFIG_REGISTRY: registry.url, DENO_DIR: join(project, '.deno'), NO_COLOR: '1' };

      const install = await setup.install(project, env);
      if (install.code !== 0) {
        results.push({ runtime: setup.label, ok: false, step: 'install', detail: (install.stderr || install.stdout).trim() });
        continue;
      }
      for (const mode of setup.modes) {
        const file = mode === 'cjs' ? 'consumer.cjs' : 'consumer.mjs';
        const r = await exec(RUNTIMES[name].bin, name === 'deno' ? ['run', '-A', '--no-lock', file] : [file], {
          cwd: project, env: { ...env, NO_WASM: mode === 'no-wasm' ? '1' : '' },
        });
        let summary = null;
        try { summary = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { /* reported below */ }
        results.push({
          runtime: setup.label, ok: r.code === 0 && summary !== null, step: `${file} (${mode})`,
          detail: r.code === 0 && summary ? JSON.stringify(summary) : (r.stderr || r.stdout).trim().split('\n').slice(0, 25).join('\n'),
        });
      }
    }
  }

  registry.server.close();
  if (!args.keep) rmSync(work, { recursive: true, force: true });
  let bad = 0;
  for (const r of results) {
    console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.runtime.padEnd(10)} ${r.step.padEnd(24)} ${r.detail.split('\n')[0]}`);
    if (!r.ok) { bad++; console.log(r.detail.split('\n').slice(1).map((l) => `       ${l}`).join('\n')); }
  }
  if (results.length === 0) { console.error('no runtime ran'); process.exit(1); }
  process.exit(bad ? 1 : 0);
}

await main();
