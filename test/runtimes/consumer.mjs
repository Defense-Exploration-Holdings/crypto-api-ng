// Consumer test for the packed tarball: runs unchanged on Node, Bun and Deno from inside a project that has
// the package installed (scripts/test-runtimes.mjs sets that up and writes expected.json next to this file).
//
// Everything is imported by bare package specifier, so the runtime's own resolver walks the `exports` map:
//   node/bun:  <project>/node_modules/crypto-api-ng, installed from the tarball
//   deno:      `npm:crypto-api-ng@<version>` through an import map (deno.json), from a local npm registry
//
// It checks, per runtime and with and without WebAssembly:
//   - the main entry (ESM default export) and `crypto-api-ng/package.json`
//   - every per-algorithm entry in `exports` imports, hashes a few messages correctly (digests computed in Node
//     from the source tree) and, with wasm, really instantiated wasm
//   - the original 24 variants and the 7 HMAC vectors through those entries
//   - HMAC, PBKDF2, HKDF and the encoders
//   - unknown subpaths are rejected by the exports map
//
// Output: one JSON line {"runtime", "version", "mode", "checks", "failures", "wasmInstances"}; exit 1 on failure.
import { readFileSync } from 'node:fs';

const NAME = 'crypto-api-ng';
const noWasm = (globalThis.process?.env?.NO_WASM ?? globalThis.Deno?.env.get('NO_WASM')) === '1';

let wasmInstances = 0;
if (noWasm) {
  delete globalThis.WebAssembly;
} else {
  const Original = WebAssembly.Instance;
  WebAssembly.Instance = class extends Original {
    constructor(...args) { super(...args); wasmInstances++; }
  };
}

const expected = JSON.parse(readFileSync(new URL('./expected.json', import.meta.url), 'utf8'));
const failures = [];
let checks = 0;
const eq = (label, got, want) => {
  checks++;
  if (got !== want) failures.push(`${label}: ${got} != ${want}`);
};
const ok = (label, cond) => {
  checks++;
  if (!cond) failures.push(label);
};
const imp = (sub) => import(sub ? `${NAME}/${sub}` : NAME);

const { toHex } = await imp('encoder/hex');
const classes = {};

// The main entry: a default export, the same object the original's module.exports was.
const main = (await imp('')).default;
ok('main entry has a default export with hash()', typeof main?.hash === 'function' && typeof main?.getHasher === 'function');
if (typeof main?.hash === 'function') {
  eq('main entry sha256("abc")', main.hash('sha256', 'abc'), expected.main.sha256abc);
  eq('main entry md5("abc")', main.hash('md5', 'abc'), expected.main.md5abc);
}
const pkgJson = await import(`${NAME}/package.json`, { with: { type: 'json' } }).then((m) => m.default, (e) => { failures.push(`import package.json: ${e.message}`); return null; });
eq('package.json version', pkgJson?.version, expected.version);

// Every per-algorithm entry.
for (const entry of expected.hashers) {
  let H;
  try { H = (await imp(entry.name)).default; } catch (e) { failures.push(`import ${entry.name}: ${e.message}`); continue; }
  classes[entry.name] = H;
  for (const c of entry.cases) {
    const h = new H(structuredClone(c.options));
    h.update(c.input);
    eq(`${entry.name} ${c.label}`, toHex(h.finalize()), c.hex);
  }
}

// The original suite's vectors, through the entries.
for (const v of expected.variants) {
  const H = classes[v.file];
  for (const vec of v.vectors) {
    const whole = new H(structuredClone(v.options));
    whole.update(vec.input);
    eq(`${v.id} ${vec.name}`, toHex(whole.finalize()), vec.hex);
    const bytewise = new H(structuredClone(v.options));
    for (const ch of vec.input) bytewise.update(ch);
    eq(`${v.id} ${vec.name} (byte-wise)`, toHex(bytewise.finalize()), vec.hex);
  }
}
const Hmac = (await imp('hmac')).default;
for (const v of expected.hmac) {
  for (const vec of v.vectors) {
    const mac = new Hmac(vec.key, new classes[v.file](structuredClone(v.options)));
    mac.update(vec.input);
    eq(`hmac-${v.id} ${vec.name}`, toHex(mac.finalize()), vec.hex);
  }
}

// KDFs and encoders.
const Pbkdf2 = (await imp('pbkdf2')).default;
const Hkdf = (await imp('hkdf')).default;
const { toBase64 } = await imp('encoder/base64');
const bytes = await imp('encoder/bytes');
const { fromUtf } = await imp('encoder/utf');
const { fromArrayBuffer } = await imp('encoder/array-buffer');
const sha256 = () => new classes.sha256({ length: 256 });
eq('pbkdf2', new Pbkdf2('password', sha256(), { salt: 'salt', iterations: 10, length: 160 }).finalize(), expected.kdf.pbkdf2);
eq('hkdf', new Hkdf('input key material', sha256(), { salt: 'salt', info: 'info', length: 320 }).finalize(), expected.kdf.hkdf);
eq('toBase64', toBase64('abcÿ'), expected.encoders.base64);
eq('fromUtf', toHex(fromUtf('héllo €')), expected.encoders.utf);
eq('bytes round trip', bytes.bytesToHex(bytes.hexToBytes('00ff10')), '00ff10');
eq('bytes utf8', bytes.bytesToUtf8(bytes.utf8ToBytes('héllo €')), 'héllo €');
eq('fromArrayBuffer', toHex(fromArrayBuffer(new Uint8Array([1, 2, 255]).buffer)), '0102ff');

// A message long enough to cross the wasm chunk boundary, fed in uneven pieces.
{
  const h = new classes.sha256({ length: 256 });
  const big = 'abcdefghij'.repeat(30000);
  h.update(big.slice(0, 12345));
  h.update(big.slice(12345));
  eq('sha256 300000 bytes in two updates', toHex(h.finalize()), expected.big.sha256);
}

// Pure JavaScript is required to agree with wasm, and both with Node; the instance count shows which one ran.
if (!noWasm && wasmInstances === 0) failures.push('wasm was never instantiated');
if (noWasm && wasmInstances !== 0) failures.push('wasm was instantiated with WebAssembly removed');

// The exports map keeps unknown subpaths out.
for (const sub of ['not-an-algorithm', 'src/hasher/not-an-algorithm.mjs', 'hasher/md5']) {
  const r = await imp(sub).then(() => 'loaded', () => 'rejected');
  eq(`import ${NAME}/${sub}`, r, 'rejected');
}

const runtime = globalThis.Deno ? 'deno' : globalThis.Bun ? 'bun' : 'node';
const version = globalThis.Deno?.version.deno ?? globalThis.Bun?.version ?? globalThis.process.versions.node;
console.log(JSON.stringify({ runtime, version, mode: noWasm ? 'no-wasm' : 'wasm', checks, failures: failures.length, wasmInstances }));
for (const f of failures.slice(0, 20)) console.error('FAIL', f);
(globalThis.process ?? { exit() {} }).exit(failures.length ? 1 : 0);
