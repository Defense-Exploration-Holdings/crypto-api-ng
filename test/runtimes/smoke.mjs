// Runtime-neutral smoke test: runs unchanged on Node 18/20/22/24, Bun and Deno (no node:test, no
// resolve hook, no oracle). It checks every published vector (hash and HMAC, single update and
// byte-wise) through the deep imports, and reports how many wasm modules were instantiated.
//
//   node test/runtimes/smoke.mjs                 wasm must be used (exit 1 if it is not)
//   NO_WASM=1 node test/runtimes/smoke.mjs       WebAssembly removed: legacy fallback only
//   deno run -A test/runtimes/smoke.mjs
//   bun test/runtimes/smoke.mjs
//
// Output: one JSON line, {"runtime", "version", "mode", "vectors", "failures", "wasmInstances"}.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..');
const pkgSrc = join(repo, 'packages', 'crypto-api', 'src');
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

const imp = (rel) => import(pathToFileURL(join(pkgSrc, rel)).href);
const { FAMILIES, VARIANTS, HMAC_VARIANTS } = await import(
  pathToFileURL(join(repo, 'test', 'harness', 'catalog.mjs')).href);
const Hmac = (await imp('mac/hmac.mjs')).default;
const { toHex } = await imp('encoder/hex.mjs');
const classes = {};
for (const f of FAMILIES) classes[f.id] = (await imp(`hasher/${f.file}.mjs`)).default;

const vectors = (name) => JSON.parse(readFileSync(join(repo, 'test', 'vectors', `${name}.json`), 'utf8'));
let count = 0;
const failures = [];
const check = (label, got, want) => { count++; if (got !== want) failures.push(`${label}: ${got} != ${want}`); };

for (const v of VARIANTS) {
  for (const vec of vectors(v.id)) {
    const whole = new classes[v.family](structuredClone(v.options));
    whole.update(vec.input);
    check(`${v.id} ${vec.name}`, toHex(whole.finalize()), vec.hex);
    const bytewise = new classes[v.family](structuredClone(v.options));
    for (const ch of vec.input) bytewise.update(ch);
    check(`${v.id} ${vec.name} (byte-wise)`, toHex(bytewise.finalize()), vec.hex);
  }
}
for (const id of HMAC_VARIANTS) {
  const v = VARIANTS.find((x) => x.id === id);
  for (const vec of vectors(`hmac-${id}`)) {
    const mac = new Hmac(vec.key, new classes[v.family](structuredClone(v.options)));
    mac.update(vec.input);
    check(`hmac-${id} ${vec.name}`, toHex(mac.finalize()), vec.hex);
  }
}

// A message long enough to cross the wasm chunk boundary, compared against the same digest from
// a hasher that has no wasm (a fresh legacy engine imported from the vendored copy).
const big = 'abcdefghij'.repeat(30000);
const legacy = (await imp('../legacy/hasher/sha256.mjs')).default;
const a = new classes.sha256({ length: 256 }); a.update(big);
const b = new legacy({ length: 256 }); b.update(big);
check('sha256 300000 bytes vs legacy engine', toHex(a.finalize()), toHex(b.finalize()));

const runtime = globalThis.Deno ? 'deno' : globalThis.Bun ? 'bun' : 'node';
const version = globalThis.Deno?.version.deno ?? globalThis.Bun?.version ?? globalThis.process.versions.node;
if (!noWasm && wasmInstances === 0) failures.push('wasm was never instantiated');
if (noWasm && wasmInstances !== 0) failures.push('wasm was instantiated with WebAssembly removed');
console.log(JSON.stringify({ runtime, version, mode: noWasm ? 'no-wasm' : 'wasm', vectors: count, failures: failures.length, wasmInstances }));
for (const f of failures.slice(0, 20)) console.error('FAIL', f);
(globalThis.process ?? { exit() {} }).exit(failures.length ? 1 : 0);
