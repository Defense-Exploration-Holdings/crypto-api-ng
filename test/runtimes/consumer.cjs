// CommonJS half of the consumer test (see consumer.mjs and scripts/test-runtimes.mjs): require() of the main
// entry, which `exports` maps to the UMD bundle, and require() of an ES module entry where the runtime can.
// Output: one JSON line {"runtime", "requireEsm", "failures"}; exit 1 on failure.
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const NAME = 'crypto-api-ng';
const expected = JSON.parse(fs.readFileSync(path.join(__dirname, 'expected.json'), 'utf8'));
const failures = [];
const eq = (label, got, want) => { if (got !== want) failures.push(`${label}: ${got} != ${want}`); };

const toHex = (s) => Array.from(s, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');

// The main entry. Two module graphs exist on purpose: this bundle and the deep ES modules do not share classes.
const CryptoApi = require(NAME);
eq('require() main sha256', CryptoApi.hash('sha256', 'abc'), expected.main.sha256abc);
eq('require() main md5', CryptoApi.hash('md5', 'abc'), expected.main.md5abc);
eq('require() main exposes the encoders', CryptoApi.encoder.toHex(CryptoApi.encoder.fromUtf('\u20ac')), 'e282ac');
eq('require() main blake3', CryptoApi.hash('blake3', 'abc'), expected.main.blake3abc);

// require() of an ES module entry: Node 22.12+, Bun, Deno 2.x. A runtime that cannot do it must say so with
// ERR_REQUIRE_ESM (or similar), not return something wrong.
let requireEsm = 'unsupported';
try {
  const mod = require(`${NAME}/sha256`);
  const Sha256 = mod.default ?? mod;
  const x = new Sha256({ length: 256 });
  x.update('abc');
  eq('require() sha256 entry', toHex(x.finalize()), expected.main.sha256abc);
  requireEsm = 'supported';
} catch (e) {
  if (!/ERR_REQUIRE_ESM|require\(\) of ES Module|Cannot require|require is not|ES module/i.test(String(e && (e.code || e.message)))) {
    failures.push(`require() of an ES module entry failed unexpectedly: ${e && e.message}`);
  }
}

const runtime = globalThis.Deno ? 'deno' : globalThis.Bun ? 'bun' : 'node';
console.log(JSON.stringify({ runtime, requireEsm, failures: failures.length }));
for (const f of failures) console.error('FAIL', f);
process.exit(failures.length ? 1 : 0);
