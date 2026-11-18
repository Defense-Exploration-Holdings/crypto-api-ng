// Writes test/vectors/fast/{xxh3,siphash}.json from the published test vectors of the reference
// implementations, so the tests do not depend on a network or on third-party code:
//
//   xxh3.json     XXH3-64 and XXH128 values of tests/sanity_test_vectors.h (xxHash 0.8.3) for a
//                 selection of lengths of the sanity buffer and every seed listed there
//   siphash.json  SipHash-2-4 (vectors.h of the reference implementation, github.com/veorq/SipHash)
//                 and SipHash-1-3 (the test vectors of the Rust standard library,
//                 library/coretests/tests/hash/sip.rs) of the messages 00, 00 01, ... with the key
//                 00 01 .. 0f
//
// The files are only parsed as text, nothing in them is run.
//
//   node scripts/gen-fast-vectors.mjs <sanity_test_vectors.h> <vectors.h> <sip.rs>
import { readFileSync, writeFileSync } from 'node:fs';

const [xxhPath, sipPath, rustPath] = process.argv.slice(2);
if (!rustPath) {
  console.error('usage: node scripts/gen-fast-vectors.mjs <sanity_test_vectors.h> <vectors.h> <sip.rs>');
  process.exit(2);
}
const out = new URL('../test/vectors/fast/', import.meta.url);
const hex64 = (s) => BigInt(s.replace(/ULL$/, '')).toString(16).padStart(16, '0');

// ---- XXH3 ---------------------------------------------------------------------------------------

const xxh = readFileSync(xxhPath, 'utf8');
function table(name) {
  const start = xxh.indexOf(`${name}[] = {`);
  if (start < 0) throw new Error(`no table ${name}`);
  return xxh.slice(start, xxh.indexOf('};', start));
}
const rows64 = new Map();
for (const m of table('XSUM_XXH3_testdata').matchAll(/\{\s*(\d+),\s*(0x[0-9A-F]+)ULL,\s*(0x[0-9A-F]+)ULL\s*\}/g)) {
  rows64.set(`${m[1]}/${hex64(m[2])}`, hex64(m[3]));
}
const rows128 = new Map();
for (const m of table('XSUM_XXH128_testdata').matchAll(/\{\s*(\d+),\s*(0x[0-9A-F]+)ULL,\s*\{\s*(0x[0-9A-F]+)ULL,\s*(0x[0-9A-F]+)ULL\s*\}\s*\}/g)) {
  // XXH128_hash_t is {low64, high64}; the canonical form is the high half first.
  rows128.set(`${m[1]}/${hex64(m[2])}`, hex64(m[4]) + hex64(m[3]));
}
const lengths = new Set();
for (let n = 0; n <= 300; n++) lengths.add(n);
for (let n = 301; n <= 4160; n += 37) lengths.add(n);
for (const n of [1023, 1024, 1025, 1087, 1088, 1089, 2047, 2048, 2049, 2111, 2112, 2113, 3072, 4095, 4096, 4097, 4160]) lengths.add(n);
const xxh3 = [];
for (const key of new Set([...rows64.keys(), ...rows128.keys()])) {
  const [length, seed] = key.split('/');
  if (!lengths.has(Number(length))) continue;
  const row = { length: Number(length), seed };
  if (rows64.has(key)) row.xxh3 = rows64.get(key);
  if (rows128.has(key)) row.xxh128 = rows128.get(key);
  xxh3.push(row);
}
xxh3.sort((a, b) => a.length - b.length || (a.seed < b.seed ? -1 : 1));
writeFileSync(new URL('xxh3.json', out), JSON.stringify(xxh3, null, 0).replace(/\},\{/g, '},\n{') + '\n');

// ---- SipHash ------------------------------------------------------------------------------------

const bytesIn = (text) => [...text.matchAll(/0x([0-9a-f]{2})/gi)].map((m) => m[1].toLowerCase());
const chunk = (list, n) => Array.from({ length: list.length / n }, (_, i) => list.slice(n * i, n * i + n).join(''));
const sip = readFileSync(sipPath, 'utf8');
const s24 = sip.slice(sip.indexOf('vectors_sip64[64][8]'), sip.indexOf('vectors_sip128'));
const rust = readFileSync(rustPath, 'utf8');
const r13 = rust.slice(rust.indexOf('fn test_siphash_1_3'), rust.indexOf('let k0', rust.indexOf('fn test_siphash_1_3')));
const v24 = chunk(bytesIn(s24), 8);
const v13 = chunk(bytesIn(r13), 8);
if (v24.length !== 64 || v13.length !== 64) throw new Error('expected 64 SipHash vectors each');
const siphash = v24.map((d, i) => ({ length: i, siphash24: d, siphash13: v13[i] }));
writeFileSync(new URL('siphash.json', out), JSON.stringify(siphash, null, 0).replace(/\},\{/g, '},\n{') + '\n');
console.log(`xxh3.json: ${xxh3.length} rows, siphash.json: ${siphash.length} rows`);
