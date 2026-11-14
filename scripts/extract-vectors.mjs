#!/usr/bin/env node
// Extracts every hash and HMAC test vector from the ORIGINAL test files
// (crypto-api/test/hasher/*, crypto-api/test/mac/*) by running them with their
// assertion helpers stubbed out, and writes:
//
//   test/vectors/<variant>.json        [{name, input, inputHex, hex, options?}]   hash vectors
//   test/vectors/hmac-<variant>.json   [{name, key, keyHex, input, inputHex, hex}] HMAC vectors
//
// `input` and `key` are binary strings (code units 0..255): for hash vectors the
// original passes the message through fromUtf() first, so `input` is the post-fromUtf
// string, i.e. exactly what update() receives. `inputHex`/`keyHex` are the same bytes in
// hex: use them from Zig, because a JSON parser decodes `input` to UTF-8, which differs
// from the intended bytes above 0x7F. `hex` is the expected digest.
//
//   node scripts/extract-vectors.mjs           write
//   node scripts/extract-vectors.mjs --check   fail if committed files differ
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { register } from 'node:module';
import { ORACLE_TEST, VECTORS_DIR, assertOracleCheckedOut } from '../test/harness/paths.mjs';
import { VARIANTS, HMAC_VARIANTS } from '../test/harness/catalog.mjs';

assertOracleCheckedOut();
register('../test/harness/hook.mjs', import.meta.url);

const imp = (rel) => import(pathToFileURL(join(ORACLE_TEST, rel)).href);
const enc = (n) => import(pathToFileURL(join(ORACLE_TEST, '..', 'src', 'encoder', `${n}.mjs`)).href);
const { fromUtf } = await enc('utf');
const { toHex } = await enc('hex');

// original test file -> variant id
const HASH_TESTS = {
  has160: 'has160Test', md2: 'md2Test', md4: 'md4Test', md5: 'md5Test',
  ripemd128: 'ripemd128Test', ripemd160: 'ripemd160Test', ripemd256: 'ripemd256Test', ripemd320: 'ripemd320Test',
  sha0: 'sha0Test', sha1: 'sha1Test', sha224: 'sha224Test', sha256: 'sha256Test',
  sha384: 'sha384Test', sha512: 'sha512Test', 'sha512-224': 'sha512_224Test', 'sha512-256': 'sha512_256Test',
  sm3: 'sm3Test',
  'snefru128-2': 'snefru128_2Test', 'snefru128-8': 'snefru128_8Test',
  'snefru256-4': 'snefru256_4Test', 'snefru256-8': 'snefru256_8Test',
  whirlpool: 'whirlpoolTest', 'whirlpool-0': 'whirlpool-0Test', 'whirlpool-t': 'whirlpool-tTest',
};

function record(TestClass, kind) {
  const out = [];
  let currentName = '';
  globalThis.describe = (_n, fn) => fn();
  globalThis.it = (name, fn) => { currentName = name; fn(); };
  const t = new TestClass();
  t.testSetGetState = () => {};
  if (kind === 'hash') {
    t.testHash = (test) => {
      const input = fromUtf(test.message);
      const entry = { name: currentName, input, inputHex: toHex(input), hex: test.hash };
      if (test.options) entry.options = test.options;
      out.push(entry);
    };
  } else {
    t.testHmac = (test) => {
      const entry = {
        name: currentName, key: test.key, keyHex: toHex(test.key),
        input: test.message, inputHex: toHex(test.message), hex: test.hash,
      };
      if (test.options) entry.options = test.options;
      out.push(entry);
    };
  }
  t.test();
  return out;
}

const files = new Map();
const variantIds = new Set(VARIANTS.map((v) => v.id));
for (const [id, testFile] of Object.entries(HASH_TESTS)) {
  if (!variantIds.has(id)) throw new Error(`catalog has no variant ${id}`);
  const { default: Cls } = await imp(`hasher/${testFile}.mjs`);
  files.set(`${id}.json`, record(Cls, 'hash'));
}
for (const id of HMAC_VARIANTS) {
  const { default: Cls } = await imp(`mac/hmac-${id}Test.mjs`);
  files.set(`hmac-${id}.json`, record(Cls, 'hmac'));
}

const check = process.argv.includes('--check');
let bad = 0;
let total = 0;
for (const [name, entries] of files) {
  total += entries.length;
  const text = `${JSON.stringify(entries, null, 1)}\n`;
  const path = join(VECTORS_DIR, name);
  if (check) {
    if (!existsSync(path) || readFileSync(path, 'utf8') !== text) { console.error(`out of date: test/vectors/${name}`); bad++; }
  } else {
    writeFileSync(path, text);
  }
}
console.log(`extract-vectors: ${files.size} files, ${total} vectors${check ? (bad ? `, ${bad} out of date` : ', up to date') : ' written'}`);
if (bad) process.exit(1);
