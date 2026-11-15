// The TypeScript declarations shipped in the package: a consumer project under Node's native module
// resolution (nodenext) imports the package every documented way and must compile with `strict`.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO_ROOT } from '../harness/paths.mjs';
import { SCRIPTS, ensureBuilt } from './support.js';

const TSC = join(REPO_ROOT, 'node_modules', 'typescript', 'bin', 'tsc');
let project;
let pkgDir;

const ESM = `
import CryptoApi from "crypto-api-ng";
import Direct from "crypto-api-ng/src/index.mjs";
import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
import Sha512 from "crypto-api-ng/src/hasher/sha512.mjs";
import Md5 from "crypto-api-ng/src/hasher/md5.mjs";
import Whirlpool from "crypto-api-ng/src/hasher/whirlpool.mjs";
import Blake2b from "crypto-api-ng/src/hasher/blake2b.mjs";
import Blake2s from "crypto-api-ng/src/hasher/blake2s.mjs";
import Blake3 from "crypto-api-ng/src/hasher/blake3.mjs";
import Hmac from "crypto-api-ng/src/mac/hmac.mjs";
import Pbkdf2 from "crypto-api-ng/src/kdf/pbkdf2.mjs";
import Hkdf from "crypto-api-ng/src/kdf/hkdf.mjs";
import Sha3 from "crypto-api-ng/src/hasher/sha3.mjs";
import Shake from "crypto-api-ng/src/hasher/shake.mjs";
import Keccak from "crypto-api-ng/src/hasher/keccak.mjs";
import { toHex } from "crypto-api-ng/src/encoder/hex.mjs";
import { toBase64 } from "crypto-api-ng/src/encoder/base64.mjs";
import { fromUtf } from "crypto-api-ng/src/encoder/utf.mjs";
import { fromArrayBuffer } from "crypto-api-ng/src/encoder/array-buffer.mjs";
import type { HasherLike, HasherName } from "crypto-api-ng/types.js";

const hex: string = CryptoApi.hash('sha256', 'abc');
const same: string = Direct.hash('md5', new Uint8Array(3), { rounds: 10 });
const hasher = new Sha256({ length: 224, rounds: 64 });
hasher.update('a');
hasher.update(new Uint8Array(1));
hasher.update(new ArrayBuffer(1));
const digest: string = hasher.finalize();
const state: Record<string, any> = hasher.getState();
hasher.setState(state);
new Sha512({ length: 256 });
new Whirlpool({ type: 't' });
new Blake2b({ length: 256, key: 'k', salt: new Uint8Array(16), personalization: 'p' });
new Blake2s({ key: new Uint8Array(32) });
new Blake3({ key: new Uint8Array(32), length: 512 });
new Blake3({ context: 'app 2026 keys' });
CryptoApi.hash('blake2b-256', 'abc', { key: 'k' });
new Sha3({ length: 256 }).update('abc');
new Keccak({ length: 256 });
new Shake({ strength: 256, length: 1024 });
const xof: string = CryptoApi.hash('shake128', 'abc', { length: 512, strength: 128 });
const mac = new Hmac('key', new Md5());
mac.update(fromUtf('message'));
const macHex: string = toHex(mac.finalize());
const b64: string = toBase64(digest) + fromArrayBuffer(new ArrayBuffer(1));
const known: HasherLike = CryptoApi.getHasher('md5');
known.update('x');
const name: HasherName = 'sha512/256';
const unknown = CryptoApi.getHasher('no-such-hash');
const viaApi: string = CryptoApi.hmac('key', new Uint8Array(2), CryptoApi.getHasher(name));
CryptoApi.getHmac('key', known).update('m');
const derived: string = new Pbkdf2('password', new Sha256(), { salt: 'salt', iterations: 1000, length: 256 }).finalize();
new Pbkdf2(new Uint8Array(4), known, { iterations: 1 });
const okm: string = new Hkdf('ikm', new Sha256(), { salt: new Uint8Array(4), info: 'ctx', length: 336 }).finalize();
const hk = new Hkdf('ikm', known);
const prk: string = hk.extract();
const more: string = hk.expand('ctx', 256) + hk.expand();
const keyHex: string = CryptoApi.pbkdf2('password', known, { iterations: 10, salt: 'salt' }) + CryptoApi.hkdf('ikm', known, { info: 'ctx' });
const encoded: string = CryptoApi.encoder.toHex(CryptoApi.encoder.fromUtf('x'));

// @ts-expect-error PBKDF2 needs iterations
new Pbkdf2('password', new Sha256(), { salt: 'salt' });
// @ts-expect-error iterations is a number
new Pbkdf2('password', new Sha256(), { iterations: '1000' });
// @ts-expect-error HKDF has no iterations
new Hkdf('ikm', new Sha256(), { iterations: 1 });
// @ts-expect-error an unsupported length for Sha256
new Sha256({ length: 123 });
// @ts-expect-error key and context exclude each other
new Blake3({ key: 'k', context: 'c' });
// @ts-expect-error SHA-3 has no 160-bit variant
new Sha3({ length: 160 });
// @ts-expect-error SHAKE strength is 128 or 256
new Shake({ strength: 512 });
// @ts-expect-error update() takes a string or bytes
hasher.update(42);
// @ts-expect-error getHasher() of an unknown name may return undefined
unknown.update('x');
// @ts-expect-error digests are strings
const notNumber: number = hex;
export { hex, same, macHex, b64, viaApi, encoded, notNumber };
`;

const CJS = `
import cryptoApi = require("crypto-api-ng");
const hex: string = cryptoApi.hash('md5', 'a');
const hasher = cryptoApi.getHasher('sha1');
hasher.update('x');
export const out: string = cryptoApi.encoder.toHex(hasher.finalize()) + hex;
`;

before(async () => {
  assert.ok(existsSync(TSC), 'typescript is not installed (npm ci)');
  await ensureBuilt();
  const buildPackage = await import(join(SCRIPTS, 'build-package.mjs'));
  project = mkdtempSync(join(tmpdir(), 'crypto-api-types-'));
  pkgDir = join(project, 'node_modules', 'crypto-api-ng');
  mkdirSync(pkgDir, { recursive: true });
  buildPackage.stage({ out: pkgDir, name: 'crypto-api-ng' });
  writeFileSync(join(project, 'package.json'), JSON.stringify({ type: 'module' }));
  writeFileSync(join(project, 'tsconfig.json'), JSON.stringify({
    compilerOptions: {
      module: 'nodenext', moduleResolution: 'nodenext', target: 'es2022', strict: true, noEmit: true, types: [],
    },
    include: ['*.mts', '*.cts'],
  }));
  writeFileSync(join(project, 'esm.mts'), ESM);
  writeFileSync(join(project, 'cjs.cts'), CJS);
});

after(() => rmSync(project, { recursive: true, force: true }));

describe('TypeScript declarations', () => {
  it('package.json points at declarations that are shipped', () => {
    const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
    assert.equal(pkg.types, 'index.d.ts');
    for (const f of ['index.d.ts', 'types.d.ts', 'src/index.d.mts', 'src/hasher/sha256.d.mts', 'src/mac/hmac.d.mts', 'src/kdf/pbkdf2.d.mts', 'src/kdf/hkdf.d.mts']) {
      assert.ok(existsSync(join(pkgDir, f)), f);
    }
  });

  it('every hasher module and encoder has a declaration next to it', () => {
    for (const dir of ['hasher', 'encoder', 'mac', 'kdf']) {
      const mjs = readdirSyncSafe(join(pkgDir, 'src', dir)).filter((f) => f.endsWith('.mjs'));
      for (const f of mjs) {
        const want = f.replace(/\.mjs$/, '.d.mts');
        // Internal base classes of the 0.8.5 layout are intentionally untyped.
        if (/^hasher(8|32le|32be)\.mjs$/.test(f)) continue;
        assert.ok(existsSync(join(pkgDir, 'src', dir, want)), `missing ${dir}/${want}`);
      }
    }
  });

  it('a strict nodenext project compiles ESM and CommonJS usage, and rejects misuse', () => {
    const r = spawnSync(process.execPath, [TSC, '-p', project], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
  });
});

import { readdirSync } from 'node:fs';
function readdirSyncSafe(dir) { return existsSync(dir) ? readdirSync(dir) : []; }
