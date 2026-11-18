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
import Argon2 from "crypto-api-ng/argon2";
import Scrypt from "crypto-api-ng/src/kdf/scrypt.mjs";
import Sha3 from "crypto-api-ng/src/hasher/sha3.mjs";
import Shake from "crypto-api-ng/src/hasher/shake.mjs";
import Keccak from "crypto-api-ng/src/hasher/keccak.mjs";
import CShake from "crypto-api-ng/cshake";
import Kmac from "crypto-api-ng/kmac";
import TupleHash from "crypto-api-ng/tuplehash";
import ParallelHash from "crypto-api-ng/parallelhash";
import TurboShake from "crypto-api-ng/turboshake";
import KangarooTwelve from "crypto-api-ng/kangarootwelve";
import Tiger from "crypto-api-ng/src/hasher/tiger.mjs";
import Tiger2 from "crypto-api-ng/src/hasher/tiger2.mjs";
import Streebog from "crypto-api-ng/src/hasher/streebog.mjs";
import Crc32 from "crypto-api-ng/src/hasher/crc32.mjs";
import Crc32c from "crypto-api-ng/src/hasher/crc32c.mjs";
import XxHash32 from "crypto-api-ng/src/hasher/xxhash32.mjs";
import XxHash64 from "crypto-api-ng/src/hasher/xxhash64.mjs";
import XxHash3 from "crypto-api-ng/xxhash3";
import XxHash128 from "crypto-api-ng/src/hasher/xxhash128.mjs";
import SipHash from "crypto-api-ng/siphash";
import SipHash13 from "crypto-api-ng/src/hasher/siphash13.mjs";
import Murmur3 from "crypto-api-ng/murmur3";
import Murmur3x64 from "crypto-api-ng/src/hasher/murmur3x64.mjs";
import { toHex } from "crypto-api-ng/src/encoder/hex.mjs";
import { toBase64 } from "crypto-api-ng/src/encoder/base64.mjs";
import { fromUtf } from "crypto-api-ng/src/encoder/utf.mjs";
import { fromArrayBuffer } from "crypto-api-ng/src/encoder/array-buffer.mjs";
import { utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes } from "crypto-api-ng/src/encoder/bytes.mjs";
import type { HasherLike, HasherName } from "crypto-api-ng/types.js";
import Bundled, { Sha256 as BundledSha256, Hmac as BundledHmac, bytesToHex as bundledHex } from "crypto-api-ng/crypto-api.min.mjs";

const hex: string = CryptoApi.hash('sha256', 'abc');
const fromBundle: string = Bundled.hash('sha256', 'abc') + bundledHex(new BundledHmac('k', new BundledSha256()).digest());
// @ts-expect-error the ES module build has no such export
import("crypto-api-ng/crypto-api.min.mjs").then((m) => m.NoSuchHasher);
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
new CShake({ strength: 256, customization: 'S', functionName: new Uint8Array(1) }).update('abc');
const kmacTag: string = new Kmac({ key: 'k', xof: true, length: 512 }).digest('hex');
new TupleHash({ customization: 'S' }).update('element');
new ParallelHash({ blockSize: 1024 });
new TurboShake({ domain: 0x0b });
new KangarooTwelve({ strength: 256, customization: 'C' });
const kt: string = CryptoApi.hash('kt128', 'abc', { length: 512 });
new Tiger({ length: 128 }).update('abc');
new Tiger2();
new Streebog({ length: 256 }).update(new Uint8Array(3));
new Crc32().update('abc');
new Crc32c();
new XxHash32({ seed: 7 });
new XxHash64({ seed: 2 ** 40 }).update('abc');
const sum: string = CryptoApi.hash('xxhash32', 'abc', { seed: 1 });
new XxHash3({ seed: 2 ** 40 }).update('abc');
const x128: string = new XxHash128().digest('hex');
new SipHash({ key: new Uint8Array(16) }).update('abc');
new SipHash13({ key: '0123456789abcdef' });
new Murmur3({ seed: 42 }).update(new Uint8Array(3));
new Murmur3x64();
const keyedSum: string = CryptoApi.hash('siphash-1-3', 'abc', { key: new Uint8Array(16) }) + CryptoApi.hash('murmur3-x64-128', 'abc');
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

const tagA: Uint8Array = new Argon2('password', { salt: 'saltsalt', iterations: 2, memory: 19456, type: 'argon2i', secret: new Uint8Array(8) }).digest();
const tagS: string = new Scrypt(new Uint8Array(4), { cost: 1024, blockSize: 8, salt: 'salt' }).finalize();
const pwHex: string = CryptoApi.argon2('pw', { salt: 'saltsalt', iterations: 1, memory: 8 }) + CryptoApi.scrypt('pw', { cost: 16 });
const pwBytes: Uint8Array = CryptoApi.argon2Bytes('pw', { salt: 'saltsalt', iterations: 1, memory: 8 }) ?? CryptoApi.scryptBytes('pw', { cost: 16 });
// @ts-expect-error Argon2 needs memory
new Argon2('password', { salt: 'saltsalt', iterations: 2 });
// @ts-expect-error not an Argon2 type
new Argon2('password', { salt: 'saltsalt', iterations: 2, memory: 8, type: 'argon2x' });
// @ts-expect-error scrypt needs cost
new Scrypt('password', { salt: 'salt' });
// @ts-expect-error PBKDF2 needs iterations
new Pbkdf2('password', new Sha256(), { salt: 'salt' });
// @ts-expect-error iterations is a number
new Pbkdf2('password', new Sha256(), { iterations: '1000' });
// @ts-expect-error HKDF has no iterations
new Hkdf('ikm', new Sha256(), { iterations: 1 });
const raw: Uint8Array = hasher.digest();
const rawHex: string = new Sha3({ length: 256 }).digest('hex');
const rawB64: string = new Blake3().digest('base64url');
const rawBin: string = mac.digest('binary');
const macBytes: Uint8Array = mac.digest();
const bytesOut: Uint8Array = CryptoApi.hashBytes('sha256', 'abc') ;
const macOut: Uint8Array = CryptoApi.hmacBytes(utf8ToBytes('key'), new Uint8Array(2), CryptoApi.getHasher('md5'));
const text: string = bytesToUtf8(utf8ToBytes('x'), { fatal: true });
const hexText: string = bytesToHex(raw) + bytesToBase64(raw, { alphabet: 'base64url', omitPadding: true });
const back: Uint8Array = hexToBytes(hexText).length ? base64ToBytes(rawB64, { alphabet: 'base64url' }) : CryptoApi.encoder.hexToBytes('00');
const kdfBytes: Uint8Array = new Pbkdf2('password', new Sha256(), { iterations: 2 }).digest();
const kdfText: string = hk.digest('base64url') + CryptoApi.encoder.bytesToHex(hk.expandBytes('ctx', 128));
const kdfApi: Uint8Array = CryptoApi.pbkdf2Bytes('p', known, { iterations: 2 }) ?? CryptoApi.hkdfBytes('ikm', known);
// @ts-expect-error not an encoding
hasher.digest('latin1');
// @ts-expect-error not an alphabet
bytesToBase64(raw, { alphabet: 'base32' });
// @ts-expect-error hex is text, not bytes
hexToBytes(raw);
// @ts-expect-error an unsupported length for Sha256
new Sha256({ length: 123 });
// @ts-expect-error key and context exclude each other
new Blake3({ key: 'k', context: 'c' });
// @ts-expect-error SHA-3 has no 160-bit variant
new Sha3({ length: 160 });
// @ts-expect-error SHAKE strength is 128 or 256
new Shake({ strength: 512 });
// @ts-expect-error KMAC needs a key
new Kmac({});
// @ts-expect-error xof is a boolean
new TupleHash({ xof: 1 });
// @ts-expect-error Streebog has 256 and 512 bits only
new Streebog({ length: 384 });
// @ts-expect-error a seed is a number
new XxHash32({ seed: 'x' });
// @ts-expect-error SipHash needs a key
new SipHash();
// @ts-expect-error a Murmur3 seed is a number
new Murmur3({ seed: '1' });
// @ts-expect-error update() takes a string or bytes
hasher.update(42);
// @ts-expect-error getHasher() of an unknown name may return undefined
unknown.update('x');
// @ts-expect-error digests are strings
const notNumber: number = hex;
export { hex, same, macHex, b64, viaApi, encoded, notNumber, sum, x128, keyedSum, kdfBytes, kdfText, kdfApi, rawHex, rawBin, macBytes, bytesOut, macOut, text, back };
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
    for (const f of ['index.d.ts', 'types.d.ts', 'src/index.d.mts', 'src/hasher/sha256.d.mts', 'src/mac/hmac.d.mts', 'src/kdf/pbkdf2.d.mts', 'src/kdf/hkdf.d.mts', 'src/kdf/argon2.d.mts', 'src/kdf/scrypt.d.mts']) {
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
