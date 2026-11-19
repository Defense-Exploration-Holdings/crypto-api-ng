// Argon2 and scrypt (packages/crypto-api/src/kdf/{argon2,scrypt}.mjs).
//
// New in crypto-api-ng: there is no 0.8.5 class to diff against. Oracles: the RFC 9106
// and RFC 7914 test vectors, vectors of the Argon2 reference implementation, node:crypto
// (OpenSSL) scrypt at random parameters, and agreement between the wasm module and the
// plain-JavaScript engine (the Zig tests also compare the core with std.crypto.pwhash).
// Every behavior runs twice: with WebAssembly, and with `_internal.reset(true)`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scryptSync, randomBytes } from 'node:crypto';

import Argon2, { _internal as argon2Internal } from '../packages/crypto-api/src/kdf/argon2.mjs';
import Scrypt, { _internal as scryptInternal } from '../packages/crypto-api/src/kdf/scrypt.mjs';
import { derive as argon2Js } from '../packages/crypto-api/src/pwhash/argon2.mjs';
import { derive as scryptJs } from '../packages/crypto-api/src/pwhash/scrypt.mjs';
import CryptoApi from '../packages/crypto-api/src/index.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { fromUtf } from '../packages/crypto-api/src/encoder/utf.mjs';

const hex = (s) => Buffer.from(s, 'hex').toString('latin1');
const fill = (n, v) => String.fromCharCode(v).repeat(n);

const ENGINES = [
  ['wasm', () => { argon2Internal.reset(false); scryptInternal.reset(false); }],
  ['js', () => { argon2Internal.reset(true); scryptInternal.reset(true); }],
];

function forEachEngine(name, fn) {
  for (const [engine, select] of ENGINES) {
    test(`${name} (${engine})`, () => {
      select();
      try {
        const before = [argon2Internal.wasmCalls(), scryptInternal.wasmCalls()];
        fn(engine);
        if (engine === 'js') {
          assert.deepEqual([argon2Internal.wasmCalls(), scryptInternal.wasmCalls()], before, 'no wasm call without WebAssembly');
        }
      } finally {
        argon2Internal.reset(false);
        scryptInternal.reset(false);
      }
    });
  }
}

// ---------- Argon2: RFC 9106 section 5 and the reference implementation

const RFC9106 = {
  argon2d: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
  argon2i: 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
  argon2id: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
};

forEachEngine('RFC 9106 section 5: Argon2d, Argon2i, Argon2id', () => {
  for (const [type, expected] of Object.entries(RFC9106)) {
    const tag = new Argon2(fill(32, 1), {
      type, salt: fill(16, 2), secret: fill(8, 3), associatedData: fill(12, 4),
      iterations: 3, memory: 32, parallelism: 4, length: 256,
    }).finalize();
    assert.equal(toHex(tag), expected, type);
  }
});

// From phc-winner-argon2 (src/test.c and the README). 64 MiB each.
const REFERENCE = [
  ['argon2i', 2, 65536, 1, 256, 'c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0'],
  ['argon2id', 2, 65536, 1, 256, '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'],
  ['argon2i', 2, 65536, 4, 192, '45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6'],
];

test('reference implementation vectors, 64 MiB (wasm)', () => {
  for (const [type, iterations, memory, parallelism, length, expected] of REFERENCE) {
    const before = argon2Internal.wasmCalls();
    const tag = new Argon2('password', { type, salt: 'somesalt', iterations, memory, parallelism, length }).finalize();
    assert.equal(toHex(tag), expected);
    assert.equal(argon2Internal.wasmCalls(), before + 1);
  }
});

test('reference implementation vector, 64 MiB (js)', () => {
  const [type, iterations, memory, parallelism, length, expected] = REFERENCE[1];
  argon2Internal.reset(true);
  try {
    const tag = new Argon2('password', { type, salt: 'somesalt', iterations, memory, parallelism, length }).finalize();
    assert.equal(toHex(tag), expected);
  } finally {
    argon2Internal.reset(false);
  }
});

// ---------- Argon2: wasm against the plain-JavaScript engine

test('Argon2: wasm and the JavaScript engine agree at random parameters', () => {
  const iters = Number(process.env.FUZZ_ITERS || 40);
  let seed = 12345;
  const rnd = (n) => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return seed % n;
  };
  const bytes = (n) => {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = rnd(256);
    return b;
  };
  for (let k = 0; k < iters; k++) {
    const mode = rnd(3);
    const p = 1 + rnd(5);
    const m = 8 * p + rnd(200);
    const t = 1 + rnd(3);
    const out = [4, 16, 32, 63, 64, 65, 96, 128, 1000][rnd(9)];
    const pw = bytes(rnd(90)), salt = bytes(8 + rnd(40)), secret = bytes(rnd(3) ? 0 : rnd(40)), ad = bytes(rnd(2) ? 0 : rnd(40));
    const type = ['argon2d', 'argon2i', 'argon2id'][mode];
    const options = { type, salt, iterations: t, memory: m, parallelism: p, length: out * 8, secret, associatedData: ad };
    const before = argon2Internal.wasmCalls();
    const viaWasm = new Argon2(pw, options).finalize();
    assert.equal(argon2Internal.wasmCalls(), before + 1);
    const viaJs = String.fromCharCode.apply(null, argon2Js(mode, t, m, p, pw, salt, secret, ad, out));
    assert.equal(toHex(viaWasm), toHex(viaJs), JSON.stringify({ type, t, m, p, out }));
  }
});

forEachEngine('Argon2: memory not a multiple of 4 * parallelism is rounded down', () => {
  const o = { salt: 'saltsalt', iterations: 1, parallelism: 3 };
  // 24 blocks for 24..35 KiB.
  const a = new Argon2('pw', { ...o, memory: 24 }).finalize();
  assert.notEqual(new Argon2('pw', { ...o, memory: 35 }).finalize(), a, 'm itself goes into H0');
  assert.notEqual(new Argon2('pw', { ...o, memory: 36 }).finalize(), a);
});

// ---------- scrypt: RFC 7914 section 12 and node:crypto

const RFC7914 = [
  ['', '', 16, 1, 1, '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906'],
  ['password', 'NaCl', 1024, 8, 16, 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640'],
  ['pleaseletmein', 'SodiumChloride', 16384, 8, 1, '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'],
];

forEachEngine('RFC 7914 section 12', () => {
  for (const [password, salt, cost, blockSize, parallelization, expected] of RFC7914) {
    const key = new Scrypt(password, { salt, cost, blockSize, parallelization, length: 512 }).finalize();
    assert.equal(toHex(key), expected);
  }
});

if (process.env.SCRYPT_1GIB) {
  test('RFC 7914 section 12, N = 2^20 (1 GiB, wasm)', () => {
    const key = new Scrypt('pleaseletmein', { salt: 'SodiumChloride', cost: 1048576, length: 512 }).finalize();
    assert.equal(toHex(key), '2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4');
  });
}

forEachEngine('scrypt agrees with node:crypto at random parameters', () => {
  for (let k = 0; k < 40; k++) {
    const N = 2 ** (1 + (k % 9));
    const r = 1 + (k % 5);
    const p = 1 + ((k * 7) % 3);
    const password = randomBytes((k * 7) % 100);
    const salt = randomBytes((k * 3) % 70);
    const length = 1 + ((k * 13) % 130);
    const ours = new Scrypt(password, { salt, cost: N, blockSize: r, parallelization: p, length: length * 8 }).finalize();
    assert.equal(toHex(ours), scryptSync(password, salt, length, { N, r, p }).toString('hex'), JSON.stringify({ N, r, p, length }));
  }
});

test('scrypt: the JavaScript engine agrees with node:crypto for long passwords and salts', () => {
  const password = randomBytes(300), salt = randomBytes(200);
  assert.equal(Buffer.from(scryptJs(64, 2, 2, password, salt, 70)).toString('hex'),
    scryptSync(password, salt, 70, { N: 64, r: 2, p: 2 }).toString('hex'));
});

// ---------- the API

forEachEngine('finalize() can be called again, digest() encodes', () => {
  const a = new Argon2('pw', { salt: 'saltsalt', iterations: 1, memory: 8 });
  const s = new Scrypt('pw', { salt: 'salt', cost: 4, blockSize: 1 });
  for (const kdf of [a, s]) {
    const first = kdf.finalize();
    assert.equal(first.length, 32);
    assert.equal(kdf.finalize(), first);
    assert.deepEqual(kdf.digest(), new Uint8Array(Buffer.from(first, 'latin1')));
    assert.equal(kdf.digest('hex'), toHex(first));
    assert.equal(kdf.digest('base64'), Buffer.from(first, 'latin1').toString('base64'));
    assert.equal(kdf.digest('binary'), first);
    assert.throws(() => kdf.digest('utf8'), TypeError);
  }
});

forEachEngine('passwords and byte options as strings, bytes and views', () => {
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  const want = new Argon2('\x00\xffpw', { salt: '\x01\x02\x03\x04\x05\x06\x07\x08\x09', iterations: 1, memory: 8, secret: 'k', associatedData: 'x' }).finalize();
  const got = new Argon2(new Uint8Array([0, 255, 112, 119]).buffer, {
    salt: new DataView(salt.buffer), iterations: 1, memory: 8, secret: new Uint8Array([107]), associatedData: new Uint8Array([120]),
  }).finalize();
  assert.equal(got, want);
  const got2 = new Argon2(new Uint8Array([0, 255, 112, 119]), { salt, iterations: 1, memory: 8, secret: 'k', associatedData: new Uint8Array([120]) }).finalize();
  assert.equal(got2, want);
  assert.throws(() => new Argon2('café€', { salt: 'saltsalt', iterations: 1, memory: 8 }), TypeError);
  assert.equal(new Scrypt(new Uint8Array([97, 98]), { cost: 4, salt: new Uint8Array([99]) }).finalize(),
    new Scrypt('ab', { cost: 4, salt: 'c' }).finalize());
});

test('Argon2 options: required, ranges, types', () => {
  const ok = { salt: 'saltsalt', iterations: 1, memory: 8 };
  new Argon2('pw', ok);
  for (const key of ['salt', 'iterations', 'memory']) {
    const o = { ...ok };
    delete o[key];
    assert.throws(() => new Argon2('pw', o), { name: 'TypeError', message: `Argon2: ${key} is required` });
  }
  assert.throws(() => new Argon2('pw'), TypeError);
  assert.throws(() => new Argon2('pw', null), TypeError);
  assert.throws(() => new Argon2('pw', { ...ok, saltt: 'x' }), TypeError);
  assert.throws(() => new Argon2('pw', { ...ok, salt: 'short' }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, iterations: 0 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, iterations: 1.5 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, iterations: '1' }), TypeError);
  assert.throws(() => new Argon2('pw', { ...ok, memory: 7 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, memory: 15, parallelism: 2 }), RangeError);
  new Argon2('pw', { ...ok, memory: 16, parallelism: 2 });
  assert.throws(() => new Argon2('pw', { ...ok, parallelism: 0 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, parallelism: 2 ** 24, memory: 2 ** 32 - 1 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, memory: 2 ** 32 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, length: 24 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, length: 257 }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, type: 'argon2' }), RangeError);
  assert.throws(() => new Argon2('pw', { ...ok, type: 2 }), TypeError);
  assert.throws(() => new Argon2('pw', { ...ok, secret: 5 }), TypeError);
  assert.throws(() => new Argon2(5, ok), TypeError);
  // Inherited properties do not count, `undefined` is absent, the object is not modified.
  const proto = Object.create({ iterations: 1 });
  proto.salt = 'saltsalt';
  proto.memory = 8;
  assert.throws(() => new Argon2('pw', proto), { message: 'Argon2: iterations is required' });
  const given = { ...ok, type: undefined, length: undefined };
  const kdf = new Argon2('pw', given);
  assert.deepEqual(given, { ...ok, type: undefined, length: undefined });
  assert.deepEqual(kdf.options, {
    type: 'argon2id', salt: 'saltsalt', iterations: 1, memory: 8, parallelism: 1, length: 256, associatedData: '',
  });
});

test('scrypt options: required, ranges, types', () => {
  new Scrypt('pw', { cost: 2 });
  assert.throws(() => new Scrypt('pw', {}), { name: 'TypeError', message: 'Scrypt: cost is required' });
  assert.throws(() => new Scrypt('pw'), TypeError);
  assert.throws(() => new Scrypt('pw', { cost: 1 }), RangeError);
  assert.throws(() => new Scrypt('pw', { cost: 3 }), RangeError);
  assert.throws(() => new Scrypt('pw', { cost: 2 ** 53 }), RangeError);
  assert.throws(() => new Scrypt('pw', { cost: '16' }), TypeError);
  assert.throws(() => new Scrypt('pw', { cost: 16, blockSize: 0 }), RangeError);
  assert.throws(() => new Scrypt('pw', { cost: 16, parallelization: 0 }), RangeError);
  assert.throws(() => new Scrypt('pw', { cost: 16, blockSize: 2 ** 15, parallelization: 2 ** 15 }), RangeError);
  new Scrypt('pw', { cost: 16, blockSize: 2 ** 15, parallelization: 2 ** 15 - 1 });
  // N < 2^(16 r): with r = 1, N = 2^16 is too large.
  assert.throws(() => new Scrypt('pw', { cost: 65536, blockSize: 1 }), RangeError);
  new Scrypt('pw', { cost: 32768, blockSize: 1 });
  assert.throws(() => new Scrypt('pw', { cost: 16, length: 0 }), RangeError);
  assert.throws(() => new Scrypt('pw', { cost: 16, length: 12 }), RangeError);
  assert.throws(() => new Scrypt('pw', { cost: 16, N: 16 }), TypeError);
  assert.deepEqual(new Scrypt('pw', { cost: 16 }).options, { cost: 16, blockSize: 8, parallelization: 1, salt: '', length: 256 });
});

test('CryptoApi.argon2() and scrypt(): UTF-8 strings, hex or bytes', () => {
  const o = { salt: 'sel de mer é', iterations: 1, memory: 8, secret: 'clé', associatedData: '€' };
  const want = new Argon2(fromUtf('mot de passe é'), {
    ...o, salt: fromUtf(o.salt), secret: fromUtf(o.secret), associatedData: fromUtf(o.associatedData),
  }).finalize();
  assert.equal(CryptoApi.argon2('mot de passe é', o), toHex(want));
  assert.deepEqual(CryptoApi.argon2Bytes('mot de passe é', o), new Uint8Array(Buffer.from(want, 'latin1')));
  const s = { salt: 'é', cost: 16, blockSize: 2 };
  assert.equal(CryptoApi.scrypt('€', s), scryptSync(Buffer.from('€'), Buffer.from('é'), 32, { N: 16, r: 2, p: 1 }).toString('hex'));
  assert.deepEqual(CryptoApi.scryptBytes('€', s), new Uint8Array(scryptSync(Buffer.from('€'), Buffer.from('é'), 32, { N: 16, r: 2, p: 1 })));
  assert.throws(() => CryptoApi.argon2('pw', { salt: 'saltsalt', iterations: 1 }), TypeError);
  assert.throws(() => CryptoApi.scrypt('pw', { cost: 3 }), RangeError);
});

// ---------- wasm memory: a fresh instance per derivation, nothing left in it

function scan(memory, needles) {
  const u8 = new Uint8Array(memory.buffer);
  const found = [];
  for (const [name, needle] of needles) {
    const first = needle[0];
    for (let i = u8.indexOf(first); i !== -1 && i <= u8.length - needle.length; i = u8.indexOf(first, i + 1)) {
      let k = 1;
      while (k < needle.length && u8[i + k] === needle[k]) k++;
      if (k === needle.length) {
        found.push(name + ' at ' + i);
        break;
      }
    }
  }
  return found;
}

function nonZeroAbove(memory, start) {
  const u8 = new Uint8Array(memory.buffer);
  let n = 0;
  for (let i = start; i < u8.length; i++) if (u8[i] !== 0) n++;
  return n;
}

test('Argon2: one instance per derivation; the matrix, inputs, tag and stack are wiped', () => {
  const initial = new WebAssembly.Instance(argon2Internal.module(), {}).exports.memory.buffer.byteLength;
  argon2Internal.keepMemory(true);
  try {
    const password = Buffer.from('correct horse battery staple');
    const salt = Buffer.from('NaCl-and-pepper!');
    const secret = Buffer.from('server-side pepper key');
    const ad = Buffer.from('associated data 1234');
    for (const type of ['argon2d', 'argon2i', 'argon2id']) {
      const before = argon2Internal.instances();
      const tag = new Argon2(password, { type, salt, secret, associatedData: ad, iterations: 2, memory: 1024, parallelism: 2, length: 512 }).digest();
      assert.equal(argon2Internal.instances(), before + 1);
      const memory = argon2Internal.lastMemory();
      assert.ok(memory.buffer.byteLength >= initial + 1024 * 1024, 'memory grew for the matrix');
      assert.deepEqual(scan(memory, [['password', password], ['salt', salt], ['secret', secret], ['ad', ad], ['tag', tag.subarray(0, 16)]]), []);
      assert.equal(nonZeroAbove(memory, initial), 0, 'every byte above the initial memory is zero');
    }
  } finally {
    argon2Internal.keepMemory(false);
  }
});

test('scrypt: one instance per derivation; the work buffer, inputs, key and stack are wiped', () => {
  const initial = new WebAssembly.Instance(scryptInternal.module(), {}).exports.memory.buffer.byteLength;
  scryptInternal.keepMemory(true);
  try {
    const password = Buffer.from('correct horse battery staple');
    const salt = Buffer.from('NaCl-and-pepper!');
    const before = scryptInternal.instances();
    const key = new Scrypt(password, { salt, cost: 1024, blockSize: 8, parallelization: 2, length: 512 }).digest();
    assert.equal(scryptInternal.instances(), before + 1);
    const memory = scryptInternal.lastMemory();
    assert.ok(memory.buffer.byteLength >= initial + 1024 * 1024, 'memory grew for V');
    assert.deepEqual(scan(memory, [['password', password], ['salt', salt], ['key', key.subarray(0, 16)]]), []);
    assert.equal(nonZeroAbove(memory, initial), 0, 'every byte above the initial memory is zero');
  } finally {
    scryptInternal.keepMemory(false);
  }
});

test('the raw exports refuse bad parameters with a status', () => {
  const a = new WebAssembly.Instance(argon2Internal.module(), {}).exports;
  const out = a.alloc(64), pw = a.alloc(16), salt = a.alloc(16);
  assert.equal(a.argon2_hash(3, 1, 8, 1, pw, 16, salt, 16, 0, 0, 0, 0, out, 32), 1, 'mode');
  assert.equal(a.argon2_hash(2, 0, 8, 1, pw, 16, salt, 16, 0, 0, 0, 0, out, 32), 1, 't');
  assert.equal(a.argon2_hash(2, 1, 7, 1, pw, 16, salt, 16, 0, 0, 0, 0, out, 32), 1, 'm');
  assert.equal(a.argon2_hash(2, 1, 8, 1, pw, 16, salt, 7, 0, 0, 0, 0, out, 32), 1, 'salt');
  assert.equal(a.argon2_hash(2, 1, 8, 1, pw, 16, salt, 16, 0, 0, 0, 0, out, 3), 1, 'tag length');
  assert.equal(a.argon2_hash(2, 1, 0xFFFFFFFF, 1, pw, 16, salt, 16, 0, 0, 0, 0, out, 32), 2, 'out of memory');
  assert.equal(a.argon2_hash(2, 1, 8, 1, pw, 16, salt, 16, 0, 0, 0, 0, out, 32), 0);
  assert.equal(a.alloc(0), 0);
  assert.equal(a.alloc(0xFFFFFFFF), 0);
  const s = new WebAssembly.Instance(scryptInternal.module(), {}).exports;
  const so = s.alloc(64);
  assert.equal(s.scrypt_hash(0, 1, 1, 0, 0, 0, 0, so, 32), 1, 'ln 0');
  assert.equal(s.scrypt_hash(64, 8, 1, 0, 0, 0, 0, so, 32), 1, 'ln 64');
  assert.equal(s.scrypt_hash(16, 1, 1, 0, 0, 0, 0, so, 32), 1, 'N >= 2^(16 r)');
  assert.equal(s.scrypt_hash(4, 0, 1, 0, 0, 0, 0, so, 32), 1, 'r 0');
  assert.equal(s.scrypt_hash(4, 1, 1, 0, 0, 0, 0, so, 0), 1, 'length 0');
  assert.equal(s.scrypt_hash(30, 8, 1, 0, 0, 0, 0, so, 32), 2, 'out of memory');
  assert.equal(s.scrypt_hash(4, 1, 1, 0, 0, 0, 0, so, 32), 0);
});

test('the password and the secret are not properties of the instance', () => {
  const pw = 'hunter2-password';
  const secret = 'the-secret-value';
  const a = new Argon2(pw, { salt: 'saltsalt', iterations: 1, memory: 8, secret: secret });
  const s = new Scrypt(new TextEncoder().encode(pw), { cost: 16, blockSize: 1, salt: 'saltsalt' });
  for (const kdf of [a, s]) {
    const shown = JSON.stringify(kdf) + Object.getOwnPropertyNames(kdf).join(',');
    assert.ok(!shown.includes(pw) && !shown.includes(secret), shown);
    const first = toHex(kdf.finalize());
    assert.equal(toHex(kdf.finalize()), first); // still derivable, and the same, after the first call
  }
  assert.equal(toHex(a.finalize()), toHex(new Argon2(pw, { salt: 'saltsalt', iterations: 1, memory: 8, secret: secret }).finalize()));
});
