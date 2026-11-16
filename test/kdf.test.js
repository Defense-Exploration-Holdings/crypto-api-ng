// PBKDF2 and HKDF (packages/crypto-api/src/kdf/{pbkdf2,hkdf}.mjs).
//
// New in crypto-api-ng: there is no 0.8.5 class to diff against. Oracles: the RFC 6070,
// RFC 7914 and RFC 5869 test vectors, and node:crypto (OpenSSL) for every digest it has.
// Digests OpenSSL lacks are checked against a plain textbook implementation written
// here on top of `Hmac`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2Sync, hkdfSync } from 'node:crypto';

import Md5 from '../packages/crypto-api/src/hasher/md5.mjs';
import Sha1 from '../packages/crypto-api/src/hasher/sha1.mjs';
import Sha256 from '../packages/crypto-api/src/hasher/sha256.mjs';
import Sha512 from '../packages/crypto-api/src/hasher/sha512.mjs';
import Sha3 from '../packages/crypto-api/src/hasher/sha3.mjs';
import Shake from '../packages/crypto-api/src/hasher/shake.mjs';
import Blake2b from '../packages/crypto-api/src/hasher/blake2b.mjs';
import Whirlpool from '../packages/crypto-api/src/hasher/whirlpool.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import Pbkdf2 from '../packages/crypto-api/src/kdf/pbkdf2.mjs';
import Hkdf from '../packages/crypto-api/src/kdf/hkdf.mjs';
import CryptoApi from '../packages/crypto-api/src/index.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { fromUtf } from '../packages/crypto-api/src/encoder/utf.mjs';

const hex = (s) => Buffer.from(s, 'hex').toString('latin1');
const pbkdf2 = (password, hasher, options) => new Pbkdf2(password, hasher, options).finalize();
const hkdf = (ikm, hasher, options) => new Hkdf(ikm, hasher, options).finalize();

/** Every digest that node:crypto also has, as [openssl name, hasher factory, digest bytes]. */
const OPENSSL = [
  ['md5', () => new Md5(), 16],
  ['sha1', () => new Sha1(), 20],
  ['sha256', () => new Sha256({ length: 256 }), 32],
  ['sha224', () => new Sha256({ length: 224 }), 28],
  ['sha512', () => new Sha512({ length: 512 }), 64],
  ['sha384', () => new Sha512({ length: 384 }), 48],
  ['sha512-256', () => new Sha512({ length: 256 }), 32],
  ['sha3-256', () => new Sha3({ length: 256 }), 32],
  ['sha3-512', () => new Sha3({ length: 512 }), 64],
  ['blake2b512', () => new Blake2b({ length: 512 }), 64],
];

// ---------- RFC 6070 (PBKDF2-HMAC-SHA1) and RFC 7914 (PBKDF2-HMAC-SHA256)

const RFC6070 = [
  ['password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'],
  ['password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'],
  ['password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'],
  ['passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25,
    '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'],
  ['pass\0word', 'sa\0lt', 4096, 16, '56fa6aa75548099dcc37d7f03425e0c3'],
];

for (const [password, salt, iterations, bytes, expected] of RFC6070) {
  test(`RFC 6070: PBKDF2-HMAC-SHA1, ${iterations} iterations, ${bytes} bytes`, () => {
    const key = pbkdf2(password, new Sha1(), { salt, iterations, length: bytes * 8 });
    assert.equal(toHex(key), expected);
  });
}

// Opt-in (LARGE_TESTS=1): 16777216 iterations, about a minute and a half.
test('RFC 6070: PBKDF2-HMAC-SHA1, 16777216 iterations (LARGE_TESTS=1)', { skip: !process.env.LARGE_TESTS }, () => {
  const key = pbkdf2('password', new Sha1(), { salt: 'salt', iterations: 16777216, length: 160 });
  assert.equal(toHex(key), 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984');
});

test('RFC 7914 section 11: PBKDF2-HMAC-SHA256', () => {
  const key = pbkdf2('passwd', new Sha256(), { salt: 'salt', iterations: 1, length: 512 });
  assert.equal(toHex(key),
    '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
    '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783');
});

// ---------- node:crypto as the oracle

for (const [name, make, size] of OPENSSL) {
  test(`PBKDF2 over ${name} matches node:crypto`, () => {
    const cases = [
      // [password, salt, iterations, key bytes]
      ['', '', 1, size],
      ['password', 'salt', 3, 1],
      ['password', 'salt', 7, size - 1],
      ['password', 'salt', 5, size],
      ['password', 'salt', 5, size + 1],
      ['password', '\x00\xff\x80binary', 20, 2 * size + 5],
      ['k'.repeat(300), 'salt', 2, 3 * size],     // password longer than a block
      ['pässword'.replace('ä', '\xe4'), 'sälz'.replace('ä', '\xe4'), 11, 40],
    ];
    for (const [password, salt, iterations, bytes] of cases) {
      const expected = pbkdf2Sync(Buffer.from(password, 'latin1'), Buffer.from(salt, 'latin1'), iterations, bytes, name);
      const key = pbkdf2(password, make(), { salt, iterations, length: bytes * 8 });
      assert.equal(toHex(key), expected.toString('hex'), `${password.length}/${salt.length}/${iterations}/${bytes}`);
    }
  });

  test(`HKDF over ${name} matches node:crypto`, () => {
    const cases = [
      // [ikm, salt, info, key bytes]
      ['\x0b'.repeat(22), 'salt', 'info', size],
      ['\x0b'.repeat(22), '', '', 42],
      ['', 'salt', 'info', 1],
      ['ikm', '\x01'.repeat(200), 'i'.repeat(300), size - 1],
      ['ikm', 'salt', 'info', size + 1],
      ['ikm', 'salt', 'info', 255 * size],
      ['ikm', 'salt', '\x00\xff', 7 * size + 3],
    ];
    for (const [ikm, salt, info, bytes] of cases) {
      const expected = Buffer.from(hkdfSync(name, Buffer.from(ikm, 'latin1'), Buffer.from(salt, 'latin1'), Buffer.from(info, 'latin1'), bytes));
      const key = hkdf(ikm, make(), { salt, info, length: bytes * 8 });
      assert.equal(toHex(key), expected.toString('hex'), `${ikm.length}/${salt.length}/${info.length}/${bytes}`);
    }
  });
}

// ---------- RFC 5869 test vectors

const bytes = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => String.fromCharCode(from + i)).join('');

const RFC5869 = [
  ['1 (SHA-256)', () => new Sha256(), '\x0b'.repeat(22), hex('000102030405060708090a0b0c'), hex('f0f1f2f3f4f5f6f7f8f9'), 42,
    '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'],
  ['2 (SHA-256, longer inputs)', () => new Sha256(), bytes(0x00, 0x4f), bytes(0x60, 0xaf), bytes(0xb0, 0xff), 82,
    '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
    'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'],
  ['3 (SHA-256, empty salt and info)', () => new Sha256(), '\x0b'.repeat(22), '', '', 42,
    '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'],
  ['4 (SHA-1)', () => new Sha1(), '\x0b'.repeat(11), hex('000102030405060708090a0b0c'), hex('f0f1f2f3f4f5f6f7f8f9'), 42,
    '9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243',
    '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896'],
  ['5 (SHA-1, longer inputs)', () => new Sha1(), bytes(0x00, 0x4f), bytes(0x60, 0xaf), bytes(0xb0, 0xff), 82,
    '8adae09a2a307059478d309b26c4115a224cfaf6',
    '0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4'],
  ['6 (SHA-1, empty salt and info)', () => new Sha1(), '\x0b'.repeat(22), '', '', 42,
    'da8c8a73c7fa77288ec6f5e7c297786aa0d32d01',
    '0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918'],
  ['7 (SHA-1, no salt)', () => new Sha1(), '\x0c'.repeat(22), undefined, '', 42,
    '2adccada18779e7c2077ad2eb19d3f3e731385dd',
    '2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48'],
];

for (const [name, make, ikm, salt, info, length, prk, okm] of RFC5869) {
  test(`RFC 5869 test case ${name}`, () => {
    const kdf = new Hkdf(ikm, make(), { salt, info, length: length * 8 });
    assert.equal(toHex(kdf.extract()), prk);
    assert.equal(toHex(kdf.finalize()), okm);
    assert.equal(toHex(kdf.expand(info, length * 8)), okm);
  });
}

// ---------- digests OpenSSL does not have: a textbook implementation as the oracle

function textbookPbkdf2(password, make, salt, iterations, bytes) {
  const mac = (data) => { const m = new Hmac(password, make()); m.update(data); return m.finalize(); };
  const hLen = mac('').length;
  let out = '';
  for (let i = 1; out.length < bytes; i++) {
    let u = mac(salt + String.fromCharCode(0, 0, 0, i));
    const t = u.split('').map((c) => c.charCodeAt(0));
    for (let n = 1; n < iterations; n++) {
      u = mac(u);
      for (let k = 0; k < hLen; k++) t[k] ^= u.charCodeAt(k);
    }
    out += String.fromCharCode(...t);
  }
  return out.slice(0, bytes);
}

function textbookHkdf(make, ikm, salt, info, bytes) {
  const mac = (key, data) => { const m = new Hmac(key, make()); m.update(data); return m.finalize(); };
  const hLen = mac('', '').length;
  const prk = mac(salt || '\x00'.repeat(hLen), ikm);
  let out = '';
  let t = '';
  for (let i = 1; out.length < bytes; i++) {
    t = mac(prk, t + info + String.fromCharCode(i));
    out += t;
  }
  return out.slice(0, bytes);
}

const OTHERS = [
  ['whirlpool', () => new Whirlpool()],
  ['shake128 (256 bits)', () => new Shake({ strength: 128, length: 256 })],
  ['blake2b with its own key option', () => new Blake2b({ length: 256, key: 'inner key' })],
  ['sha512 truncated to 224', () => new Sha512({ length: 224 })],
];

for (const [name, make] of OTHERS) {
  test(`PBKDF2 and HKDF over ${name} match the textbook implementation`, () => {
    for (const bytes of [1, 20, 33, 100]) {
      assert.equal(toHex(pbkdf2('pw', make(), { salt: 'NaCl', iterations: 6, length: bytes * 8 })),
        toHex(textbookPbkdf2('pw', make, 'NaCl', 6, bytes)));
      assert.equal(toHex(hkdf('ikm', make(), { salt: 'salt', info: 'info', length: bytes * 8 })),
        toHex(textbookHkdf(make, 'ikm', 'salt', 'info', bytes)));
    }
  });
}

// ---------- behavior

test('the default length is the digest size', () => {
  assert.equal(pbkdf2('p', new Sha256(), { iterations: 1 }).length, 32);
  assert.equal(pbkdf2('p', new Sha512({ length: 384 }), { iterations: 1 }).length, 48);
  assert.equal(pbkdf2('p', new Md5(), { iterations: 1 }).length, 16);
  assert.equal(hkdf('k', new Sha256()).length, 32);
  assert.equal(hkdf('k', new Sha1(), {}).length, 20);
  assert.equal(hkdf('k', new Shake({ length: 1024 })).length, 128);
});

test('a derived key is a prefix of a longer one', () => {
  const long = pbkdf2('p', new Sha1(), { salt: 's', iterations: 3, length: 800 });
  assert.equal(pbkdf2('p', new Sha1(), { salt: 's', iterations: 3, length: 200 }), long.slice(0, 25));
  const longer = hkdf('k', new Sha1(), { info: 'i', length: 800 });
  assert.equal(hkdf('k', new Sha1(), { info: 'i', length: 200 }), longer.slice(0, 25));
});

test('finalize() can be repeated and the hasher passed in is not modified', () => {
  const hasher = new Sha256();
  hasher.update('data already in the hasher');
  const before = JSON.stringify(hasher.getState());
  const kdf = new Pbkdf2('p', hasher, { salt: 's', iterations: 4, length: 400 });
  const a = kdf.finalize();
  assert.equal(kdf.finalize(), a);
  assert.equal(JSON.stringify(hasher.getState()), before);
  const hk = new Hkdf('k', hasher, { info: 'i', length: 400 });
  assert.equal(hk.finalize(), hk.finalize());
  assert.equal(JSON.stringify(hasher.getState()), before);
  // the data in the hasher is not part of the result
  assert.equal(pbkdf2('p', new Sha256(), { salt: 's', iterations: 4, length: 400 }), a);
});

test('HKDF: expand() derives independent keys from one extract, with or without arguments', () => {
  const kdf = new Hkdf('secret', new Sha256(), { salt: 'salt', info: 'default info', length: 512 });
  assert.equal(kdf.expand('default info', 512), kdf.finalize());
  assert.notEqual(kdf.expand('a', 256), kdf.expand('b', 256));
  assert.equal(kdf.expand().length, 32);
  assert.equal(kdf.expand(undefined, 80).length, 10);
  assert.equal(kdf.expand(new Uint8Array([97]), 256), kdf.expand('a', 256));
  assert.equal(kdf.extract().length, 32);
});

test('bytes are accepted wherever a binary string is', () => {
  const salt = new Uint8Array([0, 1, 254, 255]);
  const options = { iterations: 3, length: 160 };
  assert.equal(pbkdf2(new Uint8Array([112, 119]), new Sha1(), { ...options, salt }),
    pbkdf2('pw', new Sha1(), { ...options, salt: '\x00\x01\xfe\xff' }));
  assert.equal(pbkdf2(new Uint8Array([112, 119]).buffer, new Sha1(), { ...options, salt: salt.buffer }),
    pbkdf2('pw', new Sha1(), { ...options, salt: '\x00\x01\xfe\xff' }));
  assert.equal(hkdf(new Uint8Array([1, 2]), new Sha1(), { salt, info: new DataView(salt.buffer) }),
    hkdf('\x01\x02', new Sha1(), { salt: '\x00\x01\xfe\xff', info: '\x00\x01\xfe\xff' }));
});

test('a user-written hasher subclass works', () => {
  class Mine extends Sha256 {}
  assert.equal(pbkdf2('p', new Mine(), { salt: 's', iterations: 3 }), pbkdf2('p', new Sha256(), { salt: 's', iterations: 3 }));
});

// ---------- validation

const sha = () => new Sha256();

test('PBKDF2 requires iterations', () => {
  assert.throws(() => new Pbkdf2('p', sha()), { name: 'TypeError', message: /iterations is required/ });
  assert.throws(() => new Pbkdf2('p', sha(), {}), { name: 'TypeError', message: /iterations is required/ });
  assert.throws(() => new Pbkdf2('p', sha(), { iterations: undefined }), { name: 'TypeError' });
  assert.throws(() => new Pbkdf2('p', sha(), { salt: 's' }), { name: 'TypeError' });
});

test('PBKDF2 iterations: an integer from 1 to 2^32 - 1', () => {
  for (const iterations of [0, -1, 1.5, NaN, Infinity, 2 ** 32, 2 ** 53]) {
    assert.throws(() => new Pbkdf2('p', sha(), { iterations }), { name: 'RangeError' }, String(iterations));
  }
  for (const iterations of ['10', true, null, 10n, [], {}]) {
    assert.throws(() => new Pbkdf2('p', sha(), { iterations }), { name: 'TypeError' }, String(iterations));
  }
  new Pbkdf2('p', sha(), { iterations: 2 ** 32 - 1 }); // accepted (not run)
});

test('PBKDF2 and HKDF length: bits, a multiple of 8, within the limit', () => {
  for (const length of [0, 4, 7, 12, -8, 1.5, NaN, Infinity]) {
    assert.throws(() => new Pbkdf2('p', sha(), { iterations: 1, length }), { name: 'RangeError' }, String(length));
    assert.throws(() => new Hkdf('k', sha(), { length }), { name: 'RangeError' }, String(length));
  }
  for (const length of ['256', true, null, 8n, {}]) {
    assert.throws(() => new Pbkdf2('p', sha(), { iterations: 1, length }), { name: 'TypeError' }, String(length));
    assert.throws(() => new Hkdf('k', sha(), { length }), { name: 'TypeError' }, String(length));
  }
  new Pbkdf2('p', sha(), { iterations: 1, length: 8 });
  new Pbkdf2('p', sha(), { iterations: 1, length: (2 ** 32 - 1) * 32 * 8 }); // the RFC 8018 limit is accepted (not run)
  assert.throws(() => new Pbkdf2('p', sha(), { iterations: 1, length: (2 ** 32 - 1) * 32 * 8 + 8 }), { name: 'RangeError' });
});

test('HKDF output is limited to 255 digests', () => {
  assert.equal(hkdf('k', sha(), { length: 255 * 32 * 8 }).length, 255 * 32);
  assert.throws(() => new Hkdf('k', sha(), { length: (255 * 32 + 1) * 8 }), { name: 'RangeError' });
  assert.throws(() => new Hkdf('k', sha(), { length: 256 * 32 * 8 }), { name: 'RangeError' });
  assert.equal(hkdf('k', new Md5(), { length: 255 * 16 * 8 }).length, 255 * 16);
  assert.throws(() => new Hkdf('k', new Md5(), { length: (255 * 16 + 1) * 8 }), { name: 'RangeError' });
  const kdf = new Hkdf('k', sha());
  assert.throws(() => kdf.expand('i', 255 * 32 * 8 + 8), { name: 'RangeError' });
  assert.throws(() => kdf.expand('i', 12), { name: 'RangeError' });
  assert.throws(() => kdf.expand('i', '256'), { name: 'TypeError' });
  assert.throws(() => kdf.expand('i', null), { name: 'TypeError' });
  assert.throws(() => kdf.expand('Ā'), { name: 'TypeError' });
  assert.throws(() => kdf.expand(5), { name: 'TypeError' });
});

test('options: unknown names, wrong types and wrong containers are errors', () => {
  assert.throws(() => new Pbkdf2('p', sha(), { iterations: 1, iteration: 5 }), { name: 'TypeError', message: /unknown option "iteration"/ });
  assert.throws(() => new Pbkdf2('p', sha(), { iterations: 1, slat: 's' }), { name: 'TypeError' });
  assert.throws(() => new Hkdf('k', sha(), { slat: 's' }), { name: 'TypeError', message: /unknown option "slat"/ });
  assert.throws(() => new Hkdf('k', sha(), { rounds: 3 }), { name: 'TypeError' });
  for (const options of [null, 'x', 5, true]) {
    assert.throws(() => new Pbkdf2('p', sha(), options), { name: 'TypeError' }, String(options));
    assert.throws(() => new Hkdf('k', sha(), options), { name: 'TypeError' }, String(options));
  }
  for (const salt of [5, null, {}, [], true, Symbol('s')]) {
    assert.throws(() => new Pbkdf2('p', sha(), { iterations: 1, salt }), { name: 'TypeError' });
    assert.throws(() => new Hkdf('k', sha(), { salt }), { name: 'TypeError' });
    assert.throws(() => new Hkdf('k', sha(), { info: salt }), { name: 'TypeError' });
  }
  assert.throws(() => new Pbkdf2('p', sha(), { iterations: 1, salt: 'Ā' }), { name: 'TypeError' });
  assert.throws(() => new Hkdf('k', sha(), { info: 'é€' }), { name: 'TypeError' });
});

test('password, key material and hasher are checked', () => {
  for (const bad of [undefined, null, 5, {}, [], 'Ā', 'é\ud83d']) {
    assert.throws(() => new Pbkdf2(bad, sha(), { iterations: 1 }), { name: 'TypeError' });
    assert.throws(() => new Hkdf(bad, sha()), { name: 'TypeError' });
  }
  for (const hasher of [undefined, null, 'sha256', 5]) {
    assert.throws(() => new Pbkdf2('p', hasher, { iterations: 1 }), { name: 'TypeError' });
    assert.throws(() => new Hkdf('k', hasher), { name: 'TypeError' });
  }
  assert.equal(hkdf('', sha()).length, 32);            // empty key material is allowed
  assert.equal(pbkdf2('', sha(), { iterations: 1 }).length, 32);
});

test('options are read as own properties only and the options object is not modified', () => {
  Object.prototype.iterations = 1; Object.prototype.salt = 'inherited'; Object.prototype.length = 8; Object.prototype.info = 'inherited';
  try {
    assert.throws(() => new Pbkdf2('p', sha(), {}), { message: /iterations is required/ });
    assert.equal(pbkdf2('p', sha(), { iterations: 2 }), pbkdf2('p', sha(), { iterations: 2, salt: '', length: 256 }));
    assert.equal(hkdf('k', sha(), {}), hkdf('k', sha(), { salt: '', info: '', length: 256 }));
    assert.equal(hkdf('k', sha()).length, 32);
    assert.equal(new Hkdf('k', sha()).expand().length, 32);
  } finally {
    delete Object.prototype.iterations; delete Object.prototype.salt; delete Object.prototype.length; delete Object.prototype.info;
  }
  const options = Object.freeze({ salt: 's', iterations: 2, length: 64 });
  assert.equal(pbkdf2('p', sha(), options).length, 8);
  const frozen = Object.freeze({ salt: 's', info: 'i', length: 64 });
  assert.equal(hkdf('k', sha(), frozen).length, 8);
  // changing the options object afterwards does not change an existing instance
  const live = { salt: 's', iterations: 2, length: 64 };
  const kdf = new Pbkdf2('p', sha(), live);
  const first = kdf.finalize();
  live.iterations = 3; live.salt = 'other'; live.length = 128;
  assert.equal(kdf.finalize(), first);
});

// ---------- CryptoApi facade

test('CryptoApi.pbkdf2() and hkdf() return hex and UTF-8 encode strings', () => {
  const api = CryptoApi;
  assert.equal(api.pbkdf2('password', api.getHasher('sha1'), { salt: 'salt', iterations: 4096, length: 160 }),
    '4b007901b765489abead49d926f721d065a429c1');
  const password = 'pässword€';
  const salt = 'sält';
  assert.equal(api.pbkdf2(password, api.getHasher('sha256'), { salt, iterations: 5, length: 320 }),
    pbkdf2Sync(Buffer.from(password), Buffer.from(salt), 5, 40, 'sha256').toString('hex'));
  assert.equal(api.pbkdf2(new Uint8Array([0xe4]), api.getHasher('sha256'), { salt: new Uint8Array([0xe4]), iterations: 5 }),
    pbkdf2Sync(Buffer.from([0xe4]), Buffer.from([0xe4]), 5, 32, 'sha256').toString('hex'));
  assert.equal(api.hkdf('ikm€', api.getHasher('sha256'), { salt, info: 'ïnfo', length: 336 }),
    Buffer.from(hkdfSync('sha256', Buffer.from('ikm€'), Buffer.from(salt), Buffer.from('ïnfo'), 42)).toString('hex'));
  assert.equal(api.hkdf('ikm', api.getHasher('sha256')), Buffer.from(hkdfSync('sha256', 'ikm', '', '', 32)).toString('hex'));
  const options = { salt: 'sält', iterations: 2 };
  api.pbkdf2('p', api.getHasher('md5'), options);
  assert.deepEqual(options, { salt: 'sält', iterations: 2 });
  assert.throws(() => api.pbkdf2('p', api.getHasher('md5')), { name: 'TypeError' });
  assert.throws(() => api.pbkdf2('p', api.getHasher('md5'), null), { name: 'TypeError' });
  assert.throws(() => api.pbkdf2(5, api.getHasher('md5'), { iterations: 1 }), { name: 'TypeError' });
  assert.throws(() => api.hkdf('k', api.getHasher('md5'), 'x'), { name: 'TypeError' });
  assert.throws(() => api.hkdf('k', api.getHasher('md5'), { length: 7 }), { name: 'RangeError' });
});
