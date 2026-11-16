// The bytes-first API: digest() on hashers and Hmac, CryptoApi.hashBytes()/hmacBytes(), and the
// byte encoders (packages/crypto-api/src/encoder/bytes.mjs).
//
// New in crypto-api-ng, so there is no 0.8.5 behavior to diff against. The oracles are
// node:crypto (digests, HMAC) and Buffer / TextEncoder / TextDecoder (the encoders).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, pbkdf2Sync, hkdfSync } from 'node:crypto';

import CryptoApi from '../packages/crypto-api/src/index.mjs';
import Sha256 from '../packages/crypto-api/src/hasher/sha256.mjs';
import Sha3 from '../packages/crypto-api/src/hasher/sha3.mjs';
import Shake from '../packages/crypto-api/src/hasher/shake.mjs';
import Blake3 from '../packages/crypto-api/src/hasher/blake3.mjs';
import Hasher from '../packages/crypto-api/src/hasher/hasher.mjs';
import Hmac from '../packages/crypto-api/src/mac/hmac.mjs';
import Pbkdf2 from '../packages/crypto-api/src/kdf/pbkdf2.mjs';
import Hkdf from '../packages/crypto-api/src/kdf/hkdf.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import { toBase64 } from '../packages/crypto-api/src/encoder/base64.mjs';
import {
  utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes,
} from '../packages/crypto-api/src/encoder/bytes.mjs';
import { rng } from './support/le32-suite.js';

const NAMES = [
  'blake2b', 'blake2b-384', 'blake2b-256', 'blake2b-160', 'blake2b-128',
  'blake2s', 'blake2s-224', 'blake2s-160', 'blake2s-128', 'blake3',
  'has160', 'md2', 'md4', 'md5', 'ripemd128', 'ripemd160', 'ripemd256', 'ripemd320',
  'sha0', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sm3',
  'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'keccak224', 'keccak256', 'keccak384', 'keccak512',
  'shake128', 'shake256', 'snefru', 'snefru256', 'snefru128/2', 'snefru256/4',
  'whirlpool', 'whirlpool-0', 'whirlpool-t',
  'tiger', 'tiger160', 'tiger2', 'streebog', 'streebog256', 'crc32', 'crc32c', 'xxhash32', 'xxhash64',
];

const bytesOfHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const same = (actual, expected, message) => assert.deepStrictEqual(Array.from(actual), Array.from(expected), message);

function randomBytes(next, length) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = next() & 0xff;
  return out;
}

describe('digest() on hashers', () => {
  it('returns the bytes finalize() returns, for every algorithm', () => {
    const message = new Uint8Array(1000).map((_, i) => (i * 31 + 7) & 0xff);
    for (const name of NAMES) {
      const hex = CryptoApi.hash(name, message);
      const bytes = CryptoApi.getHasher(name);
      bytes.update(message);
      const digest = bytes.digest();
      assert.ok(digest instanceof Uint8Array, name);
      assert.equal(toHex(String.fromCharCode(...digest)), hex, name);
      assert.equal(CryptoApi.encoder.bytesToHex(CryptoApi.hashBytes(name, message)), hex, `${name} hashBytes`);
    }
  });

  it('matches node:crypto', () => {
    const next = rng(11);
    for (const [name, algo] of [['md5', 'md5'], ['sha1', 'sha1'], ['sha256', 'sha256'], ['sha512', 'sha512'], ['sha3-256', 'sha3-256']]) {
      for (const length of [0, 1, 55, 56, 64, 111, 112, 128, 1000]) {
        const message = randomBytes(next, length);
        same(CryptoApi.hashBytes(name, message), createHash(algo).update(message).digest(), `${name} ${length}`);
      }
    }
  });

  it('encodes as hex, base64, base64url and binary', () => {
    const make = () => { const s = new Sha256(); s.update('abc'); return s; };
    const expected = createHash('sha256').update('abc').digest();
    assert.equal(make().digest('hex'), expected.toString('hex'));
    assert.equal(make().digest('base64'), expected.toString('base64'));
    assert.equal(make().digest('base64url'), expected.toString('base64url'));
    const binary = make().digest('binary');
    assert.equal(typeof binary, 'string');
    assert.equal(binary, make().finalize());
    assert.equal(binary, expected.toString('latin1'));
  });

  it('pads base64 and drops the padding of base64url', () => {
    for (const [length, padded] of [[16, true], [20, true], [32, true], [48, false], [64, true]]) {
      const hasher = new Shake({ length: length * 8 });
      hasher.update('x');
      const raw = Buffer.from(hasher.digest());
      const again = new Shake({ length: length * 8 });
      again.update('x');
      const b64 = again.digest('base64');
      assert.equal(b64, raw.toString('base64'));
      assert.equal(b64.endsWith('='), padded, `${length}`);
      const third = new Shake({ length: length * 8 });
      third.update('x');
      assert.equal(third.digest('base64url'), raw.toString('base64url'));
    }
  });

  it('rejects any other encoding with TypeError, before it finalizes anything', () => {
    for (const encoding of ['HEX', 'utf8', 'latin1', 'bytes', '', null, 0, true, {}, ['hex']]) {
      const hasher = new Sha256();
      hasher.update('abc');
      assert.throws(() => hasher.digest(encoding), TypeError, String(encoding));
      // A 0.8.5 hasher is single use, so this only works if the failed call did not finalize it.
      assert.equal(hasher.digest('hex'), createHash('sha256').update('abc').digest('hex'));
    }
  });

  it('is repeatable where finalize() is, and ends the message where it does', () => {
    const sha3 = new Sha3({ length: 256 });
    sha3.update('abc');
    same(sha3.digest(), sha3.digest());
    const blake = new Blake3();
    blake.update('abc');
    assert.equal(blake.digest('hex'), blake.digest('hex'));
    // The 0.8.5 hashers are single use: digest() is finalize(), nothing more.
    const a = new Sha256();
    const b = new Sha256();
    a.update('abc');
    b.update('abc');
    assert.equal(a.digest('binary'), b.finalize());
    assert.equal(a.digest('binary'), b.finalize());
  });

  it('returns a fresh Uint8Array that owns its buffer', () => {
    const hasher = new Sha3({ length: 256 });
    hasher.update('abc');
    const first = hasher.digest();
    assert.equal(first.byteOffset, 0);
    assert.equal(first.buffer.byteLength, 32);
    first.fill(0);
    const second = hasher.digest();
    assert.notEqual(second.buffer, first.buffer);
    same(second, createHash('sha3-256').update('abc').digest());
  });

  it('works for large extendable output', () => {
    const hasher = new Shake({ strength: 128, length: 8 * 100000 });
    hasher.update('abc');
    const out = hasher.digest();
    assert.equal(out.length, 100000);
    same(out, createHash('shake128', { outputLength: 100000 }).update('abc').digest());
  });

  it('calls the finalize() of a subclass', () => {
    class Fixed extends Sha256 {
      finalize() { return '\x01\x02\xff'; }
    }
    same(new Fixed().digest(), [1, 2, 255]);
    assert.equal(new Fixed().digest('hex'), '0102ff');
  });

  it('is on the shared base class, so a hasher of your own gets it', () => {
    assert.equal(typeof Hasher.prototype.digest, 'function');
    class Mine extends Hasher {
      finalize() { return 'AB'; }
    }
    assert.equal(new Mine().digest('hex'), '4142');
  });

  it('takes bytes in and gives bytes out without a binary string in sight', () => {
    const input = new Uint8Array([0, 1, 2, 0xfe, 0xff]);
    const hasher = new Sha256();
    hasher.update(input.subarray(1, 4));
    hasher.update(input.buffer);
    same(hasher.digest(), createHash('sha256').update(input.subarray(1, 4)).update(input).digest());
  });
});

describe('digest() on Hmac and the CryptoApi helpers', () => {
  it('matches node:crypto HMAC', () => {
    const next = rng(5);
    for (const [name, algo] of [['md5', 'md5'], ['sha1', 'sha1'], ['sha256', 'sha256'], ['sha512', 'sha512'], ['sha3-256', 'sha3-256']]) {
      for (const keyLength of [0, 5, 64, 65, 200]) {
        const key = randomBytes(next, keyLength);
        const message = randomBytes(next, 77);
        const expected = createHmac(algo, key).update(message).digest();
        const mac = new Hmac(key, CryptoApi.getHasher(name));
        mac.update(message);
        same(mac.digest(), expected, `${name} ${keyLength}`);
        assert.equal(mac.digest('hex'), expected.toString('hex'));
        assert.equal(mac.digest('base64'), expected.toString('base64'));
        assert.equal(mac.digest('base64url'), expected.toString('base64url'));
        assert.equal(mac.digest('binary'), expected.toString('latin1'));
        same(CryptoApi.hmacBytes(key, message, CryptoApi.getHasher(name)), expected, `${name} hmacBytes`);
      }
    }
  });

  it('digest() leaves the message open like finalize() does', () => {
    const mac = new Hmac('key', new Sha256());
    mac.update('a');
    const one = mac.digest('hex');
    assert.equal(mac.digest('hex'), one);
    mac.update('bc');
    assert.equal(mac.digest('hex'), createHmac('sha256', 'key').update('abc').digest('hex'));
    mac.reset();
    mac.update('a');
    assert.equal(mac.digest('hex'), one);
  });

  it('rejects an unknown encoding, and the MAC can still be taken afterwards', () => {
    const mac = new Hmac('key', new Sha256());
    mac.update('abc');
    assert.throws(() => mac.digest('utf8'), TypeError);
    assert.equal(mac.digest('hex'), createHmac('sha256', 'key').update('abc').digest('hex'));
  });

  it('hashBytes and hmacBytes encode strings as UTF-8 and pass bytes through, like hash and hmac', () => {
    const text = 'héllo \u{1F600}';
    same(CryptoApi.hashBytes('sha256', text), createHash('sha256').update(text, 'utf8').digest());
    same(CryptoApi.hashBytes('sha256', Buffer.from(text)), createHash('sha256').update(text, 'utf8').digest());
    same(CryptoApi.hmacBytes('kéy', text, CryptoApi.getHasher('sha256')), createHmac('sha256', 'kéy').update(text, 'utf8').digest());
    assert.equal(CryptoApi.encoder.bytesToHex(CryptoApi.hashBytes('sha1', text)), CryptoApi.hash('sha1', text));
    assert.equal(CryptoApi.encoder.bytesToHex(CryptoApi.hmacBytes('k', text, CryptoApi.getHasher('sha1'))), CryptoApi.hmac('k', text, CryptoApi.getHasher('sha1')));
  });

  it('hashBytes honors options and rejects what hash rejects', () => {
    same(CryptoApi.hashBytes('shake128', 'abc', { length: 64 }), createHash('shake128', { outputLength: 8 }).update('abc').digest());
    assert.throws(() => CryptoApi.hashBytes('sha256', 42), TypeError);
    assert.throws(() => CryptoApi.hashBytes('sha256', 'abc', { length: 123 }), RangeError);
    assert.throws(() => CryptoApi.hashBytes('no-such-hash', 'abc'), TypeError);
  });
});

describe('key derivation in bytes', () => {
  it('Pbkdf2 digest() and CryptoApi.pbkdf2Bytes() match node:crypto', () => {
    const password = Uint8Array.from([1, 2, 3, 0xff]);
    const salt = Uint8Array.from([9, 8, 7]);
    const expected = pbkdf2Sync(password, salt, 1000, 40, 'sha256');
    const kdf = new Pbkdf2(password, new Sha256(), { salt, iterations: 1000, length: 320 });
    same(kdf.digest(), expected);
    assert.equal(kdf.digest('hex'), expected.toString('hex'));
    assert.equal(kdf.digest('base64'), expected.toString('base64'));
    assert.equal(kdf.digest('base64url'), expected.toString('base64url'));
    assert.equal(kdf.digest('binary'), kdf.finalize());
    same(CryptoApi.pbkdf2Bytes(password, CryptoApi.getHasher('sha256'), { salt, iterations: 1000, length: 320 }), expected);
    assert.equal(CryptoApi.encoder.bytesToHex(CryptoApi.pbkdf2Bytes('pw', CryptoApi.getHasher('sha1'), { salt: 's', iterations: 3 })),
      CryptoApi.pbkdf2('pw', CryptoApi.getHasher('sha1'), { salt: 's', iterations: 3 }));
    assert.throws(() => kdf.digest('utf8'), TypeError);
  });

  it('Hkdf digest(), expandBytes() and CryptoApi.hkdfBytes() match node:crypto', () => {
    const ikm = Uint8Array.from({ length: 22 }, () => 0x0b);
    const salt = Uint8Array.from({ length: 13 }, (_, i) => i);
    const info = Uint8Array.from({ length: 10 }, (_, i) => 0xf0 + i);
    const expected = Buffer.from(hkdfSync('sha256', ikm, salt, info, 42));
    const kdf = new Hkdf(ikm, new Sha256(), { salt, info, length: 336 });
    same(kdf.digest(), expected);
    assert.equal(kdf.digest('hex'), expected.toString('hex'));
    assert.equal(kdf.digest('base64url'), expected.toString('base64url'));
    same(kdf.expandBytes(info, 336), expected);
    same(CryptoApi.hkdfBytes(ikm, CryptoApi.getHasher('sha256'), { salt, info, length: 336 }), expected);
    assert.ok(kdf.expandBytes() instanceof Uint8Array);
    assert.equal(kdf.expandBytes().length, 32);
    assert.throws(() => kdf.digest('latin1'), TypeError);
    assert.throws(() => kdf.expandBytes(info, 7), RangeError);
  });
});

describe('byte encoders: hex', () => {
  it('round trips every byte and random strings, and matches Buffer', () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    assert.equal(bytesToHex(all), Buffer.from(all).toString('hex'));
    same(hexToBytes(bytesToHex(all)), all);
    const next = rng(21);
    for (let i = 0; i < 300; i++) {
      const bytes = randomBytes(next, next() % 70);
      const hex = bytesToHex(bytes);
      assert.equal(hex, Buffer.from(bytes).toString('hex'));
      same(hexToBytes(hex), bytes);
      same(hexToBytes(hex.toUpperCase()), bytes);
    }
    assert.equal(bytesToHex(new Uint8Array(0)), '');
    assert.equal(hexToBytes('').length, 0);
  });

  it('accepts any byte container and views at an offset', () => {
    const buffer = new Uint8Array([9, 0xab, 0xcd, 9]).buffer;
    assert.equal(bytesToHex(buffer), '09abcd09');
    assert.equal(bytesToHex(new Uint8Array(buffer, 1, 2)), 'abcd');
    assert.equal(bytesToHex(new DataView(buffer, 1, 2)), 'abcd');
    assert.equal(bytesToHex(Buffer.from([1, 2])), '0102');
    assert.equal(bytesToHex(new Uint16Array([0x0201])), '0102');
    assert.equal(bytesToHex(new Uint8Array(new SharedArrayBuffer(2))), '0000');
  });

  it('agrees with the binary string encoder of 0.8.5', () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    assert.equal(bytesToHex(bytes), toHex(String.fromCharCode(...bytes)));
  });

  it('throws SyntaxError for malformed hex and TypeError for the wrong type', () => {
    for (const bad of ['0', 'abc', 'zz', '0x00', 'a b', '00 ', '٠٠', 'g0', '0g']) {
      assert.throws(() => hexToBytes(bad), SyntaxError, JSON.stringify(bad));
    }
    for (const bad of [undefined, null, 1, [], new Uint8Array(2)]) {
      assert.throws(() => hexToBytes(bad), TypeError);
    }
    for (const bad of ['00', undefined, null, 1, [0], { length: 1 }]) {
      assert.throws(() => bytesToHex(bad), TypeError);
    }
  });
});

describe('byte encoders: base64', () => {
  it('matches Buffer for every length up to 70, both alphabets, with and without padding', () => {
    const next = rng(31);
    for (let length = 0; length <= 70; length++) {
      const bytes = randomBytes(next, length);
      const buffer = Buffer.from(bytes);
      assert.equal(bytesToBase64(bytes), buffer.toString('base64'), `${length}`);
      assert.equal(bytesToBase64(bytes, { omitPadding: true }), buffer.toString('base64').replace(/=+$/, ''));
      assert.equal(bytesToBase64(bytes, { alphabet: 'base64url' }), buffer.toString('base64url') + '='.repeat((3 - length % 3) % 3));
      assert.equal(bytesToBase64(bytes, { alphabet: 'base64url', omitPadding: true }), buffer.toString('base64url'));
      same(base64ToBytes(buffer.toString('base64')), bytes, `decode ${length}`);
      same(base64ToBytes(buffer.toString('base64').replace(/=+$/, '')), bytes, `decode unpadded ${length}`);
      same(base64ToBytes(buffer.toString('base64url'), { alphabet: 'base64url' }), bytes, `decode url ${length}`);
    }
  });

  it('uses the characters that tell the alphabets apart', () => {
    const bytes = Uint8Array.from([0xfb, 0xff, 0xbf]);
    assert.equal(bytesToBase64(bytes), '+/+/');
    assert.equal(bytesToBase64(bytes, { alphabet: 'base64url' }), '-_-_');
    same(base64ToBytes('+/+/'), bytes);
    same(base64ToBytes('-_-_', { alphabet: 'base64url' }), bytes);
    assert.throws(() => base64ToBytes('-_-_'), SyntaxError);
    assert.throws(() => base64ToBytes('+/+/', { alphabet: 'base64url' }), SyntaxError);
  });

  it('agrees with the binary string encoder of 0.8.5', () => {
    const next = rng(41);
    for (let length = 0; length < 40; length++) {
      const bytes = randomBytes(next, length);
      assert.equal(bytesToBase64(bytes), toBase64(String.fromCharCode(...bytes)));
    }
  });

  it('known answers (RFC 4648 section 10)', () => {
    for (const [text, encoded] of [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg=='], ['fooba', 'Zm9vYmE='], ['foobar', 'Zm9vYmFy']]) {
      assert.equal(bytesToBase64(utf8ToBytes(text)), encoded);
      assert.equal(bytesToUtf8(base64ToBytes(encoded)), text);
    }
  });

  it('ignores ASCII whitespace and accepts missing padding, but not wrong padding', () => {
    same(base64ToBytes('Zm9v\r\nYmFy\n'), utf8ToBytes('foobar'));
    same(base64ToBytes(' Z m 8 = '), utf8ToBytes('fo'));
    same(base64ToBytes('Zg'), utf8ToBytes('f'));
    same(base64ToBytes('Zg=='), utf8ToBytes('f'));
    same(base64ToBytes('Zm8'), utf8ToBytes('fo'));
    for (const bad of ['Zg=', 'Zg===', 'Zm8==', 'Zm9v=', 'Z', 'Zm9vY', '=', '==', 'Zg==Zg==', 'Zg=a', 'Zm9v====']) {
      assert.throws(() => base64ToBytes(bad), SyntaxError, JSON.stringify(bad));
    }
  });

  it('rejects characters outside the alphabet, and the text of a byte string other than its own', () => {
    for (const bad of ['Zm9v!', 'Zm9é', 'Zm9Ā', '****', 'Zm 9v ']) {
      assert.throws(() => base64ToBytes(bad), SyntaxError, JSON.stringify(bad));
    }
    // "Zh==" and "Zm9" decode to the same bytes as "Zg==" and "Zm8=" but are not what the encoder writes.
    assert.throws(() => base64ToBytes('Zh=='), SyntaxError);
    assert.throws(() => base64ToBytes('Zm9='), SyntaxError);
    assert.throws(() => base64ToBytes('Zm9'), SyntaxError);
  });

  it('checks its options', () => {
    const bytes = new Uint8Array(1);
    for (const bad of ['base32', 'BASE64', '', null, 1]) {
      assert.throws(() => bytesToBase64(bytes, { alphabet: bad }), TypeError, String(bad));
      assert.throws(() => base64ToBytes('AA==', { alphabet: bad }), TypeError);
    }
    for (const bad of [null, 'base64url', 1, true]) {
      assert.throws(() => bytesToBase64(bytes, bad), TypeError);
      assert.throws(() => base64ToBytes('AA==', bad), TypeError);
    }
    assert.equal(bytesToBase64(bytes, undefined), 'AA==');
    assert.equal(bytesToBase64(bytes, {}), 'AA==');
    assert.equal(bytesToBase64(bytes, { alphabet: undefined, omitPadding: undefined }), 'AA==');
  });

  it('reads options as own properties only (a polluted Object.prototype changes nothing)', () => {
    const bytes = Uint8Array.from([0xfb, 0xff]);
    Object.prototype.alphabet = 'base64url';
    Object.prototype.omitPadding = true;
    Object.prototype.fatal = true;
    try {
      assert.equal(bytesToBase64(bytes), '+/8=');
      assert.equal(bytesToBase64(bytes, {}), '+/8=');
      same(base64ToBytes('+/8=', {}), bytes);
      assert.equal(bytesToUtf8(Uint8Array.from([0xff]), {}), '�');
      assert.equal(bytesToUtf8(Uint8Array.from([0xff])), '�');
    } finally {
      delete Object.prototype.alphabet;
      delete Object.prototype.omitPadding;
      delete Object.prototype.fatal;
    }
  });

  it('throws TypeError for the wrong type', () => {
    for (const bad of ['AA==', undefined, null, 1, [0]]) assert.throws(() => bytesToBase64(bad), TypeError);
    for (const bad of [undefined, null, 1, new Uint8Array(1), ['AA==']]) assert.throws(() => base64ToBytes(bad), TypeError);
  });
});

// Text with every kind of character, including the ones that go wrong.
const TEXTS = [
  '', 'abc', 'héllo', '€', '\u{10000}', '\u{10FFFF}', '\u{1F600} smile', '\u0000\u007f\u0080߿ࠀ￿',
  '\ud800', '\udc00', '\ud800a', 'a\udc00', '\udc00\ud800', '😀\ud83d', '﻿bom',
];

function withoutTextCodecs(fn) {
  const { TextEncoder: encoder, TextDecoder: decoder } = globalThis;
  delete globalThis.TextEncoder;
  delete globalThis.TextDecoder;
  try {
    return fn();
  } finally {
    globalThis.TextEncoder = encoder;
    globalThis.TextDecoder = decoder;
  }
}

describe('byte encoders: UTF-8', () => {
  it('matches TextEncoder, including unpaired surrogates', () => {
    for (const text of TEXTS) {
      same(utf8ToBytes(text), new TextEncoder().encode(text), JSON.stringify(text));
    }
  });

  it('the fallback without TextEncoder gives the same bytes', () => {
    const next = rng(51);
    const random = [];
    for (let i = 0; i < 300; i++) {
      let text = '';
      for (let j = next() % 20; j > 0; j--) {
        const kind = next() % 4;
        const code = kind === 0 ? next() % 0x80 : kind === 1 ? next() % 0x800 : kind === 2 ? next() % 0x10000 : 0xd800 + next() % 0x800;
        text += String.fromCharCode(code);
        if (next() % 5 === 0) text += String.fromCodePoint(0x10000 + next() % 0x100000);
      }
      random.push(text);
    }
    const expected = [...TEXTS, ...random].map((t) => new TextEncoder().encode(t));
    const actual = withoutTextCodecs(() => {
      assert.equal(typeof globalThis.TextEncoder, 'undefined');
      return [...TEXTS, ...random].map((t) => utf8ToBytes(t));
    });
    expected.forEach((e, i) => same(actual[i], e, `case ${i}`));
  });

  it('decodes what it encodes, with the text and byte order mark intact', () => {
    for (const text of TEXTS.filter((t) => !/[\ud800-\udfff]/.test(t.replace(/[\ud800-\udbff][\udc00-\udfff]/g, '')))) {
      assert.equal(bytesToUtf8(utf8ToBytes(text)), text, JSON.stringify(text));
    }
    assert.equal(bytesToUtf8(Uint8Array.from([0xef, 0xbb, 0xbf, 0x61])), '﻿a');
  });

  it('substitutes U+FFFD for invalid bytes like TextDecoder, with and without it', () => {
    const next = rng(61);
    const cases = [
      [0xff], [0xc0, 0x80], [0xc2], [0xe0, 0x80, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xf0, 0x9f, 0x98], [0xf0, 0x9f, 0x98, 0x41],
      [0x80], [0xe2, 0x82], [0xe2, 0x82, 0x41], [0xf5], [0x41, 0xc3], [0xc3, 0xa9, 0xc3],
    ].map((a) => Uint8Array.from(a));
    for (let i = 0; i < 500; i++) cases.push(randomBytes(next, next() % 12));
    const decoder = new TextDecoder('utf-8', { ignoreBOM: true });
    const expected = cases.map((c) => decoder.decode(c));
    cases.forEach((c, i) => assert.equal(bytesToUtf8(c), expected[i], `native ${i}`));
    const fallback = withoutTextCodecs(() => cases.map((c) => bytesToUtf8(c)));
    cases.forEach((c, i) => assert.equal(fallback[i], expected[i], `fallback ${Array.from(c)}`));
  });

  it('fatal makes invalid input a TypeError, natively and in the fallback', () => {
    const invalid = [[0xff], [0xc0, 0x80], [0xc2], [0xed, 0xa0, 0x80], [0xf0, 0x9f, 0x98]].map((a) => Uint8Array.from(a));
    const valid = [utf8ToBytes('héllo \u{1F600}'), new Uint8Array(0)];
    for (const run of [(f) => f(), withoutTextCodecs]) {
      run(() => {
        for (const bytes of invalid) assert.throws(() => bytesToUtf8(bytes, { fatal: true }), TypeError, String(Array.from(bytes)));
        for (const bytes of valid) assert.equal(bytesToUtf8(bytes, { fatal: true }), bytesToUtf8(bytes));
      });
    }
  });

  it('decodes views at an offset and long input in chunks', () => {
    const text = '\u{1F600}aé'.repeat(20000);
    const bytes = utf8ToBytes(text);
    assert.equal(bytesToUtf8(bytes), text);
    assert.equal(withoutTextCodecs(() => bytesToUtf8(bytes)), text);
    const padded = new Uint8Array(bytes.length + 4);
    padded.set(bytes, 2);
    assert.equal(bytesToUtf8(padded.subarray(2, 2 + bytes.length)), text);
    assert.equal(bytesToUtf8(new Uint8Array(new SharedArrayBuffer(3)).fill(0x61)), 'aaa');
  });

  it('throws TypeError for the wrong type', () => {
    for (const bad of [undefined, null, 1, ['a'], new Uint8Array(1)]) assert.throws(() => utf8ToBytes(bad), TypeError);
    for (const bad of ['abc', undefined, null, 1, [97]]) assert.throws(() => bytesToUtf8(bad), TypeError);
    assert.throws(() => bytesToUtf8(new Uint8Array(1), null), TypeError);
  });
});

describe('the CryptoApi object', () => {
  it('has the byte encoders next to the 0.8.5 ones', () => {
    assert.deepEqual(Object.keys(CryptoApi.encoder).sort(), [
      'base64ToBytes', 'bytesToBase64', 'bytesToHex', 'bytesToUtf8', 'fromArrayBuffer', 'fromUtf', 'hexToBytes', 'toBase64', 'toHex', 'utf8ToBytes',
    ]);
    assert.equal(CryptoApi.encoder.bytesToHex, bytesToHex);
    assert.equal(CryptoApi.encoder.base64ToBytes, base64ToBytes);
  });

  it('one pipeline with no binary string: text and hex in, bytes through, base64 out', () => {
    const key = hexToBytes('000102030405060708090a0b0c0d0e0f');
    const mac = new Hmac(key, new Sha256());
    mac.update(utf8ToBytes('héllo'));
    mac.update(hexToBytes('ff00'));
    const expected = createHmac('sha256', Buffer.from(key)).update('héllo').update(Buffer.from([0xff, 0])).digest();
    assert.equal(bytesToBase64(mac.digest(), { alphabet: 'base64url', omitPadding: true }), expected.toString('base64url'));
  });
});
