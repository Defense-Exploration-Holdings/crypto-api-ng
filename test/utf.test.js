// fromUtf() must produce the bytes TextEncoder produces, including for strings
// that are not well-formed UTF-16: a surrogate that is not part of a valid
// high+low pair becomes U+FFFD and does not swallow the next code unit.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { fromUtf } from '../packages/crypto-api/src/encoder/utf.mjs';
import { toHex } from '../packages/crypto-api/src/encoder/hex.mjs';
import CryptoApi from '../packages/crypto-api/src/crypto-api.mjs';
import { modelFromUtf } from './harness/fixes-model.mjs';
import { rng } from './support/le32-suite.js';

const expected = (s) => toHex(String.fromCharCode(...new TextEncoder().encode(s)));
const actual = (s) => toHex(fromUtf(s));

/** Mostly ASCII and BMP text with a high share of surrogates of both kinds, paired and not. */
function randomString(rand) {
  const parts = [];
  for (let n = Math.floor(rand() * 30); n > 0; n--) {
    const r = Math.floor(rand() * 10);
    if (r === 0) parts.push(String.fromCharCode(0xd800 + Math.floor(rand() * 0x400)));
    else if (r === 1) parts.push(String.fromCharCode(0xdc00 + Math.floor(rand() * 0x400)));
    else if (r === 2) parts.push(String.fromCodePoint(0x10000 + Math.floor(rand() * 0x100000)));
    else if (r === 3) parts.push(String.fromCharCode(0xd800 + Math.floor(rand() * 0x800)));
    else if (r < 6) parts.push(String.fromCharCode(Math.floor(rand() * 0x80)));
    else if (r < 8) parts.push(String.fromCharCode(0x80 + Math.floor(rand() * 0x780)));
    else parts.push(String.fromCharCode(Math.floor(rand() * 0xd800)));
  }
  return parts.join('');
}

test('fromUtf equals TextEncoder for random strings with lone surrogates', () => {
  const rand = rng(0x5eed);
  for (let i = 0; i < 20000; i++) {
    const s = randomString(rand);
    assert.equal(actual(s), expected(s), JSON.stringify(s));
  }
});

test('fromUtf equals TextEncoder for every single code unit and for runs of edge units', () => {
  for (let c = 0; c < 0x10000; c++) {
    const s = String.fromCharCode(c);
    assert.equal(actual(s), expected(s), c.toString(16));
  }
  const edge = [0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0x41];
  for (const a of edge) {
    for (const b of edge) {
      for (const c of edge) {
        const s = String.fromCharCode(a, b, c);
        assert.equal(actual(s), expected(s), [a, b, c].map((x) => x.toString(16)).join(' '));
      }
    }
  }
});

test('unpaired surrogates encode as U+FFFD and do not consume the next unit', () => {
  assert.equal(actual('\ud800'), 'efbfbd');
  assert.equal(actual('\udc00'), 'efbfbd');
  assert.equal(actual('a\ud800'), '61efbfbd');
  assert.equal(actual('\udc00A'), 'efbfbd41');
  assert.equal(actual('\ud800A'), 'efbfbd41');
  assert.equal(actual('\ud800\ud800'), 'efbfbdefbfbd');
  assert.equal(actual('\ud800𐀀'), 'efbfbdf0908080');
  assert.equal(actual('\udc00\ud800'), 'efbfbdefbfbd');
});

test('valid pairs are unchanged', () => {
  assert.equal(actual('\u{10000}'), 'f0908080');
  assert.equal(actual('\u{1F600}'), 'f09f9880');
  assert.equal(actual('\u{10FFFF}'), 'f48fbfbf');
  assert.equal(actual('a😀b'), '61f09f988062');
});

test('distinct strings no longer give the same bytes, digest or MAC', () => {
  // Both used to encode to f0 90 81 81.
  const lone = '\udc00A';
  const pair = '\u{10041}';
  assert.notEqual(fromUtf(lone), fromUtf(pair));
  assert.notEqual(CryptoApi.hash('sha256', lone), CryptoApi.hash('sha256', pair));
  const mac = (m) => CryptoApi.hmac('key', m, CryptoApi.getHasher('sha256'));
  assert.notEqual(mac(lone), mac(pair));
  assert.equal(CryptoApi.hash('sha256', '\ud800'), CryptoApi.hash('sha256', new Uint8Array([0xef, 0xbf, 0xbd])));
});

test('the fixes model and the package agree', () => {
  const rand = rng(7);
  for (let i = 0; i < 2000; i++) {
    const s = randomString(rand);
    assert.equal(fromUtf(s), modelFromUtf(s));
  }
});
