// crypto-api-ng:facade
'use strict';

import {bytesToHex, bytesToBase64} from "../encoder/bytes.mjs";

/*
 * What a hasher, `Hmac` or a key derivation returns from `digest()`: the binary
 * string its `finalize()` produced, as bytes (by default) or encoded as text.
 */

/**
 * The bytes of a binary string (every character is one byte).
 *
 * @ignore
 * @param {string} raw
 * @returns {Uint8Array}
 */
export function binaryToBytes(raw) {
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < out.length; i++) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

/**
 * Throw for an `encoding` that `digest()` does not know. Called before
 * `finalize()`, so a wrong argument does not use the hasher up.
 *
 * @ignore
 * @param {string} [encoding]
 * @throws {TypeError} for any other `encoding`
 */
export function checkEncoding(encoding) {
  switch (encoding) {
    case undefined:
    case 'hex':
    case 'base64':
    case 'base64url':
    case 'binary':
      return;
  }
  throw new TypeError('digest encoding must be "hex", "base64", "base64url" or "binary", or left out for bytes; got ' +
    (typeof encoding === 'string' ? '"' + encoding + '"' : typeof encoding));
}

/**
 * Encode a binary string result of `finalize()`.
 *
 * - no `encoding`: a `Uint8Array`
 * - `'hex'`, `'base64'` (with padding), `'base64url'` (without): text
 * - `'binary'`: the binary string itself, as `finalize()` returns it
 *
 * @ignore
 * @param {string} raw
 * @param {string} [encoding]
 * @returns {Uint8Array|string}
 * @throws {TypeError} for any other `encoding`
 */
export function encodeDigest(raw, encoding) {
  switch (encoding) {
    case undefined:
      return binaryToBytes(raw);
    case 'hex':
      return bytesToHex(binaryToBytes(raw));
    case 'base64':
      return bytesToBase64(binaryToBytes(raw));
    case 'base64url':
      return bytesToBase64(binaryToBytes(raw), {alphabet: 'base64url', omitPadding: true});
    case 'binary':
      return raw;
  }
  checkEncoding(encoding);
}
