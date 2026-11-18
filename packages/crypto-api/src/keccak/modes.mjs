// crypto-api-ng:facade
'use strict';

import {toBinaryString, checkOptions, ownOption, defineOption} from "../tools/input.mjs";

/*
 * What the hashers on top of the Keccak sponge share beyond src/hasher/sponge.mjs:
 * the encodings of NIST SP 800-185 (section 2.3) and RFC 9861 (section 3.3), the
 * cSHAKE prefix, and option handling. Everything works on binary strings.
 */

/** Largest length (in bits or bytes) these encodings take. */
const MAX = Number.MAX_SAFE_INTEGER;

/** `x` as big-endian bytes without leading zeros (one zero byte for 0 when `zero` is set). */
function bigEndian(x, zero) {
  if (!Number.isSafeInteger(x) || x < 0) {
    throw new RangeError('Keccak: cannot encode ' + x);
  }
  let s = '';
  while (x > 0) {
    s = String.fromCharCode(x % 256) + s;
    x = Math.floor(x / 256);
  }
  return s === '' && zero ? '\x00' : s;
}

/** `left_encode(x)`: the byte count, then `x` big-endian. */
export function leftEncode(x) {
  const v = bigEndian(x, true);
  return String.fromCharCode(v.length) + v;
}

/** `right_encode(x)`: `x` big-endian, then the byte count. */
export function rightEncode(x) {
  const v = bigEndian(x, true);
  return v + String.fromCharCode(v.length);
}

/** `encode_string(s)`: `left_encode` of the length in bits, then `s`. */
export function encodeString(s) {
  if (s.length * 8 > MAX) {
    throw new RangeError('Keccak: a string of ' + s.length + ' bytes is too long to encode');
  }
  return leftEncode(s.length * 8) + s;
}

/** `bytepad(x, w)`: `left_encode(w) || x`, zero padded to a multiple of `w` bytes. */
export function bytepad(x, w) {
  const s = leftEncode(w) + x;
  const pad = (w - s.length % w) % w;
  return s + new Array(pad + 1).join('\x00');
}

/** RFC 9861 `length_encode(x)`: `x` big-endian without leading zeros, then the byte count. */
export function lengthEncode(x) {
  const v = bigEndian(x, false);
  return v + String.fromCharCode(v.length);
}

/** Domain suffix of cSHAKE with a function name or customization string. */
export const SUFFIX_CSHAKE = 0x04;
/** Domain suffix of SHAKE. */
export const SUFFIX_SHAKE = 0x1f;

/**
 * The bytes cSHAKE absorbs before the message, and its domain suffix. With an
 * empty function name and customization, cSHAKE is SHAKE: no prefix.
 *
 * @param {number} rate - block size in bytes
 * @param {string} functionName - N, a binary string
 * @param {string} customization - S, a binary string
 * @returns {{prefix: string, suffix: number}}
 */
export function cshakePrefix(rate, functionName, customization) {
  if (functionName === '' && customization === '') {
    return {prefix: '', suffix: SUFFIX_SHAKE};
  }
  return {prefix: bytepad(encodeString(functionName) + encodeString(customization), rate), suffix: SUFFIX_CSHAKE};
}

/** Block size in bytes for a security strength of 128 or 256 bits. */
export function rateOf(strength) {
  return 200 - strength / 4;
}

/**
 * Check `options` and return a copy with the defaults filled in: `strength` (128 by
 * default), `length` in bits (twice the strength by default), the numeric options in
 * `numbers` (name to `checkOptions` spec plus `fallback`), the byte options in `strings`
 * as binary strings ('' when absent) and, when `xof` is set, the boolean `xof`.
 * Only own properties count: an inherited value is never an option.
 *
 * @param {string} name - class name for error messages
 * @param {*} options
 * @param {{numbers?: Object, strings?: string[], xof?: boolean}} spec
 * @returns {Object}
 * @throws {TypeError} for options that are not an object, or an option of the wrong type
 * @throws {RangeError} for a value outside the supported set
 */
export function normalizeOptions(name, options, spec) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw new TypeError(name + ': options must be an object');
  }
  const numbers = Object.assign({
    strength: {values: [128, 256]},
    length: {min: 8, max: 1073741824, step: 8}
  }, spec.numbers || {});
  checkOptions(name, options, numbers);
  const out = {};
  const strength = ownOption(options, 'strength');
  defineOption(out, 'strength', strength === undefined ? 128 : strength);
  const length = ownOption(options, 'length');
  defineOption(out, 'length', length === undefined ? 2 * out.strength : length);
  for (const key of Object.keys(numbers)) {
    if (key === 'strength' || key === 'length') continue;
    const value = ownOption(options, key);
    defineOption(out, key, value === undefined ? numbers[key].fallback : value);
  }
  for (const key of spec.strings || []) {
    const value = ownOption(options, key);
    defineOption(out, key, value === undefined ? '' : toBinaryString(value, name + ': ' + key));
  }
  if (spec.xof) {
    const xof = ownOption(options, 'xof');
    if (xof !== undefined && typeof xof !== 'boolean') {
      throw new TypeError(name + ': xof must be true or false, got ' + typeof xof);
    }
    defineOption(out, 'xof', xof === true);
  }
  return out;
}

/** `state.<key>` must be a binary string. */
export function checkString(name, value, key) {
  if (typeof value !== 'string') {
    throw new TypeError(name + ': state.' + key + ' must be a string, got ' + (value === null ? 'null' : typeof value));
  }
}

/** `state.<key>` must be a non-negative safe integer. */
export function checkCount(name, value, key) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(name + ': state.' + key + ' must be a non-negative integer');
  }
}

/** Fifty zero words: an empty sponge state. */
export function emptyLanes() {
  const hash = new Array(50);
  for (let i = 0; i < 50; i++) hash[i] = 0;
  return hash;
}
