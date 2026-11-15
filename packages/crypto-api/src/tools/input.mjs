// crypto-api-ng:facade
'use strict';

/*
 * Input and option checks shared by every hasher and by `Hmac` (v2).
 *
 * crypto-api 0.8.5 accepted anything: a string with code units above 0xFF was
 * hashed into an algorithm-specific value, other types were coerced with
 * `String()` (`Uint8Array([1, 2])` became "1,2"), and any `rounds`/`length`
 * value was used as given. v2 rejects what it cannot hash meaningfully.
 */

const WIDE = /[^\x00-\xff]/;
const CHUNK = 8192;

function describe(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  const tag = Object.prototype.toString.call(value).slice(8, -1);
  return typeof value === 'object' ? tag : typeof value;
}

function bytesOf(value) {
  if (typeof ArrayBuffer === 'undefined' || value === null || typeof value !== 'object') return null;
  const tag = Object.prototype.toString.call(value);
  if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return null;
}

/**
 * Convert an `update()` argument to the binary string the hashers work on.
 *
 * - A string is returned as is. Every code unit must be a byte (0x00-0xFF);
 *   convert text with `fromUtf()` first.
 * - An `ArrayBuffer`, `SharedArrayBuffer` or any view of one (`Uint8Array`,
 *   `DataView`, other typed arrays) contributes its bytes.
 *
 * @param {string|ArrayBuffer|ArrayBufferView} input
 * @param {string} [what='message'] - name used in error messages
 * @returns {string}
 * @throws {TypeError} for any other value, or a string with a code unit above 0xFF
 */
export function toBinaryString(input, what) {
  what = what || 'message';
  if (typeof input === 'string') {
    if (WIDE.test(input)) {
      throw new TypeError(what + ' contains characters above \\xFF; encode text with fromUtf() or pass bytes');
    }
    return input;
  }
  const bytes = bytesOf(input);
  if (bytes === null) {
    throw new TypeError(what + ' must be a binary string, an ArrayBuffer or an ArrayBuffer view, got ' + describe(input));
  }
  let s = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return s;
}

function allowed(spec) {
  if (spec.values) return spec.values.join(', ');
  return 'an integer from ' + spec.min + ' to ' + spec.max + (spec.step ? ' in steps of ' + spec.step : '');
}

/**
 * Validate the `rounds`/`length` options of a hasher before it is built.
 * An absent (`undefined`) option means the default. The options object is not
 * modified.
 *
 * @param {string} name - class name for error messages
 * @param {Object} [options]
 * @param {Object<string, {values?: number[], min?: number, max?: number, step?: number}>} specs
 * @throws {TypeError} when a value is not a number
 * @throws {RangeError} when a number is outside the supported set
 */
export function checkOptions(name, options, specs) {
  if (options === null || typeof options !== 'object') return;
  for (const key in specs) {
    const value = options[key];
    if (value === undefined) continue;
    const spec = specs[key];
    if (typeof value !== 'number') {
      throw new TypeError(name + ': ' + key + ' must be ' + allowed(spec) + ', got ' + describe(value));
    }
    const ok = spec.values ?
      spec.values.indexOf(value) !== -1 :
      Number.isInteger(value) && value >= spec.min && value <= spec.max && (!spec.step || value % spec.step === 0);
    if (!ok) {
      throw new RangeError(name + ': ' + key + ' must be ' + allowed(spec) + ', got ' + value);
    }
  }
}
