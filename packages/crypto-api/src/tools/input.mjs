// crypto-api-ng:facade
'use strict';

/*
 * Input and option checks shared by every hasher and by `Hmac` (1.1).
 *
 * crypto-api 0.8.5 accepted anything: a string with code units above 0xFF was
 * hashed into an algorithm-specific value, other types were coerced with
 * `String()` (`Uint8Array([1, 2])` became "1,2"), and any `rounds`/`length`
 * value was used as given. 1.1 rejects what it cannot hash meaningfully.
 */

const WIDE = /[^\x00-\xff]/;
const CHUNK = 8192;

// Captured at load: the option helpers below must not be redirected by code
// that changes `Object.prototype` or `Object` afterwards.
const hasOwn = Object.prototype.hasOwnProperty;
const defineProperty = Object.defineProperty;
const keysOf = Object.keys;

function describe(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  const tag = Object.prototype.toString.call(value).slice(8, -1);
  return typeof value === 'object' ? tag : typeof value;
}

/**
 * The bytes of an `ArrayBuffer`, `SharedArrayBuffer` or view as a Uint8Array
 * over the same memory, or null for any other value.
 *
 * @param {*} value
 * @returns {Uint8Array|null}
 */
export function bytesOf(value) {
  // A plain Uint8Array is used as it is; anything else gets a fresh view of its bytes.
  if (typeof Uint8Array !== 'undefined' && value instanceof Uint8Array &&
    Object.getPrototypeOf(value) === Uint8Array.prototype) {
    return value;
  }
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
 * An absent (`undefined`) option means the default. Only own properties of
 * `options` are looked at, like the values the hashers go on to use (see
 * `explicitOptions`). The options object is not modified.
 *
 * @param {string} name - class name for error messages
 * @param {Object} [options]
 * @param {Object<string, {values?: number[], min?: number, max?: number, step?: number}>} specs
 * @throws {TypeError} when a value is not a number
 * @throws {RangeError} when a number is outside the supported set
 */
export function checkOptions(name, options, specs) {
  if (options === null || typeof options !== 'object') return;
  const keys = keysOf(specs);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (!hasOwn.call(options, key)) continue;
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

/**
 * The options object a hasher is built from: a fresh `{}` when none was given
 * (the original uses `options || {}` too), and every option the algorithm
 * reads as an own property.
 *
 * crypto-api 0.8.5 reads `options.rounds`, `options.length` and `options.type`
 * through the prototype chain, so a value set on `Object.prototype` (by a
 * prototype-pollution bug anywhere in the page or process) silently replaced
 * the default, for example a one-round SHA-256. Here an option that is not an
 * own property of the object is defined on it with the default the original
 * would have chosen, in the order the original assigns them, so the original
 * constructor only ever sees own values. The caller's object ends up with the
 * same defaults written into it as in 0.8.5. Own values, including invalid or
 * falsy ones, are left for `checkOptions` and the original constructor to
 * handle as before.
 *
 * A value that is not an object (a number, a non-empty string, `true`) is
 * returned as is, and the original constructor handles it as it always did.
 *
 * @param {*} options
 * @param {Object} defaults - option name to default value, in assignment order
 * @returns {*}
 */
export function explicitOptions(options, defaults) {
  if (!options) options = {};
  else if (typeof options !== 'object' && typeof options !== 'function') return options;
  const keys = keysOf(defaults);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    // defineProperty, not assignment: an inherited setter or read-only value
    // of the same name must not intercept the write.
    if (!hasOwn.call(options, key)) {
      defineProperty(options, key, {value: defaults[key], writable: true, enumerable: true, configurable: true});
    }
  }
  return options;
}

/**
 * The value of option `key` if it is an own property of `options`, else
 * `undefined`. For the hashers that have no original to stay compatible with
 * (SHA-3, SHAKE, Keccak, BLAKE2, BLAKE3): a value inherited through the
 * prototype chain, for example one added to `Object.prototype` by other code on
 * the page, is never an option. A value that is not an object (`undefined`,
 * `null`, a number, a string) has no options.
 *
 * @param {*} options
 * @param {string} key
 * @returns {*}
 */
export function ownOption(options, key) {
  if (options === null || (typeof options !== 'object' && typeof options !== 'function')) return undefined;
  return hasOwn.call(options, key) ? options[key] : undefined;
}

/**
 * Set data property `key` of `target` to `value` without going through the
 * prototype chain: a plain assignment would call a setter that other code
 * installed for that name on `Object.prototype`.
 *
 * @param {Object} target
 * @param {string} key
 * @param {*} value
 */
export function defineOption(target, key, value) {
  defineProperty(target, key, {value: value, writable: true, enumerable: true, configurable: true});
}

/**
 * `checkOptions` followed by `explicitOptions`: what every facade constructor
 * passes to `super()`. The check runs first so a rejected options object is
 * not modified.
 *
 * @param {string} name
 * @param {*} options
 * @param {Object} specs - see `checkOptions`
 * @param {Object} defaults - see `explicitOptions`
 * @returns {*}
 */
export function prepareOptions(name, options, specs, defaults) {
  checkOptions(name, options, specs);
  return explicitOptions(options, defaults);
}
