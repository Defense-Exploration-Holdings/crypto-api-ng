// crypto-api-ng:facade
'use strict';

import {toBinaryString} from "./input.mjs";
import Hmac from "../mac/hmac.mjs";

/*
 * What `Pbkdf2` and `Hkdf` share: reading their options and the HMAC output size.
 */

const hasOwn = Object.prototype.hasOwnProperty;

function describe(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  return typeof value === 'object' ? Object.prototype.toString.call(value).slice(8, -1) : typeof value;
}

/**
 * Read an options object. Only own properties count (a value on
 * `Object.prototype` is ignored), an option that is `undefined` is absent, and
 * a name that is not in `known` is an error: a misspelled `salt` must not
 * silently derive an unsalted key. The object itself is not modified.
 *
 * @ignore
 * @param {string} name - class name for error messages
 * @param {Object} [options]
 * @param {string[]} known - the option names the class has
 * @returns {Object} a plain object holding the options that were given
 * @throws {TypeError} when `options` is not an object, or has an unknown option
 */
export function readOptions(name, options, known) {
  const result = {};
  if (options === undefined) {
    return result;
  }
  if (options === null || typeof options !== 'object') {
    throw new TypeError(name + ': options must be an object, got ' + describe(options));
  }
  for (const key of Object.keys(options)) {
    if (known.indexOf(key) === -1) {
      throw new TypeError(name + ': unknown option "' + key + '" (known: ' + known.join(', ') + ')');
    }
    if (options[key] !== undefined) {
      result[key] = options[key];
    }
  }
  return result;
}

/**
 * A byte-string option (`salt`, `info`) as a binary string; empty when absent.
 *
 * @ignore
 */
export function binaryOption(name, options, key) {
  return hasOwn.call(options, key) ? toBinaryString(options[key], name + ': ' + key) : '';
}

/**
 * Check an integer option. An absent option gives `fallback`.
 *
 * @ignore
 * @throws {TypeError} when the value is not a number
 * @throws {RangeError} when it is not an integer from `min` to `max` (in steps of `step`)
 */
export function integerOption(name, options, key, min, max, step, fallback) {
  if (!hasOwn.call(options, key)) {
    return fallback;
  }
  const value = options[key];
  if (typeof value !== 'number') {
    throw new TypeError(name + ': ' + key + ' must be a number, got ' + describe(value));
  }
  if (!Number.isInteger(value) || value < min || value > max || value % step !== 0) {
    throw new RangeError(name + ': ' + key + ' must be an integer from ' + min + ' to ' + max +
      (step > 1 ? ' in steps of ' + step : '') + ', got ' + value);
  }
  return value;
}

/**
 * Size of the HMAC output over `hasher`, in bytes.
 *
 * @ignore
 * @param {Hmac} mac
 * @returns {number}
 */
export function macSize(mac) {
  const size = mac.finalize().length;
  mac.reset();
  return size;
}

export {Hmac};
