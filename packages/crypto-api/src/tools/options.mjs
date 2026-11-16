// crypto-api-ng:facade
'use strict';

// Captured at load: the helper below must not be redirected by code that
// changes `Object.prototype` or `Object` afterwards.
const hasOwn = Object.prototype.hasOwnProperty;
const defineProperty = Object.defineProperty;
const keysOf = Object.keys;

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
 * falsy ones, are left alone for the original constructor to handle as before.
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
