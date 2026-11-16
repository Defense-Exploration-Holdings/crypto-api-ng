// crypto-api-ng:facade
'use strict';

import {toBinaryString} from "../tools/input.mjs";
import {Hmac, readOptions, binaryOption, integerOption, macSize} from "../tools/kdf.mjs";

/**
 * Derives keys from key material with
 * [HKDF](https://www.rfc-editor.org/rfc/rfc5869) (extract-and-expand) using
 * HMAC over any hasher of the library. Not part of crypto-api 0.8.5.
 *
 * The extract step runs in the constructor. `finalize()` expands with the
 * `info` and `length` options, and `expand()` derives more keys from the same
 * pseudorandom key with other `info` values. The hasher passed in is not
 * modified.
 *
 * @example <caption>Two 32-byte keys from one secret</caption>
 * import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
 * import Hkdf from "crypto-api-ng/src/kdf/hkdf.mjs";
 *
 * const kdf = new Hkdf(sharedSecret, new Sha256(), {salt: salt});
 * const encryptionKey = kdf.expand('my-app encryption', 256);
 * const macKey = kdf.expand('my-app mac', 256);
 */
class Hkdf {
  /**
   * @param {string|ArrayBuffer|ArrayBufferView} ikm - input key material, binary string or bytes
   * @param {Hasher} hasher - any hasher; `Hmac` is built on it
   * @param {Object} [options]
   * @param {string|ArrayBuffer|ArrayBufferView} [options.salt] - default empty (the same as
   *   a salt of zero bytes the size of the digest, as RFC 5869 defines it)
   * @param {string|ArrayBuffer|ArrayBufferView} [options.info] - context for `finalize()`, default empty
   * @param {number} [options.length] - size of the output of `finalize()` in bits, a multiple
   *   of 8, up to 255 times the digest size (default: the digest size of the hasher)
   * @throws {TypeError} for an option or the key material of the wrong type, or an unknown option
   * @throws {RangeError} for a value outside the supported set
   */
  constructor(ikm, hasher, options) {
    const given = readOptions('Hkdf', options, ['salt', 'info', 'length']);
    const salt = binaryOption('Hkdf', given, 'salt');
    const info = binaryOption('Hkdf', given, 'info');
    const input = toBinaryString(ikm, 'ikm');
    // A fresh HMAC over the same hasher gives the size; the salt is its key.
    this.size = macSize(new Hmac('', hasher));
    const length = lengthOption(given, this.size);
    const extract = new Hmac(salt, hasher);
    extract.update(input);
    /** @ignore */
    this.hasher = hasher;
    /** @ignore */
    this.prk = extract.finalize();
    /** @type {{salt: string, info: string, length: number}} */
    this.options = {salt: salt, info: info, length: length};
  }

  /**
   * The pseudorandom key of the extract step (HKDF-Extract), as a binary string.
   *
   * @returns {string}
   */
  extract() {
    return this.prk;
  }

  /**
   * HKDF-Expand with the given context.
   *
   * @param {string|ArrayBuffer|ArrayBufferView} [info] - default empty
   * @param {number} [length] - size of the output in bits, a multiple of 8, up to 255 times
   *   the digest size (default: the digest size of the hasher)
   * @returns {string}
   * @throws {TypeError} when `info` or `length` has the wrong type
   * @throws {RangeError} when `length` is outside the supported set
   */
  expand(info, length) {
    info = info === undefined ? '' : toBinaryString(info, 'info');
    length = length === undefined ? this.size * 8 : lengthOption({length: length}, this.size);
    return expand(this.hasher, this.prk, info, length / 8, this.size);
  }

  /**
   * HKDF-Expand with the `info` and `length` options. Can be called again and
   * gives the same value.
   *
   * @returns {string}
   */
  finalize() {
    return expand(this.hasher, this.prk, this.options.info, this.options.length / 8, this.size);
  }
}

function lengthOption(options, size) {
  return integerOption('Hkdf', options, 'length', 8, 255 * size * 8, 8, size * 8);
}

function expand(hasher, prk, info, bytes, size) {
  const mac = new Hmac(prk, hasher);
  const blocks = Math.ceil(bytes / size);
  let result = '';
  let t = '';
  for (let i = 1; i <= blocks; i++) {
    mac.reset();
    mac.update(t + info + String.fromCharCode(i));
    t = mac.finalize();
    result += t;
  }
  return result.substr(0, bytes);
}

export default Hkdf;
