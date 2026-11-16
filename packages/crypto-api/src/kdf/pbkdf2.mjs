// crypto-api-ng:facade
'use strict';

import {toBinaryString} from "../tools/input.mjs";
import {Hmac, readOptions, binaryOption, integerOption, macSize} from "../tools/kdf.mjs";

const MAX_BLOCKS = 0xFFFFFFFF;

/**
 * Derives a key from a password with
 * [PBKDF2](https://www.rfc-editor.org/rfc/rfc8018#section-5.2) (PKCS #5 v2.1)
 * using HMAC over any hasher of the library. Not part of crypto-api 0.8.5.
 *
 * `iterations` is required: there is no safe default. Choose the count for the
 * hardware you run on (OWASP advises 600000 for HMAC-SHA-256 and 210000 for
 * HMAC-SHA-512 as of 2023). The hasher passed in is not modified.
 *
 * @example <caption>32 bytes from HMAC-SHA-256</caption>
 * import Sha256 from "crypto-api-ng/src/hasher/sha256.mjs";
 * import Pbkdf2 from "crypto-api-ng/src/kdf/pbkdf2.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * const kdf = new Pbkdf2('password', new Sha256(), {salt: salt, iterations: 600000, length: 256});
 * console.log(toHex(kdf.finalize()));
 */
class Pbkdf2 {
  /**
   * @param {string|ArrayBuffer|ArrayBufferView} password - binary string or bytes
   *   (use `fromUtf()` for text that is not ASCII)
   * @param {Hasher} hasher - any hasher; `Hmac` is built on it
   * @param {Object} options
   * @param {number} options.iterations - 1 to 4294967295 (required)
   * @param {string|ArrayBuffer|ArrayBufferView} [options.salt] - binary string or bytes, default empty
   * @param {number} [options.length] - size of the derived key in bits, a multiple of 8
   *   (default: the digest size of the hasher)
   * @throws {TypeError} for an option or the password of the wrong type, or an unknown option
   * @throws {RangeError} for a value outside the supported set
   */
  constructor(password, hasher, options) {
    const given = readOptions('Pbkdf2', options, ['iterations', 'salt', 'length']);
    this.mac = new Hmac(toBinaryString(password, 'password'), hasher);
    this.size = macSize(this.mac);
    if (!Object.prototype.hasOwnProperty.call(given, 'iterations')) {
      throw new TypeError('Pbkdf2: iterations is required');
    }
    const iterations = integerOption('Pbkdf2', given, 'iterations', 1, 0xFFFFFFFF, 1);
    const length = integerOption('Pbkdf2', given, 'length', 8, MAX_BLOCKS * this.size * 8, 8, this.size * 8);
    /** @type {{salt: string, iterations: number, length: number}} */
    this.options = {salt: binaryOption('Pbkdf2', given, 'salt'), iterations: iterations, length: length};
  }

  /**
   * Derive the key and return it as a binary string. Can be called again and
   * gives the same value.
   *
   * @returns {string}
   */
  finalize() {
    const {salt, iterations, length} = this.options;
    const mac = this.mac;
    const size = this.size;
    const bytes = length / 8;
    const blocks = Math.ceil(bytes / size);
    let result = '';
    for (let block = 1; block <= blocks; block++) {
      mac.reset();
      mac.update(salt + String.fromCharCode(block >>> 24, (block >>> 16) & 0xFF, (block >>> 8) & 0xFF, block & 0xFF));
      let u = mac.finalize();
      const t = new Array(size);
      for (let i = 0; i < size; i++) {
        t[i] = u.charCodeAt(i);
      }
      for (let n = 1; n < iterations; n++) {
        mac.reset();
        mac.update(u);
        u = mac.finalize();
        for (let i = 0; i < size; i++) {
          t[i] ^= u.charCodeAt(i);
        }
      }
      result += String.fromCharCode.apply(null, t);
    }
    mac.reset();
    return result.substr(0, bytes);
  }
}

export default Pbkdf2;
