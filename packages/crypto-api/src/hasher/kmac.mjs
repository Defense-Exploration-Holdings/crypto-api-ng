// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {normalizeOptions, cshakePrefix, rateOf, bytepad, encodeString, rightEncode} from "../keccak/modes.mjs";
import {ownOption} from "../tools/input.mjs";

/**
 * Calculates [KMAC](https://csrc.nist.gov/pubs/sp/800/185/final) (KMAC128 and
 * KMAC256 of NIST SP 800-185), a message authentication code on cSHAKE. With
 * `xof: true` it is KMACXOF128 / KMACXOF256, whose output does not depend on the
 * requested length.
 *
 * @example <caption>KMAC128 with a 32-byte key - ES6 style</caption>
 * import Kmac from "crypto-api-ng/src/hasher/kmac.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let mac = new Kmac({key: key, customization: 'My Tagged Application'});
 * mac.update('message');
 * console.log(toHex(mac.finalize()));
 *
 * @example <caption>KMAC256 - ES5 style</caption>
 * console.log(CryptoApi.hash('kmac256', 'message', {key: 'secret key'}));
 */
class Kmac extends Sponge {
  /**
   * @param {Object} options
   * @param {string|ArrayBuffer|ArrayBufferView} options.key - the key, of any length (required)
   * @param {number} [options.strength=128] - Security strength in bits: 128 (KMAC128) or 256 (KMAC256)
   * @param {number} [options.length] - MAC length in bits, a multiple of 8 from 8 to 2^30.
   *   Default 256 for KMAC128 and 512 for KMAC256
   * @param {string|ArrayBuffer|ArrayBufferView} [options.customization] - S, the customization string
   * @param {boolean} [options.xof=false] - KMACXOF: the output length is not part of the input
   * @throws {TypeError} without a key
   */
  constructor(options) {
    if (ownOption(options, 'key') === undefined) {
      throw new TypeError('Kmac: options.key is required');
    }
    const o = normalizeOptions('Kmac', options, {strings: ['key', 'customization'], xof: true});
    super(o, rateOf(o.strength), cshakePrefix(1, 'KMAC', '').suffix, o.length / 8);
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    super.reset();
    const o = this.options;
    const rate = rateOf(o.strength);
    this.state.message = cshakePrefix(rate, 'KMAC', o.customization).prefix + bytepad(encodeString(o.key), rate);
  }

  /**
   * The encoded output length (0 for KMACXOF)
   *
   * @protected
   * @returns {string}
   */
  trailer() {
    return rightEncode(this.options.xof ? 0 : this.options.length);
  }
}

export default Kmac;
