// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {checkOptions} from "../tools/input.mjs";

/** Supported options. */
const OPTIONS = {
  strength: {values: [128, 256]},
  length: {min: 8, max: 1073741824, step: 8}
};

/**
 * Calculates [SHAKE](https://csrc.nist.gov/pubs/fips/202/final) output
 * (SHAKE128 and SHAKE256 of FIPS 202), an extendable-output function: the
 * digest can have any length.
 *
 * @example <caption>Calculates 32 bytes of SHAKE128 from string "message" - ES6 style</caption>
 * import Shake from "crypto-api-ng/src/hasher/shake.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Shake({strength: 128, length: 256});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Calculates 32 bytes of SHAKE128 from string "message" - ES5 style</caption>
 * console.log(CryptoApi.hash('shake128', 'message'));
 */
class Shake extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.strength=128] - Security strength in bits: 128 (SHAKE128) or 256 (SHAKE256)
   * @param {number} [options.length] - Output length in bits, a multiple of 8 from 8 to 2^30.
   *   Default 256 for SHAKE128 and 512 for SHAKE256
   */
  constructor(options) {
    checkOptions('Shake', options, OPTIONS);
    const strength = options && options.strength !== undefined ? options.strength : 128;
    const length = options && options.length !== undefined ? options.length : strength * 2;
    super(options, 200 - strength / 4, 0x1f, length / 8);
  }
}

export default Shake;
