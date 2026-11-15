// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {checkOptions, ownOption} from "../tools/input.mjs";

/** Supported options. */
const OPTIONS = {length: {values: [224, 256, 384, 512]}};

/**
 * Calculates [SHA-3](https://csrc.nist.gov/pubs/fips/202/final) hash
 * (SHA3-224, SHA3-256, SHA3-384 and SHA3-512 of FIPS 202)
 *
 * @example <caption>Calculates SHA3-256 from string "message" - ES6 style</caption>
 * import Sha3 from "crypto-api-ng/src/hasher/sha3.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Sha3({length: 256});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Calculates SHA3-256 from string "message" - ES5 style</caption>
 * console.log(CryptoApi.hash('sha3-256', 'message'));
 */
class Sha3 extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=512] - Digest length in bits: 224, 256, 384 or 512
   */
  constructor(options) {
    checkOptions('Sha3', options, OPTIONS);
    // Own property only: an inherited value is not an option.
    const given = ownOption(options, 'length');
    const length = given !== undefined ? given : 512;
    super(options, 200 - length / 4, 0x06, length / 8);
  }
}

export default Sha3;
