// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {checkOptions} from "../tools/input.mjs";

/** Supported options. */
const OPTIONS = {length: {values: [224, 256, 384, 512]}};

/**
 * Calculates Keccak hash with the padding of the original submission, which
 * differs from the SHA-3 standard's. Keccak-256 is the hash used by Ethereum.
 *
 * @example <caption>Calculates Keccak-256 from string "message" - ES6 style</caption>
 * import Keccak from "crypto-api-ng/src/hasher/keccak.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Keccak({length: 256});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Calculates Keccak-256 from string "message" - ES5 style</caption>
 * console.log(CryptoApi.hash('keccak256', 'message'));
 */
class Keccak extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=512] - Digest length in bits: 224, 256, 384 or 512
   */
  constructor(options) {
    checkOptions('Keccak', options, OPTIONS);
    const length = options && options.length !== undefined ? options.length : 512;
    super(options, 200 - length / 4, 0x01, length / 8);
  }
}

export default Keccak;
