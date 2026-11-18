// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {normalizeOptions, cshakePrefix, rateOf} from "../keccak/modes.mjs";

/**
 * Calculates [cSHAKE](https://csrc.nist.gov/pubs/sp/800/185/final) output
 * (cSHAKE128 and cSHAKE256 of NIST SP 800-185): SHAKE with a function name and a
 * customization string, so that different uses of the function give unrelated
 * outputs. With both empty, cSHAKE is SHAKE.
 *
 * @example <caption>32 bytes of cSHAKE128 with a customization string - ES6 style</caption>
 * import CShake from "crypto-api-ng/src/hasher/cshake.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new CShake({customization: 'Email Signature'});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>cSHAKE256 - ES5 style</caption>
 * console.log(CryptoApi.hash('cshake256', 'message', {customization: 'Email Signature'}));
 */
class CShake extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.strength=128] - Security strength in bits: 128 (cSHAKE128) or 256 (cSHAKE256)
   * @param {number} [options.length] - Output length in bits, a multiple of 8 from 8 to 2^30.
   *   Default 256 for cSHAKE128 and 512 for cSHAKE256
   * @param {string|ArrayBuffer|ArrayBufferView} [options.customization] - S, the customization string
   * @param {string|ArrayBuffer|ArrayBufferView} [options.functionName] - N, the function name
   *   (reserved by NIST for functions defined on top of cSHAKE)
   */
  constructor(options) {
    const o = normalizeOptions('CShake', options, {strings: ['functionName', 'customization']});
    const rate = rateOf(o.strength);
    super(o, rate, cshakePrefix(rate, o.functionName, o.customization).suffix, o.length / 8);
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    super.reset();
    const o = this.options;
    this.state.message = cshakePrefix(rateOf(o.strength), o.functionName, o.customization).prefix;
  }
}

export default CShake;
