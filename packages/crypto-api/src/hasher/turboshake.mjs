// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {normalizeOptions, rateOf, SUFFIX_SHAKE} from "../keccak/modes.mjs";

/**
 * Calculates [TurboSHAKE](https://www.rfc-editor.org/rfc/rfc9861) output
 * (TurboSHAKE128 and TurboSHAKE256 of RFC 9861): SHAKE with the permutation cut
 * to 12 rounds, about twice as fast, and a domain separation byte chosen by the
 * caller. It is the function KangarooTwelve is built on.
 *
 * @example <caption>32 bytes of TurboSHAKE128 - ES6 style</caption>
 * import TurboShake from "crypto-api-ng/src/hasher/turboshake.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new TurboShake({length: 256});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 */
class TurboShake extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.strength=128] - Security strength in bits: 128 (TurboSHAKE128) or 256 (TurboSHAKE256)
   * @param {number} [options.length] - Output length in bits, a multiple of 8 from 8 to 2^30.
   *   Default 256 for TurboSHAKE128 and 512 for TurboSHAKE256
   * @param {number} [options.domain=0x1f] - The domain separation byte, 0x01 to 0x7f
   */
  constructor(options) {
    const o = normalizeOptions('TurboShake', options, {numbers: {domain: {min: 1, max: 0x7f, fallback: SUFFIX_SHAKE}}});
    super(o, rateOf(o.strength), o.domain, o.length / 8, 12);
  }
}

export default TurboShake;
