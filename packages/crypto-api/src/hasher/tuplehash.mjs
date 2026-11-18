// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {normalizeOptions, cshakePrefix, rateOf, encodeString, rightEncode} from "../keccak/modes.mjs";
import {toBinaryString} from "../tools/input.mjs";

/**
 * Calculates [TupleHash](https://csrc.nist.gov/pubs/sp/800/185/final)
 * (TupleHash128 and TupleHash256 of NIST SP 800-185), a hash of a sequence of
 * strings: **every `update()` call adds one element** to the tuple, so
 * `update('ab')` gives a different result than `update('a'); update('b')`. With
 * `xof: true` it is TupleHashXOF128 / TupleHashXOF256.
 *
 * @example <caption>TupleHash128 of the tuple ("alice", "bob") - ES6 style</caption>
 * import TupleHash from "crypto-api-ng/src/hasher/tuplehash.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new TupleHash({customization: 'My Tuple App'});
 * hasher.update('alice');
 * hasher.update('bob');
 * console.log(toHex(hasher.finalize()));
 */
class TupleHash extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.strength=128] - Security strength in bits: 128 (TupleHash128) or 256 (TupleHash256)
   * @param {number} [options.length] - Output length in bits, a multiple of 8 from 8 to 2^30.
   *   Default 256 for TupleHash128 and 512 for TupleHash256
   * @param {string|ArrayBuffer|ArrayBufferView} [options.customization] - S, the customization string
   * @param {boolean} [options.xof=false] - TupleHashXOF: the output length is not part of the input
   */
  constructor(options) {
    const o = normalizeOptions('TupleHash', options, {strings: ['customization'], xof: true});
    super(o, rateOf(o.strength), cshakePrefix(1, 'TupleHash', '').suffix, o.length / 8);
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    super.reset();
    const o = this.options;
    this.state.message = cshakePrefix(rateOf(o.strength), 'TupleHash', o.customization).prefix;
  }

  /**
   * Add one element to the tuple
   *
   * @param {string|ArrayBuffer|ArrayBufferView} message - the element, a binary string or bytes
   */
  update(message) {
    message = toBinaryString(message);
    if (typeof this.state.message !== 'string') {
      throw new TypeError('TupleHash: state.message must be a string');
    }
    this.state.message += encodeString(message);
    this.state.length += message.length;
    this.process();
  }

  /**
   * The encoded output length (0 for TupleHashXOF)
   *
   * @protected
   * @returns {string}
   */
  trailer() {
    return rightEncode(this.options.xof ? 0 : this.options.length);
  }
}

export default TupleHash;
