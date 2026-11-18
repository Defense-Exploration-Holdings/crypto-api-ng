// crypto-api-ng:facade
'use strict';

import Hasher from "../hasher/hasher.mjs";
import {checkOptions} from "../tools/input.mjs";

/**
 * What Tiger, Streebog, CRC-32, xxHash, XXH3, SipHash and MurmurHash3 share. Not meant to be
 * used directly.
 *
 * `state` is `{message, length, counter, hash}`: the bytes not yet compressed, the length
 * of the message so far, the bytes compressed so far, and the algorithm's words as int32
 * (64-bit words are pairs, low half first). The last block of the message (1 to
 * `blockSizeInBytes` bytes) is always kept in `message` until `finalize()`, because the
 * padding is added to it. With `keep` in the spec, at least `keep` bytes are kept back instead
 * of 1 (so `message` holds up to `blockSizeInBytes + keep - 1` bytes).
 *
 * Unlike the original crypto-api hashers, `finalize()` leaves the state alone: it can be
 * called again, and `update()` continues the message.
 *
 * What a subclass provides, as `Class.spec`:
 *
 *   name         class name for error messages
 *   blockBytes   block size in bytes
 *   keep         bytes always kept back for `final` (default 1; XXH3 keeps its last 64-byte stripe)
 *   digestBytes  size of the full digest in bytes
 *   engine(options) `{blocks(state, message, start, end), final(state, tail)}`
 *   init(options) the initial `hash` words (an array of int32)
 *   specs        `checkOptions` specs of the options the class accepts (may be empty)
 *   normalize(options, out) copies the options it reads from `options` (own properties
 *                only) into `out`, with the defaults filled in
 *
 * @interface
 * @ignore
 */
class BlockHasher extends Hasher {
  /**
   * @param {Object} spec - see above
   * @param {Object} [options]
   * @throws {TypeError} for an option of the wrong type
   * @throws {RangeError} for a value outside the supported set
   */
  constructor(spec, options) {
    super(normalize(spec, options));
    this.unitSize = 4;
    this.blockSize = spec.blockBytes / 4;
    this.blockSizeInBytes = spec.blockBytes;
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    this.state = {
      message: '',
      length: 0,
      counter: 0,
      hash: this.constructor.spec.init(this.options)
    };
  }

  /**
   * Process ready blocks
   *
   * @protected
   */
  process() {
    const state = this.state;
    const spec = this.constructor.spec;
    const block = spec.blockBytes;
    const keep = spec.keep || 1;
    if (typeof state.message !== 'string') {
      throw new TypeError(spec.name + ': state.message must be a string');
    }
    const length = state.message.length;
    if (length - keep < block) {
      return;
    }
    // Everything but the last block, or the last `keep` bytes and the block they are in (those
    // are compressed by finalize()).
    const take = Math.floor((length - keep) / block) * block;
    spec.engine(this.options).blocks(state, state.message, 0, take);
    state.message = state.message.substr(take);
  }

  /**
   * Finalize hash and return result. The state is not modified.
   *
   * @returns {string}
   */
  finalize() {
    this.process();
    const spec = this.constructor.spec;
    const digest = spec.engine(this.options).final(this.state, this.state.message);
    return spec.output ? spec.output(digest, this.options) : digest;
  }
}

/**
 * Check the options and return a copy with the defaults filled in.
 *
 * @ignore
 */
function normalize(spec, options) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw new TypeError(spec.name + ': options must be an object');
  }
  options = options || {};
  const out = {};
  checkOptions(spec.name, options, spec.specs);
  spec.normalize(options, out);
  return out;
}

export default BlockHasher;
