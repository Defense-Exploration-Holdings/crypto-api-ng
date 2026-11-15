// crypto-api-ng:facade
'use strict';

import Hasher from "./hasher.mjs";
import {absorb, finish} from "../wasm/keccak.mjs";

/**
 * Base class of the Keccak sponge hashers: {@link Sha3}, {@link Shake} and
 * {@link Keccak}. They differ in the block size (rate), the domain suffix
 * byte and the digest length, which the subclasses pass in.
 *
 * `state.hash` is the sponge, 25 64-bit lanes as 50 int32 words (low word of
 * each lane first). Whole blocks are absorbed as soon as they are complete;
 * `finalize()` pads a copy, so it can be called repeatedly and `update()`
 * continues the message afterwards.
 *
 * @interface
 */
class Sponge extends Hasher {
  /**
   * @param {Object} [options]
   * @param {number} rate - block size in bytes
   * @param {number} suffix - domain suffix byte
   * @param {number} outputSize - digest size in bytes
   */
  constructor(options, rate, suffix, outputSize) {
    super(options);
    /**
     * Size of unit = 1 byte
     * @type {number}
     */
    this.unitSize = 1;
    /**
     * Size of block (the sponge rate) in units
     * @type {number}
     */
    this.blockSize = rate;
    /**
     * Size of block in bytes
     * @type {number}
     */
    this.blockSizeInBytes = rate;
    /**
     * Domain separation byte appended to the message before padding
     * @protected
     * @type {number}
     */
    this.suffix = suffix;
    /**
     * Digest size in bytes
     * @protected
     * @type {number}
     */
    this.outputSize = outputSize;
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    super.reset();
    const hash = new Array(50);
    for (let i = 0; i < 50; i++) hash[i] = 0;
    this.state.hash = hash;
  }

  /**
   * Process ready blocks
   *
   * @protected
   */
  process() {
    const state = this.state;
    const rate = this.blockSizeInBytes;
    const message = state.message;
    if (message.length < rate) return;
    const total = message.length - message.length % rate;
    absorb(state.hash, message, total, rate);
    state.message = message.substr(total);
  }

  /**
   * Finalize hash and return result. The state is not changed.
   *
   * @returns {string}
   */
  finalize() {
    const rate = this.blockSizeInBytes;
    let hash = this.state.hash;
    let message = this.state.message;
    if (message.length >= rate) {
      // Only reachable through setState() with unprocessed blocks.
      hash = hash.slice();
      const total = message.length - message.length % rate;
      absorb(hash, message, total, rate);
      message = message.substr(total);
    }
    return finish(hash, message, rate, this.suffix, this.outputSize);
  }
}

export default Sponge;
