// crypto-api-ng:facade
'use strict';

import Hasher from "./hasher.mjs";

/**
 * Hasher for 32 bit little endian blocks
 * @interface
 */
class Hasher32le extends Hasher {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    super(options);

    /**
     * Current block (only for speed optimization)
     * @private
     * @type {number[]}
     */
    this.blockUnits = [];
  }

  /**
   * Process ready blocks
   *
   * @protected
   */
  process() {
    while (this.state.message.length >= this.blockSizeInBytes) {
      this.blockUnits = [];
      for (let b = 0; b < this.blockSizeInBytes; b += 4) {
        this.blockUnits.push(
          this.state.message.charCodeAt(b) |
          this.state.message.charCodeAt(b + 1) << 8 |
          this.state.message.charCodeAt(b + 2) << 16 |
          this.state.message.charCodeAt(b + 3) << 24);
      }
      this.state.message = this.state.message.substr(this.blockSizeInBytes);
      this.processBlock(this.blockUnits);
    }
  }

  /**
   * Process ready blocks
   *
   * @protected
   * @param {number[]} M
   */
  processBlock(M) {
  }

  /**
   * Get hash from state
   *
   * @protected
   * @param {number} [size=this.state.hash.length] - Limit hash size (in chunks)
   * @returns {string}
   */
  getStateHash(size) {
    size = size || this.state.hash.length;
    let hash = '';
    for (let i = 0; i < size; i++) {
      hash += String.fromCharCode(this.state.hash[i] & 0xff) +
        String.fromCharCode(this.state.hash[i] >> 8 & 0xff) +
        String.fromCharCode(this.state.hash[i] >> 16 & 0xff) +
        String.fromCharCode(this.state.hash[i] >> 24 & 0xff);
    }
    return hash;
  }

  /**
   * Add to message cumulative size of message in bits
   *
   * @protected
   */
  addLengthBits() {
    // The bit count as a 64-bit little-endian integer (0.8.5 used 32-bit
    // shifts, which broke messages of 2 GiB or more). Modulo 2^64 for lengths
    // that are not real byte counts (negative, beyond 2^53, from setState()).
    const length = Math.floor(this.state.length);
    const hi = Math.floor(length / 0x20000000) >>> 0;
    const lo = (length % 0x20000000) * 8;
    this.state.message +=
      String.fromCharCode(lo & 0xff) +
      String.fromCharCode(lo >>> 8 & 0xff) +
      String.fromCharCode(lo >>> 16 & 0xff) +
      String.fromCharCode(lo >>> 24 & 0xff) +
      String.fromCharCode(hi & 0xff) +
      String.fromCharCode(hi >>> 8 & 0xff) +
      String.fromCharCode(hi >>> 16 & 0xff) +
      String.fromCharCode(hi >>> 24 & 0xff);
  }
}

export default Hasher32le;