// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {absorb, finish, checkState} from "../wasm/keccak.mjs";
import {normalizeOptions, cshakePrefix, rateOf, leftEncode, rightEncode, emptyLanes, checkString, checkCount, SUFFIX_SHAKE} from "../keccak/modes.mjs";
import {toBinaryString} from "../tools/input.mjs";

/**
 * Calculates [ParallelHash](https://csrc.nist.gov/pubs/sp/800/185/final)
 * (ParallelHash128 and ParallelHash256 of NIST SP 800-185): the message is cut
 * into blocks of `blockSize` bytes, every block is hashed with SHAKE, and the
 * results are hashed with cSHAKE. The blocks are hashed one after another here;
 * the result is the same as with a parallel implementation. With `xof: true` it
 * is ParallelHashXOF128 / ParallelHashXOF256.
 *
 * @example <caption>ParallelHash128 with 8 KiB blocks - ES6 style</caption>
 * import ParallelHash from "crypto-api-ng/src/hasher/parallelhash.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new ParallelHash({blockSize: 8192});
 * hasher.update(bigMessage);
 * console.log(toHex(hasher.finalize()));
 */
class ParallelHash extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.strength=128] - Security strength in bits: 128 (ParallelHash128) or 256 (ParallelHash256)
   * @param {number} [options.length] - Output length in bits, a multiple of 8 from 8 to 2^30.
   *   Default 256 for ParallelHash128 and 512 for ParallelHash256
   * @param {number} [options.blockSize=8192] - B, the block size in bytes, from 1 to 2^53 - 1
   * @param {string|ArrayBuffer|ArrayBufferView} [options.customization] - S, the customization string
   * @param {boolean} [options.xof=false] - ParallelHashXOF: the output length is not part of the input
   */
  constructor(options) {
    const o = normalizeOptions('ParallelHash', options, {
      numbers: {blockSize: {min: 1, max: Number.MAX_SAFE_INTEGER, fallback: 8192}},
      strings: ['customization'],
      xof: true
    });
    super(o, rateOf(o.strength), cshakePrefix(1, 'ParallelHash', '').suffix, o.length / 8);
  }

  /**
   * Reset hasher to initial state. Next to the outer sponge (`message`, `hash`), the
   * state holds the SHAKE sponge of the current block (`inner`, `innerMessage`), the
   * bytes of that block so far (`filled`) and the number of finished blocks (`blocks`).
   */
  reset() {
    super.reset();
    const o = this.options;
    const state = this.state;
    state.message = cshakePrefix(rateOf(o.strength), 'ParallelHash', o.customization).prefix + leftEncode(o.blockSize);
    state.inner = emptyLanes();
    state.innerMessage = '';
    state.filled = 0;
    state.blocks = 0;
  }

  /**
   * Update message from binary string or bytes
   *
   * @param {string|ArrayBuffer|ArrayBufferView} message
   */
  update(message) {
    message = toBinaryString(message);
    const state = this.state;
    const rate = this.blockSizeInBytes;
    checkInner(state, rate, this.options.blockSize);
    checkString('ParallelHash', state.message, 'message');
    const size = this.options.blockSize;
    for (let pos = 0; pos < message.length;) {
      const take = Math.min(size - state.filled, message.length - pos);
      state.innerMessage += message.substr(pos, take);
      state.filled += take;
      pos += take;
      if (state.innerMessage.length >= rate) {
        const total = state.innerMessage.length - state.innerMessage.length % rate;
        absorb(state.inner, state.innerMessage, total, rate);
        state.innerMessage = state.innerMessage.substr(total);
      }
      if (state.filled === size) {
        state.message += chainingValue(state, rate, this.options.strength);
        state.inner = emptyLanes();
        state.innerMessage = '';
        state.filled = 0;
        state.blocks++;
      }
    }
    state.length += message.length;
    this.process();
  }

  /**
   * The chaining value of a last, partial block, the block count and the output length
   *
   * @protected
   * @returns {string}
   */
  trailer() {
    const state = this.state;
    checkInner(state, this.blockSizeInBytes, this.options.blockSize);
    let tail = '';
    let blocks = state.blocks;
    if (state.filled > 0) {
      tail = chainingValue(state, this.blockSizeInBytes, this.options.strength);
      blocks++;
    }
    return tail + rightEncode(blocks) + rightEncode(this.options.xof ? 0 : this.options.length);
  }
}

/** SHAKE of the block in `state.inner` and `state.innerMessage`; does not change the state. */
function chainingValue(state, rate, strength) {
  return finish(state.inner, state.innerMessage, rate, SUFFIX_SHAKE, strength / 4);
}

/** What `update()` and `finalize()` need of a state that `setState()` may have replaced. */
function checkInner(state, rate, size) {
  checkState(state.inner, rate);
  checkString('ParallelHash', state.innerMessage, 'innerMessage');
  checkCount('ParallelHash', state.filled, 'filled');
  checkCount('ParallelHash', state.blocks, 'blocks');
  if (state.innerMessage.length >= rate || state.filled >= size || state.innerMessage.length > state.filled) {
    throw new RangeError('ParallelHash: state.innerMessage and state.filled do not match the block size');
  }
}

export default ParallelHash;
