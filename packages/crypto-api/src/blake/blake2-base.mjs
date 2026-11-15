// crypto-api-ng:facade
'use strict';

import Hasher from "../hasher/hasher.mjs";
import {toBinaryString, checkOptions} from "../tools/input.mjs";

/**
 * What BLAKE2b and BLAKE2s share (RFC 7693, sequential mode). Not meant to be
 * used directly: see {@link Blake2b} and {@link Blake2s}.
 *
 * `state` is `{message, length, counter, hash}`: the bytes not yet compressed, the
 * length of the message so far, the bytes compressed so far (including the key block),
 * and the chaining value as int32 words (BLAKE2b: pairs, low half first). The last
 * block of the message is always kept in `message` until `finalize()`, because it
 * is compressed with a different flag. With a key, the zero-padded key block is the
 * first thing in `message`.
 *
 * Unlike the original crypto-api hashers, `finalize()` leaves the state alone: it
 * can be called again, and `update()` continues the message.
 *
 * @interface
 * @ignore
 */
class Blake2 extends Hasher {
  /**
   * @param {Object} spec - the algorithm constants (see blake2b.mjs)
   * @param {Object} [options]
   * @param {number} [options.length] - digest size in bits, a multiple of 8
   * @param {string|ArrayBuffer|ArrayBufferView} [options.key] - makes the hash a MAC
   * @param {string|ArrayBuffer|ArrayBufferView} [options.salt] - zero padded to the salt size
   * @param {string|ArrayBuffer|ArrayBufferView} [options.personalization] - zero padded
   * @throws {TypeError} for an option of the wrong type
   * @throws {RangeError} for a value outside the supported set
   */
  constructor(spec, options) {
    super(normalize(spec, options));
    this.unitSize = spec.wordBytes;
    this.blockSize = 16;
    this.blockSizeInBytes = spec.blockBytes;
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    const spec = this.constructor.spec;
    const options = this.options;
    const hash = spec.iv.slice();
    // Parameter block, sequential mode: digest length, key length, fanout 1, depth 1.
    const key = options.key || '';
    hash[0] ^= (options.length / 8) | (key.length << 8) | (1 << 16) | (1 << 24);
    xorParam(hash, spec, 4, options.salt);
    xorParam(hash, spec, 6, options.personalization);
    this.state = {
      message: key.length === 0 ? '' : key + new Array(spec.blockBytes - key.length + 1).join("\x00"),
      length: 0,
      counter: 0,
      hash: hash
    };
  }

  /**
   * Process ready blocks
   *
   * @protected
   */
  process() {
    const state = this.state;
    const block = this.constructor.spec.blockBytes;
    const length = state.message.length;
    if (length <= block) {
      return;
    }
    // Everything but the last block (the last one is compressed by finalize()).
    const take = Math.floor((length - 1) / block) * block;
    this.constructor.spec.engine().blocks(state, state.message, 0, take);
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
    return spec.engine().final(this.state, this.state.message).substr(0, this.options.length / 8);
  }
}

/**
 * Check the options and return a copy with the defaults filled in. `key`, `salt`
 * and `personalization` come back as binary strings.
 *
 * @ignore
 */
function normalize(spec, options) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw new TypeError(spec.name + ': options must be an object');
  }
  options = options || {};
  const out = {};
  checkOptions(spec.name, options, {length: {min: 8, max: 8 * spec.digestBytes, step: 8}});
  out.length = options.length === undefined ? 8 * spec.digestBytes : options.length;
  [['key', spec.digestBytes], ['salt', spec.paramBytes], ['personalization', spec.paramBytes]].forEach((entry) => {
    const name = entry[0];
    if (options[name] !== undefined) {
      const value = toBinaryString(options[name], name);
      if (value.length > entry[1]) {
        throw new RangeError(spec.name + ': ' + name + ' can be at most ' + entry[1] + ' bytes, got ' + value.length);
      }
      out[name] = value;
    }
  });
  return out;
}

/** XOR a salt or personalization (zero padded) into the two chaining words at `at`. */
function xorParam(hash, spec, at, value) {
  if (value === undefined) {
    return;
  }
  for (let i = 0; i < spec.paramBytes; i += 4) {
    let w = 0;
    for (let k = 0; k < 4; k++) {
      w |= (i + k < value.length ? value.charCodeAt(i + k) : 0) << (8 * k);
    }
    // 32-bit slot `i / 4` of the parameter bytes lands in hash int `at * (wordBytes / 4) + i / 4`.
    hash[at * (spec.wordBytes / 4) + i / 4] ^= w;
  }
}

export default Blake2;
