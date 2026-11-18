// crypto-api-ng:facade
'use strict';

import Sponge from "./sponge.mjs";
import {absorb, finish, checkState} from "../wasm/keccak.mjs";
import {normalizeOptions, rateOf, lengthEncode, emptyLanes, checkString, checkCount} from "../keccak/modes.mjs";
import {toBinaryString} from "../tools/input.mjs";

const CHUNK = 8192;
const ROUNDS = 12;
const DOMAIN_SINGLE = 0x07;
const DOMAIN_FINAL = 0x06;
const DOMAIN_LEAF = 0x0b;

/**
 * Calculates [KangarooTwelve](https://www.rfc-editor.org/rfc/rfc9861) output
 * (KT128 and KT256 of RFC 9861): a fast hash on TurboSHAKE that splits long
 * messages into 8 KiB chunks. Chunks are hashed one after another here; the
 * result is the same as with a parallel implementation. The output can have
 * any length.
 *
 * @example <caption>32 bytes of KT128 - ES6 style</caption>
 * import KangarooTwelve from "crypto-api-ng/src/hasher/kangarootwelve.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new KangarooTwelve();
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>KT256 - ES5 style</caption>
 * console.log(CryptoApi.hash('kt256', 'message'));
 */
class KangarooTwelve extends Sponge {
  /**
   * @param {Object} [options]
   * @param {number} [options.strength=128] - Security strength in bits: 128 (KT128) or 256 (KT256)
   * @param {number} [options.length] - Output length in bits, a multiple of 8 from 8 to 2^30.
   *   Default 256 for KT128 and 512 for KT256
   * @param {string|ArrayBuffer|ArrayBufferView} [options.customization] - C, the customization string
   */
  constructor(options) {
    const o = normalizeOptions('KangarooTwelve', options, {strings: ['customization']});
    super(o, rateOf(o.strength), DOMAIN_SINGLE, o.length / 8, ROUNDS);
  }

  /**
   * Reset hasher to initial state. `message` and `hash` are the final node, which
   * takes the first chunk and then the chaining values; `leaf` and `leafMessage`
   * are the sponge of the chunk being hashed, `leaves` the chunks finished so far.
   */
  reset() {
    super.reset();
    this.state.leaf = emptyLanes();
    this.state.leafMessage = '';
    this.state.leaves = 0;
  }

  /**
   * Update message from binary string or bytes
   *
   * @param {string|ArrayBuffer|ArrayBufferView} message
   */
  update(message) {
    message = toBinaryString(message);
    check(this.state, this.blockSizeInBytes);
    take(this.state, message, this);
  }

  /**
   * Finalize hash and return result. The state is not changed.
   *
   * @returns {string}
   */
  finalize() {
    const rate = this.blockSizeInBytes;
    const state = this.state;
    check(state, rate);
    const copy = {
      message: state.message, length: state.length, hash: state.hash.slice(),
      leaf: state.leaf.slice(), leafMessage: state.leafMessage, leaves: state.leaves
    };
    const c = this.options.customization;
    take(copy, c + lengthEncode(c.length), this);
    let domain = DOMAIN_SINGLE;
    if (copy.length > CHUNK) {
      endLeaf(copy, this);
      copy.message += lengthEncode(copy.leaves) + '\xff\xff';
      domain = DOMAIN_FINAL;
    }
    const total = copy.message.length - copy.message.length % rate;
    absorb(copy.hash, copy.message, total, rate, ROUNDS);
    return finish(copy.hash, copy.message.substr(total), rate, domain, this.outputSize, ROUNDS);
  }
}

/** Feed bytes of `S = M || C || length_encode(|C|)` into `state`. */
function take(state, data, hasher) {
  const rate = hasher.blockSizeInBytes;
  for (let pos = 0; pos < data.length;) {
    let n;
    if (state.length < CHUNK) {
      n = Math.min(CHUNK - state.length, data.length - pos);
      state.message += data.substr(pos, n);
    } else {
      const inLeaf = (state.length - CHUNK) % CHUNK;
      if (state.length === CHUNK) {
        // More than one chunk: the final node gets the marker after the first one.
        state.message += '\x03\x00\x00\x00\x00\x00\x00\x00';
      } else if (inLeaf === 0) {
        endLeaf(state, hasher);
      }
      n = Math.min(CHUNK - inLeaf, data.length - pos);
      state.leafMessage += data.substr(pos, n);
      if (state.leafMessage.length >= rate) {
        const total = state.leafMessage.length - state.leafMessage.length % rate;
        absorb(state.leaf, state.leafMessage, total, rate, ROUNDS);
        state.leafMessage = state.leafMessage.substr(total);
      }
    }
    state.length += n;
    pos += n;
  }
  if (state.message.length >= rate) {
    const total = state.message.length - state.message.length % rate;
    absorb(state.hash, state.message, total, rate, ROUNDS);
    state.message = state.message.substr(total);
  }
}

/** Hash the current chunk into a chaining value for the final node. */
function endLeaf(state, hasher) {
  state.message += finish(state.leaf, state.leafMessage, hasher.blockSizeInBytes, DOMAIN_LEAF, hasher.options.strength / 4, ROUNDS);
  state.leaf = emptyLanes();
  state.leafMessage = '';
  state.leaves++;
}

/** What `update()` and `finalize()` need of a state that `setState()` may have replaced. */
function check(state, rate) {
  checkState(state.hash, rate);
  checkState(state.leaf, rate);
  checkString('KangarooTwelve', state.message, 'message');
  checkString('KangarooTwelve', state.leafMessage, 'leafMessage');
  checkCount('KangarooTwelve', state.length, 'length');
  checkCount('KangarooTwelve', state.leaves, 'leaves');
  if (state.leafMessage.length >= rate) {
    throw new RangeError('KangarooTwelve: state.leafMessage must be shorter than the block size');
  }
}

export default KangarooTwelve;
