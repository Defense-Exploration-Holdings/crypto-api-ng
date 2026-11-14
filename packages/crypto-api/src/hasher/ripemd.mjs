// crypto-api-ng:facade
'use strict';

import LegacyRipemd from "../../legacy/hasher/ripemd.mjs";
import {wasmBytes} from "../../wasm/ripemd.mjs";
import {Engine, BLOCK, accelProcess, accelFinalize} from "../wasm/le32.mjs";

/*
 * RIPEMD-128/160/256/320 with the compression and padding done in wasm, and
 * everything else left to the original JavaScript. Same design as md5.mjs.
 *
 * RIPEMD specifics: the original chooses the variant in `reset()` from
 * `options.length` (128, 256, 320, anything else is 160) and stores the
 * matching `processBlock*` function on the instance. The facade does not look
 * at `options` at all; it picks the wasm variant from which of those functions
 * the instance holds right now, so an odd `length` (100, '160', NaN, ...) or a
 * patched `processBlock` behaves exactly as in 0.8.5. The digest always has as
 * many words as `state.hash` has, like `getStateHash()`.
 */

const engine = new Engine(wasmBytes);
const V128 = engine.variant('ripemd128', 4);
const V160 = engine.variant('ripemd160', 5);
const V256 = engine.variant('ripemd256', 8);
const V320 = engine.variant('ripemd320', 10);

/** The internals the wasm code replaces. An override of any of them must be honored. */
const P = LegacyRipemd.prototype;
const BLOCK_128 = P.processBlock128;
const BLOCK_160 = P.processBlock160;
const BLOCK_256 = P.processBlock256;
const BLOCK_320 = P.processBlock320;
const ORIGINAL_BITS = P.addLengthBits;
const ORIGINAL_PAD = P.addPaddingISO7816;
const ORIGINAL_HASH = P.getStateHash;

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/** The wasm variant for the compression function an instance holds, or null for anything else. */
function variantOf(processBlock) {
  switch (processBlock) {
    case BLOCK_160: return V160;
    case BLOCK_128: return V128;
    case BLOCK_256: return V256;
    case BLOCK_320: return V320;
    default: return null;
  }
}

/**
 * Calculates RIPEMD hash (128, 160, 256 or 320 bits). Same API, output and
 * `getState()` JSON as crypto-api 0.8.5; see legacy/hasher/ripemd.mjs for the
 * original documentation and examples.
 */
class Ripemd extends LegacyRipemd {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    // Spelled out so `Ripemd.length` is 1, as in 0.8.5.
    super(options);
  }

  /**
   * Process ready blocks
   *
   * @protected
   * @ignore
   */
  process() {
    const state = this.state;
    if (state === null || typeof state !== 'object' || typeof state.message !== 'string' ||
      this.blockSizeInBytes !== BLOCK) {
      return super.process();
    }
    if (state.message.length < BLOCK) return;
    const v = variantOf(this.processBlock);
    if (v === null || !accelProcess(v, state, 0, false)) return super.process();
  }

  /**
   * Finalize hash and return result
   *
   * @returns {string}
   */
  finalize() {
    const state = this.state;
    if (state !== null && typeof state === 'object' && this.blockSizeInBytes === BLOCK &&
      this.process === Ripemd.prototype.process &&
      this.addLengthBits === ORIGINAL_BITS && this.addPaddingISO7816 === ORIGINAL_PAD &&
      this.getStateHash === ORIGINAL_HASH) {
      const v = variantOf(this.processBlock);
      if (v !== null) {
        const digest = accelFinalize(v, state, 0, false);
        if (digest !== null) return digest;
      }
    }
    return super.finalize();
  }
}

export default Ripemd;
