// crypto-api-ng:facade
'use strict';

import LegacyMd4 from "../../legacy/hasher/md4.mjs";
import {wasmBytes} from "../../wasm/md.mjs";
import {Engine, BLOCK, accelProcess, accelFinalize} from "../wasm/le32.mjs";

/*
 * MD4 with the compression and padding done in wasm, and everything else left
 * to the original JavaScript. Same design as md5.mjs (recipe in
 * docs/porting-guide.md): extend the verbatim 0.8.5 class, override only
 * `process()` and `finalize()`, keep `this.state` the original plain object,
 * and delegate to `super` whenever the state or the class is not exactly what
 * the wasm code models.
 *
 * MD4 specifics: the original assigns a fresh `state.hash` array after every
 * block (it does not write into the old one), so the facade does too.
 */

const engine = new Engine(wasmBytes);
const V = engine.variant('md4', 4);

/** The internals the wasm code replaces. An override of any of them must be honored. */
const P = LegacyMd4.prototype;
const ORIGINAL_BLOCK = P.processBlock;
const ORIGINAL_BITS = P.addLengthBits;
const ORIGINAL_PAD = P.addPaddingISO7816;
const ORIGINAL_HASH = P.getStateHash;

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates [MD4](https://tools.ietf.org/html/rfc1320) hash. Same API,
 * output and `getState()` JSON as crypto-api 0.8.5; see legacy/hasher/md4.mjs
 * for the original documentation and examples.
 */
class Md4 extends LegacyMd4 {
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
    if (this.processBlock !== ORIGINAL_BLOCK || !accelProcess(V, state, 0, true)) return super.process();
  }

  /**
   * Finalize hash and return result
   *
   * @returns {string}
   */
  finalize() {
    const state = this.state;
    if (state !== null && typeof state === 'object' && this.blockSizeInBytes === BLOCK &&
      this.process === Md4.prototype.process && this.processBlock === ORIGINAL_BLOCK &&
      this.addLengthBits === ORIGINAL_BITS && this.addPaddingISO7816 === ORIGINAL_PAD &&
      this.getStateHash === ORIGINAL_HASH) {
      const digest = accelFinalize(V, state, 0, true);
      if (digest !== null) return digest;
    }
    return super.finalize();
  }
}

export default Md4;
