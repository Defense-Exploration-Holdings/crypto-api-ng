// crypto-api-ng:facade
'use strict';

import LegacyHas160 from "../../legacy/hasher/has160.mjs";
import {wasmBytes} from "../../wasm/has160.mjs";
import {Engine, BLOCK, accelProcess, accelFinalize} from "../wasm/le32.mjs";
import {checkOptions} from "../tools/input.mjs";

/*
 * HAS-160 with the compression and padding done in wasm, and everything else
 * left to the original JavaScript. Same design as md5.mjs.
 *
 * HAS-160 specifics: the `rounds` option is read from `this.options` at every
 * call, like the original reads it in `processBlock`, and is passed to wasm in
 * `State.param`. Only integers 0..80 go to wasm; anything else (strings,
 * fractions, more than 80) is the original code. The original's scratch array
 * `this.W` is not filled on the wasm path (it is an implementation detail,
 * like `blockUnits`).
 */

const engine = new Engine(wasmBytes);
const V = engine.variant('has160', 5);

/** The internals the wasm code replaces. An override of any of them must be honored. */
const P = LegacyHas160.prototype;
const ORIGINAL_BLOCK = P.processBlock;
const ORIGINAL_BITS = P.addLengthBits;
const ORIGINAL_PAD = P.addPaddingISO7816;
const ORIGINAL_HASH = P.getStateHash;

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/** The `rounds` value wasm can run, or -1. */
function roundsOf(options) {
  if (options === null || typeof options !== 'object') return -1;
  const r = options.rounds;
  return Number.isInteger(r) && r >= 0 && r <= 80 ? r : -1;
}

/** Supported `rounds`/`length` values (v2 rejects the rest). */
const OPTIONS = {rounds: {min: 1, max: 80}};

/**
 * Calculates HAS-160 hash. Same API, output and `getState()` JSON as
 * crypto-api 0.8.5; see legacy/hasher/has160.mjs for the original
 * documentation and examples.
 */
class Has160 extends LegacyHas160 {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    // Spelled out so `Has160.length` is 1, as in 0.8.5.
    checkOptions('Has160', options, OPTIONS);
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
    const rounds = roundsOf(this.options);
    if (rounds < 0 || this.processBlock !== ORIGINAL_BLOCK || !accelProcess(V, state, rounds, false)) {
      return super.process();
    }
  }

  /**
   * Finalize hash and return result
   *
   * @returns {string}
   */
  finalize() {
    const state = this.state;
    if (state !== null && typeof state === 'object' && this.blockSizeInBytes === BLOCK &&
      this.process === Has160.prototype.process && this.processBlock === ORIGINAL_BLOCK &&
      this.addLengthBits === ORIGINAL_BITS && this.addPaddingISO7816 === ORIGINAL_PAD &&
      this.getStateHash === ORIGINAL_HASH) {
      const rounds = roundsOf(this.options);
      if (rounds >= 0) {
        const digest = accelFinalize(V, state, rounds, false);
        if (digest !== null) return digest;
      }
    }
    return super.finalize();
  }
}

export default Has160;
