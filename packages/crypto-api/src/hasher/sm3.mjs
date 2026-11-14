// crypto-api-ng:facade
'use strict';

import LegacySm3 from "../../legacy/hasher/sm3.mjs";
import {wasmBytes} from "../../wasm/sm3.mjs";
import {createAccelerator, createFamily, roundsIn} from "../wasm/be32.mjs";

/*
 * SM3 with the compression and padding done in wasm, and everything else
 * left to the original JavaScript. Same API, output and `getState()` JSON as
 * crypto-api 0.8.5; see legacy/hasher/sm3.mjs for the original documentation and
 * examples. How this works, and the checks that make it safe: src/wasm/be32.mjs.
 *
 * Wasm is used for options.length 256 and options.rounds 1 to 64. Any other option value
 * or state runs the original code. `this.W`, the original's scratch array,
 * is not filled on the wasm path (like `blockUnits`, it is `@private`).
 */

// 120 = sizeof(sm3.State) in src/hash/sm3.zig.
const family = createFamily(wasmBytes, {sm3: 120});

const accel = createAccelerator({
  family,
  name: 'sm3',
  legacy: LegacySm3,
  words: 8,
  // Byte offsets inside the Zig `sm3.State` (src/hash/sm3.zig).
  roundsOff: 32,
  lengthOff: 40,
  bufferedOff: 48,
  bufOff: 56,
  rounds: (options) => roundsIn(options, 64),
  outBytes: (options) => options.length === 256 ? 32 : 0,
  facade: () => Sm3
});

/**
 * Calculates SM3 hash
 */
class Sm3 extends LegacySm3 {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    // Explicit, so `Sm3.length === 1` like the original (an implicit one has length 0).
    super(options);
  }

  /**
   * Process ready blocks
   *
   * @protected
   * @ignore
   */
  process() {
    if (!accel.process(this)) super.process();
  }

  /**
   * Finalize hash and return result
   *
   * @returns {string}
   */
  finalize() {
    const result = accel.finalize(this);
    return result === null ? super.finalize() : result;
  }
}

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = accel.internal;

export default Sm3;
