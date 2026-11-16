// crypto-api-ng:facade
'use strict';

import LegacySha256 from "../../legacy/hasher/sha256.mjs";
import {wasmBytes} from "../../wasm/sha256.mjs";
import {createAccelerator, createFamily, roundsIn} from "../wasm/be32.mjs";
import {explicitOptions} from "../tools/options.mjs";

/*
 * SHA-224/256 with the compression and padding done in wasm, and everything else
 * left to the original JavaScript. Same API, output and `getState()` JSON as
 * crypto-api 0.8.5; see legacy/hasher/sha256.mjs for the original documentation and
 * examples. How this works, and the checks that make it safe: src/wasm/be32.mjs.
 *
 * Wasm is used for options.length 224 or 256 and options.rounds 1 to 64. Any other option value
 * or state runs the original code. `this.W`, the original's scratch array,
 * is not filled on the wasm path (like `blockUnits`, it is `@private`).
 */

// 120 = sizeof(sha256.State) in src/hash/sha256.zig.
const family = createFamily(wasmBytes, {sha256: 120});

const accel = createAccelerator({
  family,
  name: 'sha256',
  legacy: LegacySha256,
  words: 8,
  // Byte offsets inside the Zig `sha256.State` (src/hash/sha256.zig).
  roundsOff: 32,
  lengthOff: 40,
  bufferedOff: 48,
  bufOff: 56,
  rounds: (options) => roundsIn(options, 64),
  // The original returns `(length / 32) | 0` words; SHA-224 and SHA-256 are the supported sizes.
  outBytes: (options) => options.length === 256 || options.length === 224 ? options.length / 8 : 0,
  facade: () => Sha256
});

/**
 * What the original constructor assigns when an option is missing, in its order
 * (see `explicitOptions` in tools/options.mjs).
 */
const DEFAULTS = {length: 256, rounds: 64};

/**
 * Calculates SHA-224/256 hash
 */
class Sha256 extends LegacySha256 {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    // Explicit, so `Sha256.length === 1` like the original (an implicit one has length 0).
    super(explicitOptions(options, DEFAULTS));
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

export default Sha256;
