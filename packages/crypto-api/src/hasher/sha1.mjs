// crypto-api-ng:facade
'use strict';

import LegacySha1 from "../../legacy/hasher/sha1.mjs";
import family from "../wasm/sha1-family.mjs";
import {createAccelerator, roundsIn} from "../wasm/be32.mjs";
import {checkOptions} from "../tools/input.mjs";

/*
 * SHA-1 with the compression and padding done in wasm, and everything else
 * left to the original JavaScript. Same API, output and `getState()` JSON as
 * crypto-api 0.8.5; see legacy/hasher/sha1.mjs for the original documentation and
 * examples. How this works, and the checks that make it safe: src/wasm/be32.mjs.
 *
 * Wasm is used for options.rounds 1 to 80. Any other option value
 * or state runs the original code. `this.W`, the original's scratch array,
 * is not filled on the wasm path (like `blockUnits`, it is `@private`).
 */

const accel = createAccelerator({
  family,
  name: 'sha1',
  legacy: LegacySha1,
  words: 5,
  // Byte offsets inside the Zig `sha1.State` (src/hash/sha1.zig).
  roundsOff: 20,
  lengthOff: 24,
  bufferedOff: 32,
  bufOff: 40,
  rounds: (options) => roundsIn(options, 80),
  outBytes: () => 20,
  facade: () => Sha1
});

/** Supported `rounds`/`length` values (1.1 rejects the rest). */
const OPTIONS = {rounds: {min: 1, max: 80}};

/**
 * Calculates SHA-1 hash
 */
class Sha1 extends LegacySha1 {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    // Explicit, so `Sha1.length === 1` like the original (an implicit one has length 0).
    checkOptions('Sha1', options, OPTIONS);
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

export default Sha1;
