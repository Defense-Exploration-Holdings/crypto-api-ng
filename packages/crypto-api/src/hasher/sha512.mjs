// crypto-api-ng:facade
'use strict';

import LegacySha512 from "../../legacy/hasher/sha512.mjs";
import {wasmBytes} from "../../wasm/sha512.mjs";
import {createAccelerator, createFamily, roundsIn} from "../wasm/be32.mjs";

/*
 * SHA-384, SHA-512, SHA-512/224 and SHA-512/256 with the compression and
 * padding done in wasm, and everything else left to the original JavaScript.
 * Same API, output and `getState()` JSON as crypto-api 0.8.5; see
 * legacy/hasher/sha512.mjs for the original documentation and examples. How
 * this works, and the checks that make it safe: src/wasm/be32.mjs.
 *
 * Wasm is used for options.rounds 1 to 160 (half-steps, as in the original) and
 * for finalize() when options.length is an integer from 32 to 512. The hash
 * words come from the state, so any IV works, including the one the original
 * derives for an arbitrary SHA-512/t. Any other option value or state runs the
 * original code. `this.W`, the original's scratch array, is not filled on the
 * wasm path (like `blockUnits`, it is `@private`).
 */

// 216 = sizeof(sha512.State) in src/hash/sha512.zig.
const family = createFamily(wasmBytes, {sha512: 216});

const accel = createAccelerator({
  family,
  name: 'sha512',
  legacy: LegacySha512,
  words: 16,
  block: 128,
  // Byte offsets inside the Zig `sha512.State` (src/hash/sha512.zig).
  roundsOff: 64,
  lengthOff: 72,
  bufferedOff: 80,
  bufOff: 88,
  // The State is larger than the 128-byte state slot, so the digest goes to the input
  // region (256), which `sha512_final` does not read.
  outOff: 256,
  rounds: (options) => roundsIn(options, 160),
  // The original returns `(length / 32) | 0` words of the sixteen it has.
  outBytes: (options) => {
    const length = options.length;
    return Number.isInteger(length) && length >= 32 && length <= 512 ? ((length / 32) | 0) * 4 : 0;
  },
  facade: () => Sha512
});

// Initial hash words of SHA-512/224 and SHA-512/256 (FIPS 180-4), as `reset()` of the
// original makes them (`| 0`: signed int32, like the original's `state.hash`). The
// original derives them with a full SHA-512 of "SHA-512/<length>" on every `reset()`.
const IV_224 = [
  0x8c3d37c8 | 0, 0x19544da2 | 0, 0x73e19966 | 0, 0x89dcd4d6 | 0,
  0x1dfab7ae | 0, 0x32ff9c82 | 0, 0x679dd514 | 0, 0x582f9fcf | 0,
  0x0f6d2b69 | 0, 0x7bd44da8 | 0, 0x77e36f73 | 0, 0x04c48942 | 0,
  0x3f9d85a8 | 0, 0x6a1d36c8 | 0, 0x1112e6ad | 0, 0x91d692a1 | 0
];
const IV_256 = [
  0x22312194 | 0, 0xfc2bf72c | 0, 0x9f555fa3 | 0, 0xc84c64c2 | 0,
  0x2393b86b | 0, 0x6f53b151 | 0, 0x96387719 | 0, 0x5940eabd | 0,
  0x96283ee2 | 0, 0xa88effe3 | 0, 0xbe5e1e25 | 0, 0x53863992 | 0,
  0x2b0199fc | 0, 0x2c85b8aa | 0, 0x0eb72ddc | 0, 0x81c52ca2 | 0
];
// `Hasher32be.prototype.reset`, i.e. what `super.reset()` of the original `reset()` runs.
const baseReset = Object.getPrototypeOf(LegacySha512.prototype).reset;
const ORIGINAL_RESET = LegacySha512.prototype.reset;

/**
 * Calculates SHA-384/512, SHA-512/224 and SHA-512/256 hash
 */
class Sha512 extends LegacySha512 {
  /**
   * @param {Object} [options]
   */
  constructor(options) {
    // Explicit, so `Sha512.length === 1` like the original (an implicit one has length 0).
    super(options);
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    const options = this.options;
    const length = options !== null && typeof options === 'object' ? options.length : 0;
    if ((length === 224 || length === 256) && LegacySha512.prototype.reset === ORIGINAL_RESET) {
      // Same state the original builds, without hashing "SHA-512/<length>" to find the IV.
      baseReset.call(this);
      this.state.hash = (length === 224 ? IV_224 : IV_256).slice();
    } else {
      super.reset();
    }
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

export default Sha512;
