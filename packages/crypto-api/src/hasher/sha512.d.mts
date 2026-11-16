/**
 * SHA-384, SHA-512 and the truncated SHA-512/t family including SHA-512/224 and SHA-512/256 (FIPS
 * 180-4), selected with the `length` option.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Sha512Options } from "../../types.js";

/**
 * SHA-512 hasher; `length` 384 gives SHA-384, 224 and 256 give SHA-512/224 and SHA-512/256.
 *
 * @example
 * ```ts
 * const hasher = new Sha512();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Sha512 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 32 to 512 in steps of 32; default 512. 384 is SHA-384,
   *   512 is SHA-512 and any other value is SHA-512/t. `rounds`: 1 to 160, default 160; lowering it
   *   weakens the hash and exists for compatibility and research.
   */
  constructor(options?: Sha512Options);
}
