/**
 * SHA-224 and SHA-256 (FIPS 180-4), selected with the `length` option.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Sha256Options } from "../../types.js";

/**
 * SHA-256 hasher; `length` 224 gives SHA-224.
 *
 * @example
 * ```ts
 * const hasher = new Sha256();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Sha256 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 224 or 256; default 256. `rounds`: 1 to 64, default
   *   64; lowering it weakens the hash and exists for compatibility and research.
   */
  constructor(options?: Sha256Options);
}
