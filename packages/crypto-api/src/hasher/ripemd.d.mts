/**
 * RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320, selected with the `length` option. RIPEMD-128 is
 * not collision resistant; RIPEMD-160 is the variant in common use.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { RipemdOptions } from "../../types.js";

/**
 * RIPEMD hasher: 128, 160, 256 or 320 bits.
 *
 * @example
 * ```ts
 * const hasher = new Ripemd();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Ripemd extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 128, 160, 256 or 320; default 160.
   */
  constructor(options?: RipemdOptions);
}
