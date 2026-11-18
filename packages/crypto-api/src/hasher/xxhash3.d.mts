/**
 * XXH3 (64-bit), a fast non-cryptographic hash with an optional seed. Do not use it where an
 * attacker can choose the input.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { XxHashOptions } from "../../types.js";

/**
 * XXH3 hasher (64-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new XxHash3();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class XxHash3 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `seed`: an integer from 0 to 2^53 - 1; default 0.
   */
  constructor(options?: XxHashOptions);
}
