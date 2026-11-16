/**
 * xxHash32, a fast 32-bit non-cryptographic hash with an optional seed. Do not use it where an
 * attacker can choose the input.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { XxHashOptions } from "../../types.js";

/**
 * xxHash32 hasher (32-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new XxHash32();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class XxHash32 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `seed`: an integer from 0 to 2^32 - 1; default 0.
   */
  constructor(options?: XxHashOptions);
}
