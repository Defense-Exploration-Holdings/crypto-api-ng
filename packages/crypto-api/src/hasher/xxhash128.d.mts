/**
 * XXH3-128 (XXH128), a fast non-cryptographic 128-bit hash with an optional seed. Do not use it
 * where an attacker can choose the input.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { XxHashOptions } from "../../types.js";

/**
 * XXH128 hasher (128-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new XxHash128();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class XxHash128 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `seed`: an integer from 0 to 2^53 - 1; default 0.
   */
  constructor(options?: XxHashOptions);
}
