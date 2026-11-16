/**
 * SM3, the 256-bit hash of the Chinese standard GB/T 32905-2016.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Sm3Options } from "../../types.js";

/**
 * SM3 hasher (256-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Sm3();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Sm3 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `rounds`: 1 to 64, default 64. Lowering it weakens the hash; it exists for
   *   compatibility and research.
   */
  constructor(options?: Sm3Options);
}
