/**
 * Whirlpool, a 512-bit hash, and its earlier versions Whirlpool-0 and Whirlpool-T, selected with the
 * `type` option.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { WhirlpoolOptions } from "../../types.js";

/**
 * Whirlpool hasher (512-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Whirlpool();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Whirlpool extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `type`: `'0'` for Whirlpool-0, `'t'` for Whirlpool-T, anything else for Whirlpool.
   *   `rounds`: 1 to 10, default 10; lowering it weakens the hash.
   */
  constructor(options?: WhirlpoolOptions);
}
