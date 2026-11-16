/**
 * HAS-160, a 160-bit hash from the Korean digital signature standards. It is kept for compatibility
 * with existing data and protocols and is not collision resistant: do not use it for signatures or to
 * check data from an untrusted source.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Has160Options } from "../../types.js";

/**
 * HAS-160 hasher (160-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Has160();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Has160 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `rounds`: 1 to 80, default 80. Lowering it weakens the hash; it exists for
   *   compatibility and research.
   */
  constructor(options?: Has160Options);
}
