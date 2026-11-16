/**
 * SHA-0, the original 1993 version of SHA, as a 160-bit hash. It is kept for compatibility with
 * existing data and protocols and is not collision resistant: do not use it for signatures or to check
 * data from an untrusted source.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Sha0Options } from "../../types.js";

/**
 * SHA-0 hasher (160-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Sha0();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Sha0 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `rounds`: 1 to 80, default 80. Lowering it weakens the hash; it exists for
   *   compatibility and research.
   */
  constructor(options?: Sha0Options);
}
