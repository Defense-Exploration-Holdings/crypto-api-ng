/**
 * SHA-1 (FIPS 180-4), a 160-bit hash. It is kept for compatibility with existing data and protocols
 * and is not collision resistant: do not use it for signatures or to check data from an untrusted
 * source.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Sha1Options } from "../../types.js";

/**
 * SHA-1 hasher (160-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Sha1();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Sha1 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `rounds`: 1 to 80, default 80. Lowering it weakens the hash; it exists for
   *   compatibility and research.
   */
  constructor(options?: Sha1Options);
}
