/**
 * Snefru, Ralph Merkle's hash with 128-bit digests by default and 32 to 448 bits with the `length`
 * option. It is kept for compatibility with existing data and protocols and is not collision
 * resistant: do not use it for signatures or to check data from an untrusted source.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { SnefruOptions } from "../../types.js";

/**
 * Snefru hasher.
 *
 * @example
 * ```ts
 * const hasher = new Snefru();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Snefru extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 32 to 448 in steps of 32; default 128. `rounds`: 1 to
   *   8, default 8; lowering it weakens the hash.
   */
  constructor(options?: SnefruOptions);
}
