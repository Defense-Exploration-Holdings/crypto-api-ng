/**
 * MurmurHash3 x86_32, a fast non-cryptographic 32-bit hash with an optional seed. Do not use it
 * where an attacker can choose the input.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Murmur3Options } from "../../types.js";

/**
 * MurmurHash3 x86_32 hasher (32-bit digest, most significant byte first).
 *
 * @example
 * ```ts
 * const hasher = new Murmur3();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Murmur3 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `seed`: an integer from 0 to 2^32 - 1; default 0.
   */
  constructor(options?: Murmur3Options);
}
