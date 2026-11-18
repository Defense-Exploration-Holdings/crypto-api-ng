/**
 * MurmurHash3 x64_128, a fast non-cryptographic 128-bit hash with an optional seed. Do not use it
 * where an attacker can choose the input.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Murmur3Options } from "../../types.js";

/**
 * MurmurHash3 x64_128 hasher (128-bit digest in the byte order of the reference implementation).
 *
 * @example
 * ```ts
 * const hasher = new Murmur3x64();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Murmur3x64 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `seed`: an integer from 0 to 2^32 - 1; default 0.
   */
  constructor(options?: Murmur3Options);
}
