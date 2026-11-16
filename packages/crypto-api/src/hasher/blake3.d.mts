/**
 * BLAKE3 with 256-bit output by default, any output length up to 1 MiB, keyed hashing and key
 * derivation. Compression runs in WebAssembly, with a plain JavaScript implementation where it is
 * unavailable.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Blake3Options } from "../../types.js";

/**
 * BLAKE3 hasher.
 *
 * @example
 * ```ts
 * const hasher = new Blake3();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Blake3 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: output size in bits, 8 to 8388608 in steps of 8; default 256. `key`:
   *   exactly 32 bytes, for keyed hashing. `context`: the context string of key derivation. `key` and
   *   `context` exclude each other.
   */
  constructor(options?: Blake3Options);
}
