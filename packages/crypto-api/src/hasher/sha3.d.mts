/**
 * SHA3-224, SHA3-256, SHA3-384 and SHA3-512 (FIPS 202), selected with the `length` option. The
 * permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Sha3Options } from "../../types.js";

/**
 * SHA-3 hasher.
 *
 * @example
 * ```ts
 * const hasher = new Sha3();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Sha3 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 224, 256, 384 or 512; default 512.
   */
  constructor(options?: Sha3Options);
}
