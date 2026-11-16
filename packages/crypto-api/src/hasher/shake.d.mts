/**
 * SHAKE128 and SHAKE256 (FIPS 202), extendable-output functions with any output length that is a
 * multiple of 8 bits. The permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { ShakeOptions } from "../../types.js";

/**
 * SHAKE hasher.
 *
 * @example
 * ```ts
 * const hasher = new Shake();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Shake extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `strength`: 128 (SHAKE128, the default) or 256 (SHAKE256). `length`: output size in
   *   bits, a multiple of 8 from 8 to 2^30; default 256 for SHAKE128 and 512 for SHAKE256.
   */
  constructor(options?: ShakeOptions);
}
