/**
 * ParallelHash128 and ParallelHash256 (NIST SP 800-185): the message is hashed in blocks of `blockSize` bytes.
 * With `xof: true`, ParallelHashXOF. The permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { ParallelHashOptions } from "../../types.js";

/**
 * ParallelHash hasher.
 *
 * @example
 * ```ts
 * const hasher = new ParallelHash({ blockSize: 8192 });
 * hasher.update("abc");
 * const digest = hasher.digest("hex");
 * ```
 */
export default class ParallelHash extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `strength`: 128 (the default) or 256. `length`: output size in bits, default twice the strength.
   *   `blockSize`: bytes per block, default 8192. `customization`: a binary string or bytes. `xof`: true for
   *   ParallelHashXOF.
   */
  constructor(options?: ParallelHashOptions);
}
