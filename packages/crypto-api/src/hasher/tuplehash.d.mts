/**
 * TupleHash128 and TupleHash256 (NIST SP 800-185), a hash of a sequence of strings: every `update()` call
 * adds one element. With `xof: true`, TupleHashXOF. The permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { TupleHashOptions } from "../../types.js";

/**
 * TupleHash hasher.
 *
 * @example
 * ```ts
 * const hasher = new TupleHash();
 * hasher.update("alice"); // one element
 * hasher.update("bob"); // another
 * const digest = hasher.digest("hex");
 * ```
 */
export default class TupleHash extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `strength`: 128 (the default) or 256. `length`: output size in bits, default twice the strength.
   *   `customization`: a binary string or bytes. `xof`: true for TupleHashXOF.
   */
  constructor(options?: TupleHashOptions);
}
