/**
 * KangarooTwelve, KT128 and KT256 (RFC 9861): a fast tree hash on TurboSHAKE, output of any length. The
 * permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { KangarooTwelveOptions } from "../../types.js";

/**
 * KangarooTwelve hasher.
 *
 * @example
 * ```ts
 * const hasher = new KangarooTwelve();
 * hasher.update("abc");
 * const digest = hasher.digest("hex");
 * ```
 */
export default class KangarooTwelve extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `strength`: 128 (KT128, the default) or 256 (KT256). `length`: output size in bits, default twice
   *   the strength. `customization`: a binary string or bytes.
   */
  constructor(options?: KangarooTwelveOptions);
}
