/**
 * TurboSHAKE128 and TurboSHAKE256 (RFC 9861): SHAKE with 12 rounds and a domain separation byte. The
 * permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { TurboShakeOptions } from "../../types.js";

/**
 * TurboShake hasher.
 *
 * @example
 * ```ts
 * const hasher = new TurboShake();
 * hasher.update("abc");
 * const digest = hasher.digest("hex");
 * ```
 */
export default class TurboShake extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `strength`: 128 (the default) or 256. `length`: output size in bits, default twice the strength.
   *   `domain`: 0x01 to 0x7f, default 0x1f.
   */
  constructor(options?: TurboShakeOptions);
}
