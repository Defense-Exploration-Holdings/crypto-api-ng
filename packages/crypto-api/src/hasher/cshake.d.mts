/**
 * cSHAKE128 and cSHAKE256 (NIST SP 800-185): SHAKE with a function name and a customization string. With
 * both empty it is SHAKE. The permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { CShakeOptions } from "../../types.js";

/**
 * CShake hasher.
 *
 * @example
 * ```ts
 * const hasher = new CShake({ customization: "Email Signature" });
 * hasher.update("abc");
 * const digest = hasher.digest("hex");
 * ```
 */
export default class CShake extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `strength`: 128 (the default) or 256. `length`: output size in bits, a multiple of 8 from 8 to
   *   2^30; default twice the strength. `customization` and `functionName`: binary strings or bytes.
   */
  constructor(options?: CShakeOptions);
}
