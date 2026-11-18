/**
 * KMAC128 and KMAC256 (NIST SP 800-185), a MAC on cSHAKE, and with `xof: true` KMACXOF128 and KMACXOF256.
 * The permutation runs in WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { KmacOptions } from "../../types.js";

/**
 * Kmac hasher.
 *
 * @example
 * ```ts
 * const hasher = new Kmac({ key: "secret key" });
 * hasher.update("abc");
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Kmac extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `key` (required): a binary string or bytes of any length. `strength`: 128 (the default) or 256.
   *   `length`: MAC size in bits, default twice the strength. `customization`: a binary string or bytes.
   *   `xof`: true for KMACXOF. Throws `TypeError` without a key.
   */
  constructor(options: KmacOptions);
}
