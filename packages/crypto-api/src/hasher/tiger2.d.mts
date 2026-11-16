/**
 * Tiger2, the variant of Tiger with a different padding byte, with a 192-bit digest and shorter ones
 * with the `length` option. Compression runs in WebAssembly, with a plain JavaScript implementation
 * where it is unavailable.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { TigerOptions } from "../../types.js";

/**
 * Tiger2 hasher.
 *
 * @example
 * ```ts
 * const hasher = new Tiger2();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Tiger2 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 8 to 192 in steps of 8; default 192.
   */
  constructor(options?: TigerOptions);
}
