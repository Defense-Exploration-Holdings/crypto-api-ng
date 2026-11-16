/**
 * Streebog, the GOST R 34.11-2012 hash (RFC 6986) with 256-bit or 512-bit digests. Compression runs in
 * WebAssembly, with a plain JavaScript implementation where it is unavailable.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { StreebogOptions } from "../../types.js";

/**
 * Streebog hasher.
 *
 * @example
 * ```ts
 * const hasher = new Streebog();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Streebog extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 256 or 512; default 512.
   */
  constructor(options?: StreebogOptions);
}
