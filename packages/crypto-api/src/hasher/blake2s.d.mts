/**
 * BLAKE2s (RFC 7693) with digests of 8 to 256 bits, an optional key, salt and personalization string.
 * Compression runs in WebAssembly, with a plain JavaScript implementation where it is unavailable.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Blake2sOptions } from "../../types.js";

/**
 * BLAKE2s hasher.
 *
 * @example
 * ```ts
 * const hasher = new Blake2s();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Blake2s extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 8 to 256 in steps of 8; default 256. `key`: up to 32
   *   bytes, makes the hash a MAC. `salt` and `personalization`: up to 8 bytes each, zero padded.
   */
  constructor(options?: Blake2sOptions);
}
