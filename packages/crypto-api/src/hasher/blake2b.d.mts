/**
 * BLAKE2b (RFC 7693) with digests of 8 to 512 bits, an optional key, salt and personalization string.
 * Compression runs in WebAssembly, with a plain JavaScript implementation where it is unavailable.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Blake2bOptions } from "../../types.js";

/**
 * BLAKE2b hasher.
 *
 * @example
 * ```ts
 * const hasher = new Blake2b();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Blake2b extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 8 to 512 in steps of 8; default 512. `key`: up to 64
   *   bytes, makes the hash a MAC. `salt` and `personalization`: up to 16 bytes each, zero padded.
   */
  constructor(options?: Blake2bOptions);
}
