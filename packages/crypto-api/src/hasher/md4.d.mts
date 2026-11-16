/**
 * MD4 (RFC 1320), a 128-bit hash. It is kept for compatibility with existing data and protocols and is
 * not collision resistant: do not use it for signatures or to check data from an untrusted source.
 *
 * @module
 */

import Hasher from "./hasher.mjs";

/**
 * MD4 hasher (128-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Md4();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Md4 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options This algorithm has no options.
   */
  constructor(options?: Record<string, never>);
}
