/**
 * MD5 (RFC 1321), a 128-bit hash. It is kept for compatibility with existing data and protocols and is
 * not collision resistant: do not use it for signatures or to check data from an untrusted source.
 *
 * @module
 */

import Hasher from "./hasher.mjs";

/**
 * MD5 hasher (128-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Md5();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Md5 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options This algorithm has no options.
   */
  constructor(options?: Record<string, never>);
}
