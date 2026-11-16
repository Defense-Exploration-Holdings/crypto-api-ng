/**
 * CRC-32 (IEEE 802.3), a 32-bit checksum. It detects accidental changes only and is not a
 * cryptographic hash.
 *
 * @module
 */

import Hasher from "./hasher.mjs";

/**
 * CRC-32 checksum (32-bit).
 *
 * @example
 * ```ts
 * const hasher = new Crc32();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Crc32 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options This algorithm has no options.
   */
  constructor(options?: object);
}
