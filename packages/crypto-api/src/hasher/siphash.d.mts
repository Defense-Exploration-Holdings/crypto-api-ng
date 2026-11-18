/**
 * SipHash-2-4, a keyed 64-bit hash for hash tables that face untrusted input. The key is required.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { SipHashOptions } from "../../types.js";

/**
 * SipHash-2-4 hasher (64-bit digest, least significant byte first).
 *
 * @example
 * ```ts
 * const hasher = new SipHash({ key: hexToBytes("000102030405060708090a0b0c0d0e0f") });
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class SipHash extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `key`: exactly 16 bytes, required; should be random and secret.
   */
  constructor(options: SipHashOptions);
}
