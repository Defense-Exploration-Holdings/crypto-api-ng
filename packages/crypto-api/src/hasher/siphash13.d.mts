/**
 * SipHash-1-3, the faster SipHash variant used by Rust and Python hash tables. The key is required.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { SipHashOptions } from "../../types.js";

/**
 * SipHash-1-3 hasher (64-bit digest, least significant byte first).
 *
 * @example
 * ```ts
 * const hasher = new SipHash13({ key: hexToBytes("000102030405060708090a0b0c0d0e0f") });
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class SipHash13 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `key`: exactly 16 bytes, required; should be random and secret.
   */
  constructor(options: SipHashOptions);
}
