/**
 * Keccak-224, Keccak-256, Keccak-384 and Keccak-512 with the original Keccak padding, as used by
 * Ethereum. This is not SHA-3: the padding differs, so the digests differ. The permutation runs in
 * WebAssembly, with a JavaScript fallback.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { KeccakOptions } from "../../types.js";

/**
 * Keccak hasher with the original Keccak padding.
 *
 * @example
 * ```ts
 * const hasher = new Keccak();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Keccak extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `length`: digest size in bits, 224, 256, 384 or 512; default 512.
   */
  constructor(options?: KeccakOptions);
}
