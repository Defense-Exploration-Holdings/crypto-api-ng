/**
 * MD2 (RFC 1319), a 128-bit hash. It is kept for compatibility with existing data and protocols and is
 * not collision resistant: do not use it for signatures or to check data from an untrusted source.
 *
 * @module
 */

import Hasher from "./hasher.mjs";
import type { Md2Options } from "../../types.js";

/**
 * MD2 hasher (128-bit digest).
 *
 * @example
 * ```ts
 * const hasher = new Md2();
 * hasher.update("abc"); // a binary string or bytes; convert text with fromUtf()
 * const digest = hasher.digest("hex");
 * ```
 */
export default class Md2 extends Hasher {
  /**
   * Creates a hasher.
   *
   * @param options `rounds`: 1 to 255, default 18. Lowering it weakens the hash; it exists for
   *   compatibility and research.
   */
  constructor(options?: Md2Options);
}
