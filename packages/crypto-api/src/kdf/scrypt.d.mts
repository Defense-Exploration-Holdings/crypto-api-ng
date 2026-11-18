/**
 * scrypt key derivation (RFC 7914). The cost parameter N is required; there is no safe default.
 *
 * @module
 */

import type { BinaryInput, DigestEncoding, ScryptOptions } from "../../types.js";

/** scrypt (RFC 7914). */
export default class Scrypt {
  /**
   * Creates a scrypt instance for a password.
   *
   * @param password The password: a binary string or bytes.
   * @param options `cost` (N, a power of two) is required; `blockSize` (r, default 8),
   *   `parallelization` (p, default 1), `salt` (default empty) and `length` of the key in bits
   *   (default 256) are optional.
   */
  constructor(password: BinaryInput, options: ScryptOptions);
  /** The derived key as a binary string. Can be called again. */
  finalize(): string;
  /** Like `finalize()`, but returns the key as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the key as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
}
