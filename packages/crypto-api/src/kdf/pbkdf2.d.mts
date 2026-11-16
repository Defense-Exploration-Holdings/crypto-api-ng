/**
 * PBKDF2 (RFC 8018) over HMAC with any hasher of this package. The number of iterations is required;
 * there is no safe default.
 *
 * @module
 */

import type { BinaryInput, DigestEncoding, HasherLike, Pbkdf2Options } from "../../types.js";

/** PBKDF2 (RFC 8018) over HMAC with any hasher. */
export default class Pbkdf2 {
  /**
   * Creates a PBKDF2 instance for a password.
   *
   * @param password The password: a binary string or bytes.
   * @param hasher The hasher the HMAC is built on.
   * @param options `iterations` (required, 1 to 4294967295), `salt` (default empty) and `length` of the
   *   derived key in bits (a multiple of 8; default the digest size of the hasher).
   */
  constructor(password: BinaryInput, hasher: HasherLike, options: Pbkdf2Options);
  /** The derived key as a binary string. Can be called again. */
  finalize(): string;
  /** Like `finalize()`, but returns the key as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the key as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
}
