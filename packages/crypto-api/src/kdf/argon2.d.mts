/**
 * Argon2id, Argon2i and Argon2d password hashing (RFC 9106, version 0x13). The salt, the number of
 * iterations and the memory size are required; there are no safe defaults.
 *
 * @module
 */

import type { Argon2Options, BinaryInput, DigestEncoding } from "../../types.js";

/** Argon2 (RFC 9106): Argon2id by default, or Argon2i or Argon2d. */
export default class Argon2 {
  /**
   * Creates an Argon2 instance for a password.
   *
   * @param password The password: a binary string or bytes.
   * @param options `salt` (8 bytes or more), `iterations` and `memory` in KiB are required;
   *   `parallelism` (default 1), `type` (default `'argon2id'`), `length` of the tag in bits
   *   (default 256), `secret` and `associatedData` are optional.
   */
  constructor(password: BinaryInput, options: Argon2Options);
  /** The tag as a binary string. Can be called again. */
  finalize(): string;
  /** Like `finalize()`, but returns the tag as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the tag as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
}
