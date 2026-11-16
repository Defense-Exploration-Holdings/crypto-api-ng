/**
 * HKDF (RFC 5869) over HMAC with any hasher of this package.
 *
 * @module
 */

import type { BinaryInput, DigestEncoding, HasherLike, HkdfOptions } from "../../types.js";

/** HKDF (RFC 5869) over HMAC with any hasher. */
export default class Hkdf {
  /**
   * Creates a HKDF instance for input keying material.
   *
   * @param ikm The input keying material: a binary string or bytes.
   * @param hasher The hasher the HMAC is built on.
   * @param options `salt` (default empty), `info` and `length` of the output of `finalize()` in bits (a
   *   multiple of 8, up to 255 times the digest size; default the digest size).
   */
  constructor(ikm: BinaryInput, hasher: HasherLike, options?: HkdfOptions);
  /** The pseudorandom key of the extract step, as a binary string. */
  extract(): string;
  /** HKDF-Expand with the given context; `length` is in bits. */
  expand(info?: BinaryInput, length?: number): string;
  /** Like `expand()`, but returns the key as bytes. */
  expandBytes(info?: BinaryInput, length?: number): Uint8Array;
  /** HKDF-Expand with the `info` and `length` options. Can be called again. */
  finalize(): string;
  /** Like `finalize()`, but returns the key as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the key as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
}
