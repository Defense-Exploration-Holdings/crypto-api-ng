import type { BinaryInput, DigestEncoding, HasherLike, HkdfOptions } from "../../types.js";

/** HKDF (RFC 5869) over HMAC with any hasher. */
export default class Hkdf {
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
