import type { BinaryInput, DigestEncoding, HasherLike, Pbkdf2Options } from "../../types.js";

/** PBKDF2 (RFC 8018) over HMAC with any hasher. */
export default class Pbkdf2 {
  constructor(password: BinaryInput, hasher: HasherLike, options: Pbkdf2Options);
  /** The derived key as a binary string. Can be called again. */
  finalize(): string;
  /** Like `finalize()`, but returns the key as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the key as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
}
