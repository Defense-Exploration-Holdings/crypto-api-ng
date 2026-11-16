import type { BinaryInput, HasherLike, Pbkdf2Options } from "../../types.js";

/** PBKDF2 (RFC 8018) over HMAC with any hasher. */
export default class Pbkdf2 {
  constructor(password: BinaryInput, hasher: HasherLike, options: Pbkdf2Options);
  /** The derived key as a binary string. Can be called again. */
  finalize(): string;
}
