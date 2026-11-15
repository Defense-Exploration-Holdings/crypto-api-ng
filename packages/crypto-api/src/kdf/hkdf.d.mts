import type { BinaryInput, HasherLike, HkdfOptions } from "../../types.js";

/** HKDF (RFC 5869) over HMAC with any hasher. */
export default class Hkdf {
  constructor(ikm: BinaryInput, hasher: HasherLike, options?: HkdfOptions);
  /** The pseudorandom key of the extract step, as a binary string. */
  extract(): string;
  /** HKDF-Expand with the given context; `length` is in bits. */
  expand(info?: BinaryInput, length?: number): string;
  /** HKDF-Expand with the `info` and `length` options. Can be called again. */
  finalize(): string;
}
