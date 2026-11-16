/**
 * HMAC (RFC 2104) over any hasher of this package, for example `Sha256`, `Md5` or `Blake2b`.
 *
 * @module
 */

import type { BinaryInput, DigestEncoding, HasherLike, HmacLike } from "../../types.js";

/** HMAC over any hasher; the hasher passed in is not modified. */
export default class Hmac implements HmacLike {
  /**
   * Creates a HMAC for a key.
   *
   * @param key The key: a binary string or bytes, of any length.
   * @param hasher The hasher to build the MAC on. It is copied, not modified.
   */
  constructor(key: BinaryInput, hasher: HasherLike);
  /** Adds a binary string or bytes to the message. */
  update(message: BinaryInput): void;
  /** Returns the MAC as a binary string. Can be called again; `update()` continues the message. */
  finalize(): string;
  /** Like `finalize()`, but returns the MAC as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the MAC as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
  /** Restarts with the same key. */
  reset(): void;
}
