import type { BinaryInput, DigestEncoding, HasherLike, HmacLike } from "../../types.js";

/** HMAC over any hasher; the hasher passed in is not modified. */
export default class Hmac implements HmacLike {
  constructor(key: BinaryInput, hasher: HasherLike);
  update(message: BinaryInput): void;
  finalize(): string;
  /** Like `finalize()`, but returns the MAC as bytes. */
  digest(): Uint8Array;
  /** Like `finalize()`, but returns the MAC as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
  reset(): void;
}
