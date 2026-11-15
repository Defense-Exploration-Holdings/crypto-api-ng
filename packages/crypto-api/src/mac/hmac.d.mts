import type { BinaryInput, HasherLike, HmacLike } from "../../types.js";

/** HMAC over any hasher; the hasher passed in is not modified. */
export default class Hmac implements HmacLike {
  constructor(key: BinaryInput, hasher: HasherLike);
  update(message: BinaryInput): void;
  finalize(): string;
  reset(): void;
}
