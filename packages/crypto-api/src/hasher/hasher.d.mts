import type { HasherLike, BinaryInput, DigestEncoding } from "../../types.js";

/**
 * Base class of every hasher. Feed it with `update()`, then read the digest with `digest()` or
 * `finalize()`.
 */
export default class Hasher implements HasherLike {
  /** @param options Options of the algorithm; each hasher documents the ones it reads. */
  constructor(options?: Record<string, any>);
  /** The options the hasher was created with. */
  options: Record<string, any>;
  /** Everything that changes while a message is processed. See `getState()`. */
  state: Record<string, any>;
  /** Size of a unit in bytes (4 means 32-bit words). */
  readonly unitSize: number;
  /** Byte order within a unit: 0 normal, 1 reversed. */
  readonly unitOrder: number;
  /** Size of a block in units. */
  readonly blockSize: number;
  /** Size of a block in bytes. */
  readonly blockSizeInBytes: number;
  /** Back to the initial state, keeping the options. */
  reset(): void;
  /**
   * Adds to the message.
   *
   * @param message A binary string (every character in `\x00`-`\xFF`; convert text with
   *   `fromUtf()`), or bytes. Throws `TypeError` for anything else.
   */
  update(message: BinaryInput): void;
  /** Finishes the message and returns the digest as a binary string. */
  finalize(): string;
  /** Finalizes like `finalize()` and returns the digest as bytes. */
  digest(): Uint8Array;
  /** Finalizes like `finalize()` and returns the digest as text in the given encoding. */
  digest(encoding: DigestEncoding): string;
  /** A JSON-serializable snapshot of the hasher. */
  getState(): Record<string, any>;
  /** Restores a snapshot made by `getState()` of a hasher with the same class and options. */
  setState(state: Record<string, any>): void;
}
