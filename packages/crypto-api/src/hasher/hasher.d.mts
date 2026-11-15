import type { HasherLike, BinaryInput } from "../../types.js";

/** Base class of every hasher. */
export default class Hasher implements HasherLike {
  constructor(options?: Record<string, any>);
  options: Record<string, any>;
  state: Record<string, any>;
  readonly unitSize: number;
  readonly unitOrder: number;
  readonly blockSize: number;
  readonly blockSizeInBytes: number;
  reset(): void;
  update(message: BinaryInput): void;
  finalize(): string;
  getState(): Record<string, any>;
  setState(state: Record<string, any>): void;
}
