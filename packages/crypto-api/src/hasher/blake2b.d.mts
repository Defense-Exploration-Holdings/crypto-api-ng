import Hasher from "./hasher.mjs";
import type { Blake2bOptions } from "../../types.js";

export default class Blake2b extends Hasher {
  constructor(options?: Blake2bOptions);
}
