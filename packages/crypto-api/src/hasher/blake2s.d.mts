import Hasher from "./hasher.mjs";
import type { Blake2sOptions } from "../../types.js";

export default class Blake2s extends Hasher {
  constructor(options?: Blake2sOptions);
}
