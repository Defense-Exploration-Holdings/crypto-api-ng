import Hasher from "./hasher.mjs";
import type { Blake3Options } from "../../types.js";

export default class Blake3 extends Hasher {
  constructor(options?: Blake3Options);
}
