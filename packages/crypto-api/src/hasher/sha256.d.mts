import Hasher from "./hasher.mjs";
import type { Sha256Options } from "../../types.js";

export default class Sha256 extends Hasher {
  constructor(options?: Sha256Options);
}
