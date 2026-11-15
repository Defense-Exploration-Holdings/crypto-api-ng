import Hasher from "./hasher.mjs";
import type { Sha512Options } from "../../types.js";

export default class Sha512 extends Hasher {
  constructor(options?: Sha512Options);
}
