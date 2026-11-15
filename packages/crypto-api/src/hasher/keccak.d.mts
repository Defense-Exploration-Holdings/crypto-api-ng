import Hasher from "./hasher.mjs";
import type { KeccakOptions } from "../../types.js";

export default class Keccak extends Hasher {
  constructor(options?: KeccakOptions);
}
