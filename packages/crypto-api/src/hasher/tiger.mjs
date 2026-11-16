// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {tiger as js, IV} from "../blocks/tiger.mjs";
import {wasmBytes} from "../../wasm/tiger.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'tiger', block: 64, hashInts: 6, digest: 24}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates [Tiger](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) hash (Anderson and Biham, 1995):
 * 64-byte blocks, three passes, 192-bit digest. The digest is the three 64-bit words in
 * little-endian byte order (`3293ac63...` for the empty message), the order every implementation
 * of the reference code prints. Shorter digests (Tiger/160, Tiger/128) are the first bytes of it.
 * The compression runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>Tiger of "abc" - ES6 style</caption>
 * import Tiger from "crypto-api-ng/src/hasher/tiger.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Tiger();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Tiger/128 of "abc" - ES6 style</caption>
 * import Tiger from "crypto-api-ng/src/hasher/tiger.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Tiger({length: 128});
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Tiger of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('tiger', 'message'));
 * </script>
 */
class Tiger extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=192] - digest size in bits: 8 to 192 in steps of 8
   */
  constructor(options) {
    super(Tiger.spec, options);
  }
}

Tiger.spec = {
  name: 'Tiger', blockBytes: 64, digestBytes: 24,
  engine: () => engine,
  init: () => IV.slice(),
  specs: {length: {min: 8, max: 192, step: 8}},
  normalize: (options, out) => {
    const length = ownOption(options, 'length');
    defineOption(out, 'length', length === undefined ? 192 : length);
  },
  output: (digest, options) => digest.substr(0, options.length / 8)
};

export default Tiger;
