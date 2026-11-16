// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {tiger2 as js, IV} from "../blocks/tiger.mjs";
import {wasmBytes} from "../../wasm/tiger.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'tiger2', block: 64, hashInts: 6, digest: 24}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates Tiger2 hash: [Tiger](./tiger.mjs) with the padding byte 0x80 instead of 0x01 (Anderson
 * and Biham's own variant, which makes the padding match MD4, MD5 and SHA). Same blocks, same
 * 192-bit digest, same word order (`4441be75...` for the empty message), same shorter digests.
 * The compression runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>Tiger2 of "abc" - ES6 style</caption>
 * import Tiger2 from "crypto-api-ng/src/hasher/tiger2.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Tiger2();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Tiger2 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('tiger2', 'message'));
 * </script>
 */
class Tiger2 extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=192] - digest size in bits: 8 to 192 in steps of 8
   */
  constructor(options) {
    super(Tiger2.spec, options);
  }
}

Tiger2.spec = {
  name: 'Tiger2', blockBytes: 64, digestBytes: 24,
  engine: () => engine,
  init: () => IV.slice(),
  specs: {length: {min: 8, max: 192, step: 8}},
  normalize: (options, out) => {
    const length = ownOption(options, 'length');
    defineOption(out, 'length', length === undefined ? 192 : length);
  },
  output: (digest, options) => digest.substr(0, options.length / 8)
};

export default Tiger2;
