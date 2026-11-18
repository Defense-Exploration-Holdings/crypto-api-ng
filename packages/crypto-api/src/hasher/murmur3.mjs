// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {murmur3_32 as js, iv32} from "../blocks/murmur3.mjs";
import {wasmBytes} from "../../wasm/murmur3.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'murmur3_32', block: 4, hashInts: 1, digest: 4, stateSize: 16}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates [MurmurHash3](https://github.com/aappleby/smhasher) x86_32 (Austin Appleby): a fast
 * non-cryptographic 32-bit hash with a seed, for hash tables, Bloom filters and sharding. It must not be used where
 * an attacker can choose the input and the hash matters for security. The digest is the 32-bit result as a
 * big-endian number, so its hex form is the number other libraries print (`514e28b7` for the empty message with
 * seed 1). The loop runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>MurmurHash3 of "abc" - ES6 style</caption>
 * import Murmur3 from "crypto-api-ng/src/hasher/murmur3.mjs";
 *
 * let hasher = new Murmur3({seed: 42});
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 *
 * @example <caption>MurmurHash3 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('murmur3', 'message'));
 * </script>
 */
class Murmur3 extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.seed=0] - an integer from 0 to 2^32 - 1
   */
  constructor(options) {
    super(Murmur3.spec, options);
  }
}

Murmur3.spec = {
  name: 'Murmur3', blockBytes: 4, digestBytes: 4,
  engine: () => engine,
  init: (options) => iv32(options.seed),
  specs: {seed: {min: 0, max: 4294967295}},
  normalize: (options, out) => {
    const seed = ownOption(options, 'seed');
    defineOption(out, 'seed', seed === undefined ? 0 : seed);
  }
};

export default Murmur3;
