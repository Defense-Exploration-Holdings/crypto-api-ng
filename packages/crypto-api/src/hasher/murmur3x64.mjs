// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {murmur3_128 as js, iv128} from "../blocks/murmur3.mjs";
import {wasmBytes} from "../../wasm/murmur3.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'murmur3_128', block: 16, hashInts: 4, digest: 16}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates [MurmurHash3](https://github.com/aappleby/smhasher) x64_128 (Austin Appleby): a fast
 * non-cryptographic 128-bit hash with a 32-bit seed, for hash tables, Bloom filters and sharding. It must not be
 * used where an attacker can choose the input and the hash matters for security. The digest is the 16 bytes the
 * reference implementation writes (h1 then h2, each least significant byte first), the bytes `mmh3.hash_bytes` of
 * Python and `Hashing.murmur3_128` of Guava return. The x86_128 variant gives different values and is not
 * provided. The loop runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>MurmurHash3 x64_128 of "abc" - ES6 style</caption>
 * import Murmur3x64 from "crypto-api-ng/src/hasher/murmur3x64.mjs";
 *
 * let hasher = new Murmur3x64({seed: 42});
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 *
 * @example <caption>MurmurHash3 x64_128 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('murmur3-x64-128', 'message'));
 * </script>
 */
class Murmur3x64 extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.seed=0] - an integer from 0 to 2^32 - 1
   */
  constructor(options) {
    super(Murmur3x64.spec, options);
  }
}

Murmur3x64.spec = {
  name: 'Murmur3x64', blockBytes: 16, digestBytes: 16,
  engine: () => engine,
  init: (options) => iv128(options.seed),
  specs: {seed: {min: 0, max: 4294967295}},
  normalize: (options, out) => {
    const seed = ownOption(options, 'seed');
    defineOption(out, 'seed', seed === undefined ? 0 : seed);
  }
};

export default Murmur3x64;
