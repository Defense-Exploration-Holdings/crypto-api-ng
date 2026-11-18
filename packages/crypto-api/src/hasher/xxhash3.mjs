// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {xxh3 as js, iv} from "../blocks/xxh3.mjs";
import {wasmBytes} from "../../wasm/xxh3.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'xxh3', block: 1024, hashInts: 18, digest: 8, keep: 64}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates the 64-bit [XXH3](https://xxhash.com/) hash (`XXH3_64bits`, Yann Collet): a very fast
 * non-cryptographic hash with a seed, for hash tables, deduplication and checksums. It must not be used where an
 * attacker can choose the input and the hash matters for security. The digest is the canonical representation of
 * the specification, the hash as a big-endian number (`2d06800538d394c2` for the empty message with seed 0). The
 * loop runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>XXH3 of "abc" - ES6 style</caption>
 * import XxHash3 from "crypto-api-ng/src/hasher/xxhash3.mjs";
 *
 * let hasher = new XxHash3();
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 *
 * @example <caption>XXH3 with a seed - ES6 style</caption>
 * import XxHash3 from "crypto-api-ng/src/hasher/xxhash3.mjs";
 *
 * let hasher = new XxHash3({seed: 12345});
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 *
 * @example <caption>XXH3 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('xxhash3', 'message'));
 * </script>
 */
class XxHash3 extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.seed=0] - an integer from 0 to 2^53 - 1
   */
  constructor(options) {
    super(XxHash3.spec, options);
  }
}

XxHash3.spec = {
  name: 'XxHash3', blockBytes: 1024, keep: 64, digestBytes: 8,
  engine: () => engine,
  init: (options) => iv(options.seed),
  specs: {seed: {min: 0, max: Number.MAX_SAFE_INTEGER}},
  normalize: (options, out) => {
    const seed = ownOption(options, 'seed');
    defineOption(out, 'seed', seed === undefined ? 0 : seed);
  }
};

export default XxHash3;
