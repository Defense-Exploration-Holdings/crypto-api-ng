// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {xxh128 as js, iv} from "../blocks/xxh3.mjs";
import {wasmBytes} from "../../wasm/xxh3.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'xxh128', block: 1024, hashInts: 18, digest: 16, keep: 64}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates the 128-bit [XXH3](https://xxhash.com/) hash (`XXH3_128bits`, also called XXH128, Yann Collet): a very
 * fast non-cryptographic hash with a seed, for deduplication, checksums and content addressing where 64 bits give
 * too many collisions. It must not be used where an attacker can choose the input and the hash matters for
 * security. The digest is the canonical representation of the specification, the hash as a big-endian number
 * (`99aa06d3014798d86001c324468d497f` for the empty message with seed 0). The loop runs in WebAssembly, or in
 * plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>XXH128 of "abc" - ES6 style</caption>
 * import XxHash128 from "crypto-api-ng/src/hasher/xxhash128.mjs";
 *
 * let hasher = new XxHash128();
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 *
 * @example <caption>XXH128 with a seed - ES6 style</caption>
 * import XxHash128 from "crypto-api-ng/src/hasher/xxhash128.mjs";
 *
 * let hasher = new XxHash128({seed: 12345});
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 *
 * @example <caption>XXH128 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('xxhash128', 'message'));
 * </script>
 */
class XxHash128 extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.seed=0] - an integer from 0 to 2^53 - 1
   */
  constructor(options) {
    super(XxHash128.spec, options);
  }
}

XxHash128.spec = {
  name: 'XxHash128', blockBytes: 1024, keep: 64, digestBytes: 16,
  engine: () => engine,
  init: (options) => iv(options.seed),
  specs: {seed: {min: 0, max: Number.MAX_SAFE_INTEGER}},
  normalize: (options, out) => {
    const seed = ownOption(options, 'seed');
    defineOption(out, 'seed', seed === undefined ? 0 : seed);
  }
};

export default XxHash128;
