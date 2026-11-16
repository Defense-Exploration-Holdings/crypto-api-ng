// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {xxhash32 as js, iv32} from "../blocks/xxhash.mjs";
import {wasmBytes} from "../../wasm/xxhash.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'xxhash32', block: 16, hashInts: 5, digest: 4, stateSize: 32}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates the [XXH32](https://xxhash.com/) hash (Yann Collet): a very fast non-cryptographic 32-bit hash with a
 * seed, for hash tables, deduplication and checksums. It must not be used where an attacker can choose the
 * input and the hash matters for security. The digest is the canonical representation of the specification, the
 * hash as a big-endian number, so its hex form is the number everyone prints (`02cc5d05` for the empty
 * message with seed 0). The loop runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>XXH32 of "abc" - ES6 style</caption>
 * import XxHash32 from "crypto-api-ng/src/hasher/xxhash32.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new XxHash32();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>XXH32 with a seed - ES6 style</caption>
 * import XxHash32 from "crypto-api-ng/src/hasher/xxhash32.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new XxHash32({seed: 12345});
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>XXH32 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('xxhash32', 'message'));
 * </script>
 */
class XxHash32 extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.seed=0] - an integer from 0 to 4294967295
   */
  constructor(options) {
    super(XxHash32.spec, options);
  }
}

XxHash32.spec = {
  name: 'XxHash32', blockBytes: 16, digestBytes: 4,
  engine: () => engine,
  init: (options) => iv32(options.seed),
  specs: {seed: {min: 0, max: 4294967295}},
  normalize: (options, out) => {
    const seed = ownOption(options, 'seed');
    defineOption(out, 'seed', seed === undefined ? 0 : seed);
  }
};

export default XxHash32;
