// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {xxhash64 as js, iv64} from "../blocks/xxhash.mjs";
import {wasmBytes} from "../../wasm/xxhash.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, {prefix: 'xxhash64', block: 32, hashInts: 10, digest: 8, stateSize: 48}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates the [XXH64](https://xxhash.com/) hash (Yann Collet): a very fast non-cryptographic 64-bit hash with a
 * seed, for hash tables, deduplication and checksums. It must not be used where an attacker can choose the
 * input and the hash matters for security. The digest is the canonical representation of the specification, the
 * hash as a big-endian number, so its hex form is the number everyone prints (`ef46db3751d8e999` for the empty
 * message with seed 0). The loop runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>XXH64 of "abc" - ES6 style</caption>
 * import XxHash64 from "crypto-api-ng/src/hasher/xxhash64.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new XxHash64();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>XXH64 with a seed - ES6 style</caption>
 * import XxHash64 from "crypto-api-ng/src/hasher/xxhash64.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new XxHash64({seed: 12345});
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>XXH64 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('xxhash64', 'message'));
 * </script>
 */
class XxHash64 extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.seed=0] - an integer from 0 to 2^53 - 1
   */
  constructor(options) {
    super(XxHash64.spec, options);
  }
}

XxHash64.spec = {
  name: 'XxHash64', blockBytes: 32, digestBytes: 8,
  engine: () => engine,
  init: (options) => iv64(options.seed),
  specs: {seed: {min: 0, max: Number.MAX_SAFE_INTEGER}},
  normalize: (options, out) => {
    const seed = ownOption(options, 'seed');
    defineOption(out, 'seed', seed === undefined ? 0 : seed);
  }
};

export default XxHash64;
