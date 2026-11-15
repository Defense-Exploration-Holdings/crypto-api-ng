// crypto-api-ng:facade
'use strict';

import Blake2 from "../blake/blake2-base.mjs";
import js, {IV} from "../blake/blake2s.mjs";
import {wasmBytes} from "../../wasm/blake2s.mjs";
import createEngine from "../wasm/blake2.mjs";

const engine = createEngine(wasmBytes, 'blake2s', 4, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates [BLAKE2s](https://www.rfc-editor.org/rfc/rfc7693) hash: 32-bit words, 64-byte
 * blocks, digests of 8 to 256 bits. The compression runs in WebAssembly, or in plain
 * JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>BLAKE2s-256 of "abc" - ES6 style</caption>
 * import Blake2s from "crypto-api-ng/src/hasher/blake2s.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Blake2s();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>BLAKE2s-128 keyed - ES6 style</caption>
 * import Blake2s from "crypto-api-ng/src/hasher/blake2s.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Blake2s({length: 128, key: 'secret key'});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>BLAKE2s-256 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('blake2s', 'message'));
 * </script>
 */
class Blake2s extends Blake2 {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=256] - digest size in bits: 8 to 256 in steps of 8
   * @param {string|ArrayBuffer|ArrayBufferView} [options.key] - up to 32 bytes; makes the hash a MAC
   * @param {string|ArrayBuffer|ArrayBufferView} [options.salt] - up to 8 bytes
   * @param {string|ArrayBuffer|ArrayBufferView} [options.personalization] - up to 8 bytes
   */
  constructor(options) {
    super(Blake2s.spec, options);
  }
}

Blake2s.spec = {
  name: 'Blake2s', wordBytes: 4, blockBytes: 64, digestBytes: 32, paramBytes: 8,
  iv: IV, engine: () => engine
};

export default Blake2s;
