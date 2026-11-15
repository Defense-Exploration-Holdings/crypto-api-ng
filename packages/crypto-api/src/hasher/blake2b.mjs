// crypto-api-ng:facade
'use strict';

import Blake2 from "../blake/blake2-base.mjs";
import js, {IV} from "../blake/blake2b.mjs";
import {wasmBytes} from "../../wasm/blake2b.mjs";
import createEngine from "../wasm/blake2.mjs";

const engine = createEngine(wasmBytes, 'blake2b', 8, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates [BLAKE2b](https://www.rfc-editor.org/rfc/rfc7693) hash: 64-bit words, 128-byte
 * blocks, digests of 8 to 512 bits. The compression runs in WebAssembly, or in plain
 * JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>BLAKE2b-512 of "abc" - ES6 style</caption>
 * import Blake2b from "crypto-api-ng/src/hasher/blake2b.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Blake2b();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>BLAKE2b-256 keyed, with a salt - ES6 style</caption>
 * import Blake2b from "crypto-api-ng/src/hasher/blake2b.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Blake2b({length: 256, key: 'secret key', salt: 'salt'});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>BLAKE2b-512 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('blake2b', 'message'));
 * </script>
 */
class Blake2b extends Blake2 {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=512] - digest size in bits: 8 to 512 in steps of 8
   * @param {string|ArrayBuffer|ArrayBufferView} [options.key] - up to 64 bytes; makes the hash a MAC
   * @param {string|ArrayBuffer|ArrayBufferView} [options.salt] - up to 16 bytes
   * @param {string|ArrayBuffer|ArrayBufferView} [options.personalization] - up to 16 bytes
   */
  constructor(options) {
    super(Blake2b.spec, options);
  }
}

Blake2b.spec = {
  name: 'Blake2b', wordBytes: 8, blockBytes: 128, digestBytes: 64, paramBytes: 16,
  iv: IV, engine: () => engine
};

export default Blake2b;
