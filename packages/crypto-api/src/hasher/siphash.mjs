// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {siphash24 as js, iv, normalizeKey} from "../blocks/siphash.mjs";
import {wasmBytes} from "../../wasm/siphash.mjs";
import createEngine from "../wasm/blocks.mjs";

const engine = createEngine(wasmBytes, {prefix: 'siphash24', block: 8, hashInts: 8, digest: 8}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates [SipHash-2-4](https://www.aumasson.jp/siphash/siphash.pdf) (Jean-Philippe Aumasson and Daniel J.
 * Bernstein): a keyed 64-bit hash for hash tables and other short-input uses where an attacker chooses the input
 * but must not be able to predict the hash. The 16-byte `key` is required and should be random and secret. The
 * 64-bit output is too short for a message authentication code; use HMAC or a keyed BLAKE2 for that. The digest
 * is the output of the reference implementation, the 64-bit result least significant byte first (`310e0edd47db6f72`
 * for the empty message with the key 00 01 .. 0f). The loop runs in WebAssembly, or in plain JavaScript where that
 * is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>SipHash-2-4 of "abc" - ES6 style</caption>
 * import SipHash from "crypto-api-ng/src/hasher/siphash.mjs";
 * import {hexToBytes} from "crypto-api-ng/src/encoder/bytes.mjs";
 *
 * let hasher = new SipHash({key: hexToBytes('000102030405060708090a0b0c0d0e0f')});
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 *
 * @example <caption>SipHash-2-4 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   var key = CryptoApi.encoder.hexToBytes('000102030405060708090a0b0c0d0e0f');
 *   console.log(CryptoApi.hash('siphash', 'message', {key: key}));
 * </script>
 */
class SipHash extends BlockHasher {
  /**
   * @param {Object} options
   * @param {string|ArrayBuffer|ArrayBufferView} options.key - 16 bytes, required
   */
  constructor(options) {
    super(SipHash.spec, options);
  }
}

SipHash.spec = {
  name: 'SipHash', blockBytes: 8, digestBytes: 8,
  engine: () => engine,
  init: (options) => iv(options.key),
  specs: {},
  normalize: (options, out) => normalizeKey('SipHash', options, out)
};

export default SipHash;
