// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {siphash13 as js, iv, normalizeKey} from "../blocks/siphash.mjs";
import {wasmBytes} from "../../wasm/siphash.mjs";
import createEngine from "../wasm/blocks.mjs";

const engine = createEngine(wasmBytes, {prefix: 'siphash13', block: 8, hashInts: 8, digest: 8}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates SipHash-1-3: SipHash with one compression round per word and three finalization rounds, the variant
 * Rust and Python use for their hash tables. It is about twice as fast as SipHash-2-4 with a smaller security
 * margin; prefer `SipHash` (2-4) unless a format needs this one. The 16-byte `key` is required and should be
 * random and secret. The digest is the 64-bit result least significant byte first (`dcc40f055801acab` for the
 * empty message with the key 00 01 .. 0f). The loop runs in WebAssembly, or in plain JavaScript where that is not
 * available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>SipHash-1-3 of "abc" - ES6 style</caption>
 * import SipHash13 from "crypto-api-ng/src/hasher/siphash13.mjs";
 * import {hexToBytes} from "crypto-api-ng/src/encoder/bytes.mjs";
 *
 * let hasher = new SipHash13({key: hexToBytes('000102030405060708090a0b0c0d0e0f')});
 * hasher.update('abc');
 * console.log(hasher.digest('hex'));
 */
class SipHash13 extends BlockHasher {
  /**
   * @param {Object} options
   * @param {string|ArrayBuffer|ArrayBufferView} options.key - 16 bytes, required
   */
  constructor(options) {
    super(SipHash13.spec, options);
  }
}

SipHash13.spec = {
  name: 'SipHash13', blockBytes: 8, digestBytes: 8,
  engine: () => engine,
  init: (options) => iv(options.key),
  specs: {},
  normalize: (options, out) => normalizeKey('SipHash13', options, out)
};

export default SipHash13;
