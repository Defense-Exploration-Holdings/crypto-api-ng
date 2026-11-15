// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {streebog256 as js256, streebog512 as js512, iv} from "../blocks/streebog.mjs";
import {wasmBytes} from "../../wasm/streebog.mjs";
import createEngine from "../wasm/blocks.mjs";
import {ownOption, defineOption} from "../tools/input.mjs";

// The wasm state of Streebog is 136 bytes, more than the 128-byte state slot, so the digest is
// written behind the (at most 64 byte) last block in the input region instead of the output slot.
const OUT_AFTER_INPUT = 256 + 64;
const engine256 = createEngine(wasmBytes, {prefix: 'streebog256', block: 64, hashInts: 32, digest: 32, outOff: OUT_AFTER_INPUT}, js256);
const engine512 = createEngine(wasmBytes, {prefix: 'streebog512', block: 64, hashInts: 32, digest: 64, outOff: OUT_AFTER_INPUT}, js512);

const hooks256 = engine256.hooks();
const hooks512 = engine512.hooks();

/**
 * Test-only hooks; not public API and not kept in later releases. They act on both engines
 * (Streebog-256 and Streebog-512 each have one).
 */
export const _internal = {
  wasmCalls: () => hooks256.wasmCalls() + hooks512.wasmCalls(),
  runtime: () => hooks512.runtime() || hooks256.runtime(),
  reset: (disable) => {
    hooks256.reset(disable);
    hooks512.reset(disable);
  },
  fallback: js512,
  engines: {256: hooks256, 512: hooks512}
};

/**
 * Calculates [Streebog](https://www.rfc-editor.org/rfc/rfc6986) hash, the GOST R 34.11-2012 standard:
 * 64-byte blocks, 256- or 512-bit digest. The digest is the final value in memory order, as printed by
 * OpenSSL's gost engine, rhash and the Linux kernel (`3f539a21...` for the empty message with 256 bits);
 * RFC 6986 prints its test vectors byte-reversed. The compression runs in WebAssembly, or in plain
 * JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>Streebog-512 of "abc" - ES6 style</caption>
 * import Streebog from "crypto-api-ng/src/hasher/streebog.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Streebog();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Streebog-256 of "abc" - ES6 style</caption>
 * import Streebog from "crypto-api-ng/src/hasher/streebog.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Streebog({length: 256});
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Streebog-256 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('streebog256', 'message'));
 * </script>
 */
class Streebog extends BlockHasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=512] - digest size in bits: 256 or 512
   */
  constructor(options) {
    super(Streebog.spec, options);
  }
}

Streebog.spec = {
  name: 'Streebog', blockBytes: 64, digestBytes: 64,
  engine: (options) => options.length === 256 ? engine256 : engine512,
  init: (options) => iv(options.length / 8),
  specs: {length: {values: [256, 512]}},
  normalize: (options, out) => {
    const length = ownOption(options, 'length');
    defineOption(out, 'length', length === undefined ? 512 : length);
  }
};

export default Streebog;
