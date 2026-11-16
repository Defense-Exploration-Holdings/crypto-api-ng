// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {crc32 as js, IV} from "../blocks/crc32.mjs";
import {wasmBytes} from "../../wasm/crc32.mjs";
import createEngine from "../wasm/blocks.mjs";

const engine = createEngine(wasmBytes, {prefix: 'crc32', block: 64, hashInts: 1, digest: 4, stateSize: 16}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates the CRC-32 checksum (IEEE 802.3, as used by zlib, gzip, PNG and Ethernet). It is a 32-bit checksum
 * for catching accidental changes, not a cryptographic hash: anyone can produce a message with
 * any checksum they want. The digest is the four bytes of the checksum, most significant first, so
 * its hex form is the number everyone prints (`cbf43926` for "123456789"). The loop runs in
 * WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>CRC-32 of "123456789" - ES6 style</caption>
 * import Crc32 from "crypto-api-ng/src/hasher/crc32.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Crc32();
 * hasher.update('123456789');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>CRC-32 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('crc32', 'message'));
 * </script>
 */
class Crc32 extends BlockHasher {
  /**
   * @param {Object} [options] - there are none; the argument is accepted for the common interface
   */
  constructor(options) {
    super(Crc32.spec, options);
  }
}

Crc32.spec = {
  name: 'Crc32', blockBytes: 64, digestBytes: 4,
  engine: () => engine,
  init: () => IV.slice(),
  specs: {},
  normalize: () => {}
};

export default Crc32;
