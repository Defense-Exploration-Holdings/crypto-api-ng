// crypto-api-ng:facade
'use strict';

import BlockHasher from "../blocks/base.mjs";
import {crc32c as js, IV} from "../blocks/crc32.mjs";
import {wasmBytes} from "../../wasm/crc32.mjs";
import createEngine from "../wasm/blocks.mjs";

const engine = createEngine(wasmBytes, {prefix: 'crc32c', block: 64, hashInts: 1, digest: 4, stateSize: 16}, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/**
 * Calculates the CRC-32C checksum (Castagnoli, as used by iSCSI, ext4 and Btrfs). It is a 32-bit checksum
 * for catching accidental changes, not a cryptographic hash: anyone can produce a message with
 * any checksum they want. The digest is the four bytes of the checksum, most significant first, so
 * its hex form is the number everyone prints (`e3069283` for "123456789"). The loop runs in
 * WebAssembly, or in plain JavaScript where that is not available.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>CRC-32C of "123456789" - ES6 style</caption>
 * import Crc32c from "crypto-api-ng/src/hasher/crc32c.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Crc32c();
 * hasher.update('123456789');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>CRC-32C of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('crc32c', 'message'));
 * </script>
 */
class Crc32c extends BlockHasher {
  /**
   * @param {Object} [options] - there are none; the argument is accepted for the common interface
   */
  constructor(options) {
    super(Crc32c.spec, options);
  }
}

Crc32c.spec = {
  name: 'Crc32c', blockBytes: 64, digestBytes: 4,
  engine: () => engine,
  init: () => IV.slice(),
  specs: {},
  normalize: () => {}
};

export default Crc32c;
