// crypto-api-ng:facade
'use strict';

import {toBinaryString} from "../tools/input.mjs";
import {checkEncoding, encodeDigest, binaryToBytes} from "../tools/digest.mjs";
import {readOptions, binaryOption, integerOption} from "../tools/kdf.mjs";
import {derive as deriveJs} from "../pwhash/scrypt.mjs";
import {wasmBytes} from "../../wasm/scrypt.mjs";
import createRunner from "../wasm/pwhash.mjs";

const runner = createRunner(wasmBytes);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = runner.hooks();

/**
 * Derives a key from a password with [scrypt](https://www.rfc-editor.org/rfc/rfc7914)
 * (RFC 7914). Not part of crypto-api 0.8.5.
 *
 * `cost` (N) is required. Memory use is about 128 * `cost` * `blockSize` bytes;
 * OWASP advises `cost: 131072` (2^17) with `blockSize: 8` and `parallelization: 1`
 * as of 2023, which needs 128 MiB.
 *
 * The work runs in WebAssembly, or in plain JavaScript where that is not
 * available. Each derivation gets its own wasm memory, which is zeroed and
 * released afterwards.
 *
 * @example <caption>32 bytes with N = 2^17, r = 8, p = 1</caption>
 * import Scrypt from "crypto-api-ng/src/kdf/scrypt.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * const kdf = new Scrypt('password', {salt: salt, cost: 131072});
 * console.log(toHex(kdf.finalize()));
 */
class Scrypt {
  /**
   * @param {string|ArrayBuffer|ArrayBufferView} password - binary string or bytes
   *   (use `fromUtf()` for text that is not ASCII)
   * @param {Object} options
   * @param {number} options.cost - N, a power of two from 2, below 2^(16 * blockSize) (required)
   * @param {number} [options.blockSize=8] - r, from 1
   * @param {number} [options.parallelization=1] - p, from 1; `blockSize * parallelization` below 2^30
   * @param {string|ArrayBuffer|ArrayBufferView} [options.salt] - binary string or bytes, default empty
   * @param {number} [options.length=256] - key size in bits, a multiple of 8
   * @throws {TypeError} for an option or the password of the wrong type, a missing or unknown option
   * @throws {RangeError} for a value outside the supported set
   */
  constructor(password, options) {
    const given = readOptions('Scrypt', options, ['cost', 'blockSize', 'parallelization', 'salt', 'length']);
    if (!Object.prototype.hasOwnProperty.call(given, 'cost')) {
      throw new TypeError('Scrypt: cost is required');
    }
    const cost = integerOption('Scrypt', given, 'cost', 2, Number.MAX_SAFE_INTEGER, 1);
    if (!Number.isInteger(Math.log2(cost))) {
      throw new RangeError('Scrypt: cost must be a power of two, got ' + cost);
    }
    const blockSize = integerOption('Scrypt', given, 'blockSize', 1, 0x3FFFFFFF, 1, 8);
    const parallelization = integerOption('Scrypt', given, 'parallelization', 1, 0x3FFFFFFF, 1, 1);
    if (blockSize * parallelization >= 0x40000000) {
      throw new RangeError('Scrypt: blockSize * parallelization must be below 2^30, got ' + blockSize * parallelization);
    }
    if (Math.log2(cost) >= 16 * blockSize) {
      throw new RangeError('Scrypt: cost must be below 2^(16 * blockSize), got ' + cost);
    }
    const length = integerOption('Scrypt', given, 'length', 8, 0xFFFFFFFF * 256, 8, 256);
    /** @ignore */
    this.password = toBinaryString(password, 'password');
    /** @type {{cost: number, blockSize: number, parallelization: number, salt: string, length: number}} */
    this.options = {
      cost: cost, blockSize: blockSize, parallelization: parallelization,
      salt: binaryOption('Scrypt', given, 'salt'), length: length
    };
  }

  /**
   * Derive the key and return it as a binary string. Can be called again and
   * gives the same value.
   *
   * @returns {string}
   * @throws {RangeError} when the memory cannot be allocated
   */
  finalize() {
    const o = this.options;
    const bytes = o.length / 8;
    const password = binaryToBytes(this.password);
    const salt = binaryToBytes(o.salt);
    try {
      let key = runner.run((ex, put, take) => {
        const out = take(bytes);
        const status = ex.scrypt_hash(Math.log2(o.cost), o.blockSize, o.parallelization,
          put(password), password.length, put(salt), salt.length, out.ptr, bytes);
        return {status: status, result: status === 0 ? out.read() : null};
      });
      if (key === null) {
        key = deriveJs(o.cost, o.blockSize, o.parallelization, password, salt, bytes);
      }
      let result = '';
      for (let i = 0; i < key.length; i += 8192) {
        result += String.fromCharCode.apply(null, key.subarray(i, i + 8192));
      }
      key.fill(0);
      return result;
    } finally {
      password.fill(0);
    }
  }

  /**
   * Like `finalize()`, but returns the key as bytes, or encoded as text.
   *
   * @param {string} [encoding] - `'hex'`, `'base64'`, `'base64url'` or `'binary'`
   *   (the binary string `finalize()` returns); left out, the key is bytes
   * @returns {Uint8Array|string}
   * @throws {TypeError} for any other `encoding`
   */
  digest(encoding) {
    checkEncoding(encoding);
    return encodeDigest(this.finalize(), encoding);
  }
}

export default Scrypt;
