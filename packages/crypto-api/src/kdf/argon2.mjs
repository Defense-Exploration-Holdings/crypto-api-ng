// crypto-api-ng:facade
'use strict';

import {toBinaryString} from "../tools/input.mjs";
import {checkEncoding, encodeDigest, binaryToBytes} from "../tools/digest.mjs";
import {readOptions, binaryOption, integerOption} from "../tools/kdf.mjs";
import {derive as deriveJs} from "../pwhash/argon2.mjs";
import {wasmBytes} from "../../wasm/argon2.mjs";
import createRunner from "../wasm/pwhash.mjs";

const runner = createRunner(wasmBytes);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = runner.hooks();

const TYPES = ['argon2d', 'argon2i', 'argon2id'];

// Password and secret of each instance, as bytes. They are kept out of the
// object's own properties so that logging or serializing an instance does not
// print them.
const secrets = new WeakMap();
const MAX_U32 = 0xFFFFFFFF;

/**
 * Hashes a password with [Argon2](https://www.rfc-editor.org/rfc/rfc9106)
 * (RFC 9106, version 0x13): Argon2id (the default), Argon2i or Argon2d. Not part
 * of crypto-api 0.8.5.
 *
 * `iterations`, `memory` and `salt` are required. RFC 9106 recommends Argon2id
 * with `iterations: 1, memory: 2097152` (2 GiB) or, where that much memory is
 * not available, `iterations: 3, memory: 65536` (64 MiB), with `parallelism: 4`
 * and a random 16-byte salt. Lanes are computed one after another, so
 * `parallelism` adds time here without making anything faster.
 *
 * The work runs in WebAssembly, or in plain JavaScript where that is not
 * available (several times slower). Each derivation gets its own wasm memory,
 * which is zeroed and released afterwards.
 *
 * @example <caption>A 32-byte Argon2id tag</caption>
 * import Argon2 from "crypto-api-ng/src/kdf/argon2.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * const kdf = new Argon2('password', {salt: salt, iterations: 3, memory: 65536, parallelism: 1});
 * console.log(toHex(kdf.finalize()));
 */
class Argon2 {
  /**
   * @param {string|ArrayBuffer|ArrayBufferView} password - binary string or bytes
   *   (use `fromUtf()` for text that is not ASCII)
   * @param {Object} options
   * @param {string|ArrayBuffer|ArrayBufferView} options.salt - 8 bytes or more (required)
   * @param {number} options.iterations - passes over the memory, 1 to 4294967295 (required)
   * @param {number} options.memory - memory size in KiB, from 8 times `parallelism`
   *   to 4294967295 (required)
   * @param {number} [options.parallelism=1] - lanes, 1 to 16777215
   * @param {string} [options.type='argon2id'] - `'argon2id'`, `'argon2i'` or `'argon2d'`
   * @param {number} [options.length=256] - tag size in bits, a multiple of 8 from 32
   * @param {string|ArrayBuffer|ArrayBufferView} [options.secret] - key, default empty
   * @param {string|ArrayBuffer|ArrayBufferView} [options.associatedData] - default empty
   * @throws {TypeError} for an option or the password of the wrong type, a missing or unknown option
   * @throws {RangeError} for a value outside the supported set
   */
  constructor(password, options) {
    const given = readOptions('Argon2', options,
      ['type', 'salt', 'iterations', 'memory', 'parallelism', 'length', 'secret', 'associatedData']);
    for (const key of ['salt', 'iterations', 'memory']) {
      if (!Object.prototype.hasOwnProperty.call(given, key)) {
        throw new TypeError('Argon2: ' + key + ' is required');
      }
    }
    let type = 'argon2id';
    if (Object.prototype.hasOwnProperty.call(given, 'type')) {
      type = given.type;
      if (typeof type !== 'string') {
        throw new TypeError('Argon2: type must be a string, got ' + typeof type);
      }
      if (TYPES.indexOf(type) === -1) {
        throw new RangeError('Argon2: type must be "argon2id", "argon2i" or "argon2d", got "' + type + '"');
      }
    }
    const salt = binaryOption('Argon2', given, 'salt');
    if (salt.length < 8 || salt.length > MAX_U32) {
      throw new RangeError('Argon2: salt must be 8 bytes or more, got ' + salt.length);
    }
    const secret = binaryToBytes(binaryOption('Argon2', given, 'secret'));
    const associatedData = binaryOption('Argon2', given, 'associatedData');
    const iterations = integerOption('Argon2', given, 'iterations', 1, MAX_U32, 1);
    const parallelism = integerOption('Argon2', given, 'parallelism', 1, 0xFFFFFF, 1, 1);
    const memory = integerOption('Argon2', given, 'memory', 8 * parallelism, MAX_U32, 1);
    const length = integerOption('Argon2', given, 'length', 32, MAX_U32 * 8, 8, 256);
    secrets.set(this, {password: binaryToBytes(toBinaryString(password, 'password')), secret: secret});
    /**
     * The options in effect. `secret` is not included.
     *
     * @type {{type: string, salt: string, iterations: number, memory: number, parallelism: number,
     *   length: number, associatedData: string}}
     */
    this.options = {
      type: type, salt: salt, iterations: iterations, memory: memory, parallelism: parallelism,
      length: length, associatedData: associatedData
    };
  }

  /**
   * Derive the tag and return it as a binary string. Can be called again and
   * gives the same value.
   *
   * @returns {string}
   * @throws {RangeError} when the memory cannot be allocated
   */
  finalize() {
    const o = this.options;
    const mode = TYPES.indexOf(o.type);
    const bytes = o.length / 8;
    const kept = secrets.get(this);
    const password = kept.password.slice();
    const salt = binaryToBytes(o.salt);
    const secret = kept.secret.slice();
    const ad = binaryToBytes(o.associatedData);
    try {
      let tag = runner.run((ex, put, take) => {
        const out = take(bytes);
        const status = ex.argon2_hash(mode, o.iterations, o.memory, o.parallelism,
          put(password), password.length, put(salt), salt.length, put(secret), secret.length,
          put(ad), ad.length, out.ptr, bytes);
        return {status: status, result: status === 0 ? out.read() : null};
      });
      if (tag === null) {
        tag = deriveJs(mode, o.iterations, o.memory, o.parallelism, password, salt, secret, ad, bytes);
      }
      let result = '';
      for (let i = 0; i < tag.length; i += 8192) {
        result += String.fromCharCode.apply(null, tag.subarray(i, i + 8192));
      }
      tag.fill(0);
      return result;
    } finally {
      password.fill(0);
      secret.fill(0);
    }
  }

  /**
   * Like `finalize()`, but returns the tag as bytes, or encoded as text.
   *
   * @param {string} [encoding] - `'hex'`, `'base64'`, `'base64url'` or `'binary'`
   *   (the binary string `finalize()` returns); left out, the tag is bytes
   * @returns {Uint8Array|string}
   * @throws {TypeError} for any other `encoding`
   */
  digest(encoding) {
    checkEncoding(encoding);
    return encodeDigest(this.finalize(), encoding);
  }
}

export default Argon2;
