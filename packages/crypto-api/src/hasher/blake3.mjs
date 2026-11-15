// crypto-api-ng:facade
'use strict';

import Hasher from "./hasher.mjs";
import js, {IV, CHUNK, KEYED_HASH, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL} from "../blake/blake3.mjs";
import {wasmBytes} from "../../wasm/blake3.mjs";
import createEngine from "../wasm/blake3.mjs";
import {toBinaryString, checkOptions} from "../tools/input.mjs";

const engine = createEngine(wasmBytes, js);

/**
 * Test-only hooks; not public API and not kept in later releases.
 */
export const _internal = engine.hooks();

/** Longest output, in bytes. BLAKE3 can produce any length; this keeps a digest a reasonable string. */
const MAX_OUTPUT = 1 << 20;

/** The little-endian int32 words of a binary string of 32 bytes. */
function words(bytes) {
  const out = [];
  for (let i = 0; i < 32; i += 4) {
    out.push(bytes.charCodeAt(i) | (bytes.charCodeAt(i + 1) << 8) | (bytes.charCodeAt(i + 2) << 16) | (bytes.charCodeAt(i + 3) << 24));
  }
  return out;
}

/** Hash a whole binary string `message` with `init` and return `bytes` bytes of output. */
function hashAll(init, message, bytes) {
  const state = {chunks: 0, stack: []};
  const whole = Math.floor((message.length - 1) / CHUNK);
  if (whole > 0) {
    engine.update(state, init, message, whole);
  }
  return engine.finalize(state, init, message.substr(Math.max(whole, 0) * CHUNK), bytes);
}

/**
 * Check the options and return a copy with the defaults filled in, together with the
 * key words and flags every compression of this hash uses.
 */
function normalize(options) {
  if (options !== undefined && options !== null && typeof options !== 'object') {
    throw new TypeError('Blake3: options must be an object');
  }
  options = options || {};
  checkOptions('Blake3', options, {length: {min: 8, max: 8 * MAX_OUTPUT, step: 8}});
  const out = {length: options.length === undefined ? 256 : options.length};
  let init = {key: IV, flags: 0};
  if (options.key !== undefined && options.context !== undefined) {
    throw new TypeError('Blake3: key and context cannot be used together');
  }
  if (options.key !== undefined) {
    out.key = toBinaryString(options.key, 'key');
    if (out.key.length !== 32) {
      throw new RangeError('Blake3: key must be 32 bytes, got ' + out.key.length);
    }
    init = {key: words(out.key), flags: KEYED_HASH};
  } else if (options.context !== undefined) {
    out.context = toBinaryString(options.context, 'context');
    // The context string is hashed once; its 32-byte output keys the hash of the material.
    const contextKey = hashAll({key: IV, flags: DERIVE_KEY_CONTEXT}, out.context, 32);
    init = {key: words(contextKey), flags: DERIVE_KEY_MATERIAL};
  }
  return {options: out, init: init};
}

/**
 * Calculates [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash, with its three modes:
 * plain hash, keyed hash (`key`, a MAC) and key derivation (`context`). The output can have
 * any length from 8 bits to 1 MiB (`length`); the first 256 bits are the usual BLAKE3 hash.
 * The compression runs in WebAssembly, or in plain JavaScript where that is not available.
 *
 * `state` is `{message, length, chunks, stack}`: the bytes of the last, unfinished chunk
 * (at most 1024), the length of the message, the number of finished chunks and the chaining
 * values of the finished subtrees (eight int32 each). The last chunk stays in `message`
 * until `finalize()`, which does not modify the state: it can be called again, and
 * `update()` continues the message.
 *
 * Messages are limited to 2^53 - 1 bytes.
 *
 * @example <caption>BLAKE3 of "abc" - ES6 style</caption>
 * import Blake3 from "crypto-api-ng/src/hasher/blake3.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Blake3();
 * hasher.update('abc');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Keyed hash with 512 bits of output - ES6 style</caption>
 * import Blake3 from "crypto-api-ng/src/hasher/blake3.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Blake3({key: new Uint8Array(32), length: 512});
 * hasher.update('message');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>Derive a key from key material - ES6 style</caption>
 * import Blake3 from "crypto-api-ng/src/hasher/blake3.mjs";
 * import {toHex} from "crypto-api-ng/src/encoder/hex.mjs";
 *
 * let hasher = new Blake3({context: 'my-app 2026-01-01 session keys'});
 * hasher.update('input key material');
 * console.log(toHex(hasher.finalize()));
 *
 * @example <caption>BLAKE3 of UTF string "message" - ES5 style</caption>
 * <script src="https://unpkg.com/crypto-api-ng/crypto-api.min.js"></script>
 * <script>
 *   console.log(CryptoApi.hash('blake3', 'message'));
 * </script>
 */
class Blake3 extends Hasher {
  /**
   * @param {Object} [options]
   * @param {number} [options.length=256] - output size in bits: 8 to 8388608 in steps of 8
   * @param {string|ArrayBuffer|ArrayBufferView} [options.key] - exactly 32 bytes: keyed hash
   * @param {string|ArrayBuffer|ArrayBufferView} [options.context] - derive-key mode; cannot be combined with `key`
   */
  constructor(options) {
    const checked = normalize(options);
    super(checked.options);
    /**
     * Key words and flags of every compression of this hash
     * @private
     */
    this.init = checked.init;
  }

  /**
   * Reset hasher to initial state
   */
  reset() {
    this.state = {message: '', length: 0, chunks: 0, stack: []};
  }

  /**
   * Process ready blocks
   *
   * @protected
   */
  process() {
    const state = this.state;
    const length = state.message.length;
    if (length <= CHUNK) {
      return;
    }
    // Every chunk but the last one is added to the tree; the last one waits for finalize().
    const whole = Math.floor((length - 1) / CHUNK);
    engine.update(state, this.init, state.message, whole);
    state.message = state.message.substr(whole * CHUNK);
  }

  /**
   * Finalize hash and return result. The state is not modified.
   *
   * @returns {string}
   */
  finalize() {
    this.process();
    return engine.finalize(this.state, this.init, this.state.message, this.options.length / 8);
  }
}

export default Blake3;
