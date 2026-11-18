// crypto-api-ng:facade
'use strict';

import {toBinaryString, bytesOf} from "../tools/input.mjs";
import Hasher from "../hasher/hasher.mjs";
import {checkEncoding, encodeDigest} from "../tools/digest.mjs";

/**
 * Calculates [HMAC](https://tools.ietf.org/html/rfc2104)
 *
 * @example <caption>Calculates HMAC-MD5 from string "message" with key "key" - ES6 style</caption>
 * import Md5 from "crypto-api/src/hasher/md5";
 * import Hmac from "crypto-api/src/mac/hmac";
 * import {toHex} from "crypto-api/src/encoder/hex";
 *
 * let hasher = new Md5();
 * let hmac = new Hmac('key', hasher);
 * hmac.update('message');
 * console.log(toHex(hmac.finalize()));
 *
 * @example <caption>Calculates HMAC-MD5 from UTF string "message" with UTF key "key" - ES6 style</caption>
 * import Md5 from "crypto-api/src/hasher/md5";
 * import Hmac from "crypto-api/src/mac/hmac";
 * import {toHex} from "crypto-api/src/encoder/hex";
 * import {fromUtf} from "crypto-api/src/encoder/utf";
 *
 * let hasher = new Md5();
 * let hmac = new Hmac(fromUtf('key'), hasher);
 * hmac.update(fromUtf('message'));
 * console.log(toHex(hmac.finalize()));
 *
 * @example <caption>Calculates HMAC-MD5 from string "message" with key "key" - ES5 style</caption>
 * <script src="https://nf404.github.io/crypto-api/crypto-api.min.js"></script>
 * <script>
 *   var hasher = CryptoApi.getHasher('md5');
 *   var hmac = CryptoApi.getHmac('key', hasher);
 *   hmac.update('message');
 *   console.log(CryptoApi.encoder.toHex(hmac.finalize()));
 * </script>
 *
 * @example <caption>Calculates HMAC-MD5 from UTF string "message" with UTF key "key" - ES5 style</caption>
 * <script src="https://nf404.github.io/crypto-api/crypto-api.min.js"></script>
 * <script>
 *   var hasher = CryptoApi.getHasher('md5');
 *   console.log(CryptoApi.hmac('key', 'message', hasher));
 * </script>
 */
class Hmac {
  /**
   * The hasher passed in is not modified: HMAC runs on two fresh hashers of
   * the same class and options.
   *
   * @param {string|ArrayBuffer|ArrayBufferView} key - binary string or bytes
   * @param {Hasher} hasher
   */
  constructor(key, hasher) {
    key = toBinaryString(key, 'key');
    const inner = freshCopy(hasher);
    const outer = freshCopy(hasher);
    const blockSize = inner.blockSizeInBytes;
    if (key.length > blockSize) {
      inner.update(key);
      key = inner.finalize();
      inner.reset();
    }
    let iPad = '';
    let oPad = '';
    for (let i = 0; i < blockSize; i++) {
      const c = i < key.length ? key.charCodeAt(i) : 0;
      iPad += String.fromCharCode(0x36 ^ c);
      oPad += String.fromCharCode(0x5c ^ c);
    }
    inner.update(iPad);
    outer.update(oPad);
    /**
     * @type {string}
     * @ignore
     */
    this.oPad = oPad;
    /**
     * Inner hasher (key XOR ipad, then the message)
     * @type {Hasher}
     * @ignore
     */
    this.hasher = inner;
    /**
     * @type {Hasher}
     * @ignore
     */
    this.outer = outer;
    /** @ignore */
    this.innerStart = JSON.stringify(inner.getState());
    /** @ignore */
    this.outerStart = JSON.stringify(outer.getState());
  }

  /**
   * Reset to the state right after construction (same key, no message)
   */
  reset() {
    this.hasher.setState(JSON.parse(this.innerStart));
  }

  /**
   * Update message from binary string or bytes
   *
   * @param {string|ArrayBuffer|ArrayBufferView} message
   */
  update(message) {
    const hasher = this.hasher;
    // Bytes go to Hasher#update() as they are, which copies them straight into
    // wasm memory where it can; any other update() gets the binary string.
    if (typeof message !== 'string' && hasher.update === Hasher.prototype.update && bytesOf(message) !== null) {
      hasher.update(message);
      return;
    }
    hasher.update(toBinaryString(message));
  }

  /**
   * Finalize hmac and return result. Does not end the message: calling it
   * again returns the same value, and `update()` continues the message.
   *
   * @returns {string}
   */
  finalize() {
    const state = JSON.stringify(this.hasher.getState());
    const hash = this.hasher.finalize();
    this.hasher.setState(JSON.parse(state));
    this.outer.setState(JSON.parse(this.outerStart));
    this.outer.update(hash);
    return this.outer.finalize();
  }

  /**
   * Like `finalize()`, but returns the MAC as bytes, or encoded as text.
   *
   * @param {string} [encoding] - `'hex'`, `'base64'`, `'base64url'` or `'binary'`
   *   (the binary string `finalize()` returns); left out, the MAC is bytes
   * @returns {Uint8Array|string}
   * @throws {TypeError} for any other `encoding`
   */
  digest(encoding) {
    checkEncoding(encoding);
    return encodeDigest(this.finalize(), encoding);
  }
}

/**
 * A new hasher of the same class and options as `hasher`, in its initial state.
 *
 * @ignore
 * @param {Hasher} hasher
 * @returns {Hasher}
 */
function freshCopy(hasher) {
  if (hasher === null || typeof hasher !== 'object') {
    throw new TypeError('Hmac: hasher must be a hasher object');
  }
  const proto = Object.getPrototypeOf(hasher);
  const options = hasher.options && typeof hasher.options === 'object' ?
    Object.assign({}, hasher.options) : hasher.options;
  let copy = null;
  try {
    copy = new hasher.constructor(options);
  } catch (e) {
    copy = null;
  }
  if (copy === null || Object.getPrototypeOf(copy) !== proto ||
    copy.blockSizeInBytes !== hasher.blockSizeInBytes) {
    // A constructor that does not take an options object: copy the instance.
    copy = Object.assign(Object.create(proto), hasher);
    copy.options = options;
  }
  copy.reset();
  return copy;
}

export default Hmac;
