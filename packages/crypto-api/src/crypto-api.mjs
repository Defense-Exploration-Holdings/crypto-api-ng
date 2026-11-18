// crypto-api-ng:facade
'use strict';

import Blake2b from "./hasher/blake2b.mjs";
import Blake2s from "./hasher/blake2s.mjs";
import Blake3 from "./hasher/blake3.mjs";
import Has160 from "./hasher/has160.mjs";
import Md2 from "./hasher/md2.mjs";
import Md4 from "./hasher/md4.mjs";
import Md5 from "./hasher/md5.mjs";
import Ripemd from "./hasher/ripemd.mjs";
import Sha0 from "./hasher/sha0.mjs";
import Sha1 from "./hasher/sha1.mjs";
import Sha256 from "./hasher/sha256.mjs";
import Sha512 from "./hasher/sha512.mjs";
import Sm3 from "./hasher/sm3.mjs";
import Streebog from "./hasher/streebog.mjs";
import Snefru from "./hasher/snefru.mjs";
import Tiger from "./hasher/tiger.mjs";
import Tiger2 from "./hasher/tiger2.mjs";
import Whirlpool from "./hasher/whirlpool.mjs";
import XxHash32 from "./hasher/xxhash32.mjs";
import XxHash64 from "./hasher/xxhash64.mjs";
import XxHash3 from "./hasher/xxhash3.mjs";
import XxHash128 from "./hasher/xxhash128.mjs";
import SipHash from "./hasher/siphash.mjs";
import SipHash13 from "./hasher/siphash13.mjs";
import Murmur3 from "./hasher/murmur3.mjs";
import Murmur3x64 from "./hasher/murmur3x64.mjs";
import Crc32 from "./hasher/crc32.mjs";
import Crc32c from "./hasher/crc32c.mjs";
import Keccak from "./hasher/keccak.mjs";
import Sha3 from "./hasher/sha3.mjs";
import Shake from "./hasher/shake.mjs";
import {fromUtf} from "./encoder/utf.mjs";
import {fromArrayBuffer} from "./encoder/array-buffer.mjs";
import {toHex} from "./encoder/hex.mjs";
import {toBase64} from "./encoder/base64.mjs";
import {utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes} from "./encoder/bytes.mjs";
import Hmac from "./mac/hmac.mjs";
import Pbkdf2 from "./kdf/pbkdf2.mjs";
import Hkdf from "./kdf/hkdf.mjs";
import {toBinaryString} from "./tools/input.mjs";

/**
 * UTF-8 encode a string; pass bytes through as a binary string.
 *
 * @ignore
 * @param {*} value
 * @param {string} what
 * @returns {string}
 */
function utfOrBytes(value, what) {
  return typeof value === 'string' ? fromUtf(value) : toBinaryString(value, what);
}

/**
 * A copy of own `options` in which the byte options named in `keys` that are strings
 * are UTF-8 encoded. Anything that is not a plain options object goes through as it
 * is, for the class to reject.
 *
 * @ignore
 * @param {Object|undefined} options
 * @param {string[]} keys
 * @returns {Object|undefined}
 */
function utfOptions(options, keys) {
  if (options === null || typeof options !== 'object') {
    return options;
  }
  const copy = {};
  for (const key of Object.keys(options)) {
    copy[key] = keys.indexOf(key) !== -1 && typeof options[key] === 'string' ? fromUtf(options[key]) : options[key];
  }
  return copy;
}

/**
 * Main class for ES5 compatibility.
 * Please use subclasses of {@link Hasher} for ES6
 */
class CryptoApi {
  /**
   * @ignore
   */
  constructor() {
    /** @type {{}} */
    this.encoder = {};
    /** @type {fromUtf} */
    this.encoder.fromUtf = fromUtf;
    /** @type {fromArrayBuffer} */
    this.encoder.fromArrayBuffer = fromArrayBuffer;
    /** @type {toHex} */
    this.encoder.toHex = toHex;
    /** @type {toBase64} */
    this.encoder.toBase64 = toBase64;
    // Added by crypto-api-ng: the same conversions on bytes (Uint8Array)
    this.encoder.utf8ToBytes = utf8ToBytes;
    this.encoder.bytesToUtf8 = bytesToUtf8;
    this.encoder.bytesToHex = bytesToHex;
    this.encoder.hexToBytes = hexToBytes;
    this.encoder.bytesToBase64 = bytesToBase64;
    this.encoder.base64ToBytes = base64ToBytes;
  }

  /**
   * Get hasher by alias
   *
   * @param {string} name
   * @param {Object} options
   * @returns {Hasher}
   */
  getHasher(name, options) {
    options = options || {};
    switch (name) {
      case 'has160':
        return new Has160(options);
      case 'md2':
        return new Md2(options);
      case 'md4':
        return new Md4(options);
      case 'md5':
        return new Md5(options);
      case 'ripemd128':
        options = Object.assign({}, {length: 128}, options);
        return new Ripemd(options);
      case 'ripemd':
      case 'ripemd160':
        options = Object.assign({}, {length: 160}, options);
        return new Ripemd(options);
      case 'ripemd256':
        options = Object.assign({}, {length: 256}, options);
        return new Ripemd(options);
      case 'ripemd320':
        options = Object.assign({}, {length: 320}, options);
        return new Ripemd(options);
      case 'sha0':
        return new Sha0(options);
      case 'sha1':
        return new Sha1(options);
      case 'sha224':
        options = Object.assign({}, {length: 224}, options);
        return new Sha256(options);
      case 'sha256':
        options = Object.assign({}, {length: 256}, options);
        return new Sha256(options);
      case 'sha384':
        options = Object.assign({}, {length: 384}, options);
        return new Sha512(options);
      case 'sha512':
        options = Object.assign({}, {length: 512}, options);
        return new Sha512(options);
      case 'sha512/224':
        options = Object.assign({}, {length: 224}, options);
        return new Sha512(options);
      case 'sha512/256':
        options = Object.assign({}, {length: 256}, options);
        return new Sha512(options);
      case 'sm3':
        return new Sm3(options);
      case 'sha3-224':
        options = Object.assign({}, {length: 224}, options);
        return new Sha3(options);
      case 'sha3-256':
        options = Object.assign({}, {length: 256}, options);
        return new Sha3(options);
      case 'sha3-384':
        options = Object.assign({}, {length: 384}, options);
        return new Sha3(options);
      case 'sha3-512':
        options = Object.assign({}, {length: 512}, options);
        return new Sha3(options);
      case 'keccak224':
        options = Object.assign({}, {length: 224}, options);
        return new Keccak(options);
      case 'keccak256':
        options = Object.assign({}, {length: 256}, options);
        return new Keccak(options);
      case 'keccak384':
        options = Object.assign({}, {length: 384}, options);
        return new Keccak(options);
      case 'keccak512':
        options = Object.assign({}, {length: 512}, options);
        return new Keccak(options);
      case 'shake128':
        options = Object.assign({}, {strength: 128}, options);
        return new Shake(options);
      case 'shake256':
        options = Object.assign({}, {strength: 256}, options);
        return new Shake(options);
      case 'snefru':
      case 'snefru128':
      case 'snefru128/8':
        options = Object.assign({}, {length: 128}, options);
        return new Snefru(options);
      case 'snefru256':
      case 'snefru256/8':
        options = Object.assign({}, {length: 256}, options);
        return new Snefru(options);
      case 'snefru128/2':
        options = Object.assign({}, {length: 128, rounds: 2}, options);
        return new Snefru(options);
      case 'snefru256/4':
        options = Object.assign({}, {length: 256, rounds: 4}, options);
        return new Snefru(options);
      case 'blake2b':
      case 'blake2b-512':
        options = Object.assign({}, {length: 512}, options);
        return new Blake2b(options);
      case 'blake2b-384':
        options = Object.assign({}, {length: 384}, options);
        return new Blake2b(options);
      case 'blake2b-256':
        options = Object.assign({}, {length: 256}, options);
        return new Blake2b(options);
      case 'blake2b-160':
        options = Object.assign({}, {length: 160}, options);
        return new Blake2b(options);
      case 'blake2b-128':
        options = Object.assign({}, {length: 128}, options);
        return new Blake2b(options);
      case 'blake2s':
      case 'blake2s-256':
        options = Object.assign({}, {length: 256}, options);
        return new Blake2s(options);
      case 'blake2s-224':
        options = Object.assign({}, {length: 224}, options);
        return new Blake2s(options);
      case 'blake2s-160':
        options = Object.assign({}, {length: 160}, options);
        return new Blake2s(options);
      case 'blake2s-128':
        options = Object.assign({}, {length: 128}, options);
        return new Blake2s(options);
      case 'blake3':
        options = Object.assign({}, {length: 256}, options);
        return new Blake3(options);
      case 'tiger':
      case 'tiger192':
        options = Object.assign({}, {length: 192}, options);
        return new Tiger(options);
      case 'tiger160':
        options = Object.assign({}, {length: 160}, options);
        return new Tiger(options);
      case 'tiger128':
        options = Object.assign({}, {length: 128}, options);
        return new Tiger(options);
      case 'tiger2':
        options = Object.assign({}, {length: 192}, options);
        return new Tiger2(options);
      case 'streebog':
      case 'streebog512':
        options = Object.assign({}, {length: 512}, options);
        return new Streebog(options);
      case 'streebog256':
        options = Object.assign({}, {length: 256}, options);
        return new Streebog(options);
      case 'crc32':
        return new Crc32(options);
      case 'crc32c':
        return new Crc32c(options);
      case 'xxhash32':
        return new XxHash32(options);
      case 'xxhash64':
        return new XxHash64(options);
      case 'xxhash3':
        return new XxHash3(options);
      case 'xxhash128':
        return new XxHash128(options);
      case 'siphash':
      case 'siphash-2-4':
        return new SipHash(options);
      case 'siphash-1-3':
        return new SipHash13(options);
      case 'murmur3':
      case 'murmur3-x86-32':
        return new Murmur3(options);
      case 'murmur3-x64-128':
        return new Murmur3x64(options);
      case 'whirlpool':
        return new Whirlpool(options);
      case 'whirlpool-0':
        options = Object.assign({}, {type: '0'}, options);
        return new Whirlpool(options);
      case 'whirlpool-t':
        options = Object.assign({}, {type: 't'}, options);
        return new Whirlpool(options);
    }
  }

  /**
   * Hash a UTF message (or bytes) and return the result in hex
   *
   * @param {string} name
   * @param {string|ArrayBuffer|ArrayBufferView} message - a string is UTF-8 encoded
   * @param {Object} options
   * @returns {string}
   */
  hash(name, message, options) {
    options = options || {};
    let hasher = this.getHasher(name, options);
    hasher.update(utfOrBytes(message, 'message'));
    return toHex(hasher.finalize());
  }

  /**
   * Like {@link CryptoApi#hash}, but returns the digest as bytes. Not in 0.8.5.
   *
   * @param {string} name
   * @param {string|ArrayBuffer|ArrayBufferView} message - a string is UTF-8 encoded
   * @param {Object} options
   * @returns {Uint8Array}
   */
  hashBytes(name, message, options) {
    options = options || {};
    let hasher = this.getHasher(name, options);
    hasher.update(utfOrBytes(message, 'message'));
    return hasher.digest();
  }

  /**
   * Get HMAC instance
   *
   * @param {string} key
   * @param {Hasher} hasher
   * @returns {Hmac}
   */
  getHmac(key, hasher) {
    return new Hmac(key, hasher);
  }

  /**
   * HMAC with UTF key from UTF message (either may be bytes) and return result in hex
   *
   * @param {string|ArrayBuffer|ArrayBufferView} key - a string is UTF-8 encoded
   * @param {string|ArrayBuffer|ArrayBufferView} message - a string is UTF-8 encoded
   * @param {Hasher} hasher
   * @returns {string}
   */
  hmac(key, message, hasher) {
    let mac = this.getHmac(utfOrBytes(key, 'key'), hasher);
    mac.update(utfOrBytes(message, 'message'));
    return toHex(mac.finalize());
  }

  /**
   * Like {@link CryptoApi#hmac}, but returns the MAC as bytes. Not in 0.8.5.
   *
   * @param {string|ArrayBuffer|ArrayBufferView} key - a string is UTF-8 encoded
   * @param {string|ArrayBuffer|ArrayBufferView} message - a string is UTF-8 encoded
   * @param {Hasher} hasher
   * @returns {Uint8Array}
   */
  hmacBytes(key, message, hasher) {
    let mac = this.getHmac(utfOrBytes(key, 'key'), hasher);
    mac.update(utfOrBytes(message, 'message'));
    return mac.digest();
  }

  /**
   * PBKDF2 key derivation with HMAC over `hasher`, result in hex. A string password
   * or `options.salt` is UTF-8 encoded; bytes are used as they are. Not in 0.8.5.
   *
   * @param {string|ArrayBuffer|ArrayBufferView} password
   * @param {Hasher} hasher
   * @param {{iterations: number, salt: (string|ArrayBuffer|ArrayBufferView), length: number}} options -
   *   `iterations` is required, `length` is in bits
   * @returns {string}
   */
  pbkdf2(password, hasher, options) {
    return toHex(new Pbkdf2(utfOrBytes(password, 'password'), hasher, utfOptions(options, ['salt'])).finalize());
  }

  /**
   * Like {@link CryptoApi#pbkdf2}, but returns the key as bytes. Not in 0.8.5.
   *
   * @param {string|ArrayBuffer|ArrayBufferView} password
   * @param {Hasher} hasher
   * @param {{iterations: number, salt: (string|ArrayBuffer|ArrayBufferView), length: number}} options
   * @returns {Uint8Array}
   */
  pbkdf2Bytes(password, hasher, options) {
    return new Pbkdf2(utfOrBytes(password, 'password'), hasher, utfOptions(options, ['salt'])).digest();
  }

  /**
   * HKDF key derivation with HMAC over `hasher`, result in hex. A string `ikm`,
   * `options.salt` or `options.info` is UTF-8 encoded; bytes are used as they are.
   * Not in 0.8.5.
   *
   * @param {string|ArrayBuffer|ArrayBufferView} ikm - input key material
   * @param {Hasher} hasher
   * @param {{salt: (string|ArrayBuffer|ArrayBufferView), info: (string|ArrayBuffer|ArrayBufferView), length: number}} [options] -
   *   `length` is in bits
   * @returns {string}
   */
  hkdf(ikm, hasher, options) {
    return toHex(new Hkdf(utfOrBytes(ikm, 'ikm'), hasher, utfOptions(options, ['salt', 'info'])).finalize());
  }

  /**
   * Like {@link CryptoApi#hkdf}, but returns the key as bytes. Not in 0.8.5.
   *
   * @param {string|ArrayBuffer|ArrayBufferView} ikm - input key material
   * @param {Hasher} hasher
   * @param {{salt: (string|ArrayBuffer|ArrayBufferView), info: (string|ArrayBuffer|ArrayBufferView), length: number}} [options]
   * @returns {Uint8Array}
   */
  hkdfBytes(ikm, hasher, options) {
    return new Hkdf(utfOrBytes(ikm, 'ikm'), hasher, utfOptions(options, ['salt', 'info'])).digest();
  }
}

CryptoApi = new CryptoApi();
export default CryptoApi;