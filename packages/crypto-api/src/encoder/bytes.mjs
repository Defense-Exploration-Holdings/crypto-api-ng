// crypto-api-ng:facade
'use strict';

/*
 * Encoders between bytes (`Uint8Array`) and text: UTF-8, hex and base64.
 *
 * The encoders of crypto-api 0.8.5 (`fromUtf`, `toHex`, `toBase64`) work on
 * binary strings, one character per byte. These work on bytes, so a program
 * that passes `Uint8Array` to `update()` and gets `Uint8Array` from `digest()`
 * never needs a binary string.
 */

const hasOwn = Object.prototype.hasOwnProperty;
const toString = Object.prototype.toString;
const CHUNK = 8192;

const HEX = [];
for (let i = 0; i < 256; i++) {
  HEX.push((i < 16 ? '0' : '') + i.toString(16));
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function describe(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  return typeof value === 'object' ? toString.call(value).slice(8, -1) : typeof value;
}

/**
 * The bytes of an `ArrayBuffer`, `SharedArrayBuffer` or any view of one, as a
 * `Uint8Array` over the same memory (no copy).
 *
 * @ignore
 * @param {*} value
 * @param {string} what - name used in error messages
 * @returns {Uint8Array}
 * @throws {TypeError} for anything else, including strings
 */
function viewBytes(value, what) {
  if (value !== null && typeof value === 'object') {
    const tag = toString.call(value);
    if (tag === '[object ArrayBuffer]' || tag === '[object SharedArrayBuffer]') {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
  }
  throw new TypeError(what + ' must be an ArrayBuffer or an ArrayBuffer view such as a Uint8Array, got ' + describe(value));
}

/**
 * An option that is an own property of `options`, else `undefined`: a value
 * inherited through the prototype chain is never an option.
 *
 * @ignore
 */
function ownOption(options, key) {
  return hasOwn.call(options, key) ? options[key] : undefined;
}

/**
 * @ignore
 * @param {*} options
 * @param {string} name - function name for error messages
 * @returns {Object}
 */
function checkedOptions(options, name) {
  if (options === undefined) return {};
  if (options === null || typeof options !== 'object') {
    throw new TypeError(name + ': options must be an object, got ' + describe(options));
  }
  return options;
}

// ---- UTF-8 ------------------------------------------------------------------

function encodeUtf8Fallback(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    let c = text.charCodeAt(i);
    if (c >= 0xd800 && c < 0xe000) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (c < 0xdc00 && next >= 0xdc00 && next < 0xe000) {
        c = 0x10000 + ((c & 0x3ff) << 10) + (next & 0x3ff);
        i++;
      } else {
        c = 0xfffd; // an unpaired surrogate is not text
      }
    }
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c < 0x10000) {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return Uint8Array.from(out);
}

// The decoding algorithm of the WHATWG Encoding Standard: a byte that cannot
// continue a sequence ends it with one U+FFFD and is read again.
function decodeUtf8Fallback(bytes, fatal) {
  const units = [];
  let text = '';
  let needed = 0;
  let seen = 0;
  let point = 0;
  let lower = 0x80;
  let upper = 0xbf;
  const fail = function () {
    if (fatal) throw new TypeError('The data is not valid UTF-8');
    units.push(0xfffd);
  };
  const emit = function (cp) {
    if (cp >= 0x10000) {
      cp -= 0x10000;
      units.push(0xd800 | (cp >> 10), 0xdc00 | (cp & 0x3ff));
    } else {
      units.push(cp);
    }
    if (units.length >= CHUNK) {
      text += String.fromCharCode.apply(null, units);
      units.length = 0;
    }
  };
  for (let i = 0; i < bytes.length;) {
    const b = bytes[i];
    if (needed === 0) {
      i++;
      if (b <= 0x7f) {
        emit(b);
      } else if (b >= 0xc2 && b <= 0xdf) {
        needed = 1;
        point = b & 0x1f;
      } else if (b >= 0xe0 && b <= 0xef) {
        if (b === 0xe0) lower = 0xa0;
        if (b === 0xed) upper = 0x9f;
        needed = 2;
        point = b & 0xf;
      } else if (b >= 0xf0 && b <= 0xf4) {
        if (b === 0xf0) lower = 0x90;
        if (b === 0xf4) upper = 0x8f;
        needed = 3;
        point = b & 0x7;
      } else {
        fail();
      }
    } else if (b < lower || b > upper) {
      needed = seen = point = 0;
      lower = 0x80;
      upper = 0xbf;
      fail();
    } else {
      lower = 0x80;
      upper = 0xbf;
      point = (point << 6) | (b & 0x3f);
      i++;
      if (++seen === needed) {
        emit(point);
        needed = seen = point = 0;
      }
    }
  }
  if (needed !== 0) fail();
  return text + String.fromCharCode.apply(null, units);
}

/**
 * Encode text as UTF-8. An unpaired surrogate becomes U+FFFD (EF BF BD), as
 * `TextEncoder` does.
 *
 * @param {string} text
 * @returns {Uint8Array}
 * @throws {TypeError} when `text` is not a string
 */
export function utf8ToBytes(text) {
  if (typeof text !== 'string') {
    throw new TypeError('text must be a string, got ' + describe(text));
  }
  return typeof TextEncoder === 'function' ? new TextEncoder().encode(text) : encodeUtf8Fallback(text);
}

/**
 * Decode UTF-8 bytes to text. A leading byte order mark is kept (as U+FEFF),
 * and invalid bytes become U+FFFD unless `options.fatal` is true.
 *
 * @param {ArrayBuffer|ArrayBufferView} bytes
 * @param {{fatal: boolean}} [options] - `fatal`: throw `TypeError` instead of substituting U+FFFD
 * @returns {string}
 * @throws {TypeError} when `bytes` is not bytes, or is invalid UTF-8 with `fatal`
 */
export function bytesToUtf8(bytes, options) {
  const view = viewBytes(bytes, 'bytes');
  const fatal = !!ownOption(checkedOptions(options, 'bytesToUtf8'), 'fatal');
  if (typeof TextDecoder === 'function') {
    // TextDecoder rejects views of shared memory in some engines
    const own = toString.call(view.buffer) === '[object SharedArrayBuffer]' ? new Uint8Array(view) : view;
    return new TextDecoder('utf-8', {fatal: fatal, ignoreBOM: true}).decode(own);
  }
  return decodeUtf8Fallback(view, fatal);
}

// ---- hex --------------------------------------------------------------------

/**
 * Bytes to lowercase hex.
 *
 * @param {ArrayBuffer|ArrayBufferView} bytes
 * @returns {string}
 * @throws {TypeError} when `bytes` is not bytes
 */
export function bytesToHex(bytes) {
  const view = viewBytes(bytes, 'bytes');
  let str = '';
  for (let i = 0; i < view.length; i++) {
    str += HEX[view[i]];
  }
  return str;
}

function hexDigit(code) {
  if (code >= 48 && code <= 57) return code - 48;       // 0-9
  if (code >= 97 && code <= 102) return code - 87;      // a-f
  if (code >= 65 && code <= 70) return code - 55;       // A-F
  return -1;
}

/**
 * Hex (upper or lower case, no separators or prefix) to bytes.
 *
 * @param {string} hex
 * @returns {Uint8Array}
 * @throws {TypeError} when `hex` is not a string
 * @throws {SyntaxError} for an odd length or a character that is not a hex digit
 */
export function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hex must be a string, got ' + describe(hex));
  }
  if (hex.length % 2 !== 0) {
    throw new SyntaxError('hex has an odd number of digits');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexDigit(hex.charCodeAt(2 * i));
    const lo = hexDigit(hex.charCodeAt(2 * i + 1));
    if (hi < 0 || lo < 0) {
      throw new SyntaxError('hex has a character that is not a hex digit at index ' + (hi < 0 ? 2 * i : 2 * i + 1));
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

// ---- base64 -----------------------------------------------------------------

function alphabetOf(options, name) {
  const alphabet = ownOption(options, 'alphabet');
  if (alphabet === undefined || alphabet === 'base64') return BASE64;
  if (alphabet === 'base64url') return BASE64URL;
  throw new TypeError(name + ': alphabet must be "base64" or "base64url", got ' + describe(alphabet));
}

/**
 * Bytes to base64 (RFC 4648), with padding unless `omitPadding` is set.
 *
 * @param {ArrayBuffer|ArrayBufferView} bytes
 * @param {{alphabet: ('base64'|'base64url'), omitPadding: boolean}} [options] -
 *   `alphabet` defaults to `'base64'` (`+` and `/`); `'base64url'` uses `-` and `_`
 * @returns {string}
 * @throws {TypeError} when `bytes` is not bytes, or `alphabet` is not one of the two names
 */
export function bytesToBase64(bytes, options) {
  const view = viewBytes(bytes, 'bytes');
  options = checkedOptions(options, 'bytesToBase64');
  const chars = alphabetOf(options, 'bytesToBase64');
  const pad = !ownOption(options, 'omitPadding');
  let str = '';
  const whole = view.length - view.length % 3;
  for (let i = 0; i < whole; i += 3) {
    const n = (view[i] << 16) | (view[i + 1] << 8) | view[i + 2];
    str += chars.charAt(n >> 18) + chars.charAt((n >> 12) & 0x3f) + chars.charAt((n >> 6) & 0x3f) + chars.charAt(n & 0x3f);
  }
  const rest = view.length - whole;
  if (rest === 1) {
    const n = view[whole] << 16;
    str += chars.charAt(n >> 18) + chars.charAt((n >> 12) & 0x3f) + (pad ? '==' : '');
  } else if (rest === 2) {
    const n = (view[whole] << 16) | (view[whole + 1] << 8);
    str += chars.charAt(n >> 18) + chars.charAt((n >> 12) & 0x3f) + chars.charAt((n >> 6) & 0x3f) + (pad ? '=' : '');
  }
  return str;
}

/**
 * Base64 (RFC 4648) to bytes. Padding is optional, but if present it must be
 * right; ASCII whitespace is ignored; the unused bits of the last character
 * must be zero, so every byte string has one text.
 *
 * @param {string} text
 * @param {{alphabet: ('base64'|'base64url')}} [options] - `alphabet` defaults to `'base64'`
 * @returns {Uint8Array}
 * @throws {TypeError} when `text` is not a string, or `alphabet` is not one of the two names
 * @throws {SyntaxError} for a character outside the alphabet, wrong padding or a length no byte string encodes to
 */
export function base64ToBytes(text, options) {
  if (typeof text !== 'string') {
    throw new TypeError('text must be a string, got ' + describe(text));
  }
  options = checkedOptions(options, 'base64ToBytes');
  const chars = alphabetOf(options, 'base64ToBytes');
  const values = new Uint8Array(text.length);
  let count = 0;
  let padding = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 12 || c === 13) continue;
    if (c === 61) { // '='
      padding++;
      continue;
    }
    const v = padding === 0 && c < 128 ? chars.indexOf(text.charAt(i)) : -1;
    if (v < 0) {
      throw new SyntaxError(padding === 0 ?
        'base64 has a character outside the alphabet at index ' + i :
        'base64 has data after the padding at index ' + i);
    }
    values[count++] = v;
  }
  const rest = count % 4;
  if (rest === 1) {
    throw new SyntaxError('base64 has a length no byte string encodes to');
  }
  if (padding !== 0 && padding !== (4 - rest) % 4) {
    throw new SyntaxError('base64 has wrong padding');
  }
  if ((rest === 2 && (values[count - 1] & 0x0f) !== 0) || (rest === 3 && (values[count - 1] & 0x03) !== 0)) {
    throw new SyntaxError('base64 has non-zero bits after the last byte');
  }
  const out = new Uint8Array(Math.floor(count * 6 / 8));
  let o = 0;
  for (let i = 0; i < count; i += 4) {
    const n = (values[i] << 18) | (values[i + 1] << 12) | (values[i + 2] << 6) | values[i + 3];
    out[o++] = n >> 16;
    if (o < out.length) out[o++] = (n >> 8) & 0xff;
    if (o < out.length) out[o++] = n & 0xff;
  }
  return out;
}
