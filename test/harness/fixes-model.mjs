// Reference model of 1.1 behavior, built on the untouched original.
//
// 1.1 differs from crypto-api 0.8.5 in a few documented ways (see the package
// CHANGELOG). Everything else must stay identical. This model is the original's
// classes plus exactly those changes, written independently of the package
// code, so the differential fuzzer can compare the target against "0.8.5 with
// the 1.1 fixes" instead of against 0.8.5 itself:
//
//   1. update() takes binary strings (code units 0x00-0xFF) and bytes
//      (ArrayBuffer, SharedArrayBuffer, any ArrayBuffer view); anything else,
//      including a string with a code unit above 0xFF, throws TypeError and
//      leaves the state untouched.
//   2. The length field is the 64-bit bit count (computed here with BigInt).
//   3. rounds/length outside OPTION_RULES throw at construction: TypeError for a
//      non-number, RangeError for a number. The options object is untouched.
//   4. fromUtf() encodes a UTF-16 code unit in 0xD800..0xDFFF that is not part of
//      a valid high+low pair as U+FFFD (`ef bf bd`) and does not consume the next
//      unit, like TextEncoder. Valid pairs and everything else are unchanged.
//
// Thrown errors are compared by class only (see `diffRuns(..., {loose: true})`),
// because the model does not reproduce the package's messages.
import { FAMILIES, OPTION_RULES } from './catalog.mjs';

/** Families whose 8-byte length field is little-endian (Hasher32le). */
const LITTLE_ENDIAN = new Set(['has160', 'md4', 'md5', 'ripemd']);

function modelBinary(input) {
  if (typeof input === 'string') {
    for (let i = 0; i < input.length; i++) {
      if (input.charCodeAt(i) > 0xff) throw new TypeError('wide');
    }
    return input;
  }
  let bytes = null;
  if (input instanceof ArrayBuffer || (typeof SharedArrayBuffer !== 'undefined' && input instanceof SharedArrayBuffer)) {
    bytes = new Uint8Array(input);
  } else if (ArrayBuffer.isView(input)) {
    bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (bytes === null) throw new TypeError('not bytes');
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function modelCheck(familyId, options) {
  if (options === null || typeof options !== 'object') return;
  const rules = OPTION_RULES[familyId];
  for (const key of Object.keys(rules)) {
    const v = options[key];
    if (v === undefined) continue;
    if (typeof v !== 'number') throw new TypeError(key);
    if (!rules[key].includes(v)) throw new RangeError(key);
  }
}

/**
 * `fromUtf()` as 1.1 defines it, written from the rule alone (no code shared with
 * the package; strings only): walk the string by code point, where a lone surrogate is its own
 * "code point", and replace each of those with U+FFFD.
 */
export function modelFromUtf(message) {
  let out = '';
  for (const ch of message) {
    let cp = ch.codePointAt(0);
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
    if (cp < 0x80) out += String.fromCharCode(cp);
    else if (cp < 0x800) out += String.fromCharCode(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) out += String.fromCharCode(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else out += String.fromCharCode(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return out;
}

/** The 8 length-field bytes for a byte count, as the 1.1 spec defines them. */
export function lengthFieldBytes(length, littleEndian) {
  // Real byte counts are non-negative integers below 2^53. For anything else a
  // `setState()` can produce, the field is the bit count of floor(length),
  // modulo 2^64 (zero when it is not finite).
  const bits = Number.isFinite(length) ? BigInt.asUintN(64, BigInt(Math.floor(length)) * 8n) : 0n;
  const out = [];
  for (let i = 7; i >= 0; i--) out.push(Number((bits >> BigInt(8 * i)) & 0xffn));
  return littleEndian ? out.reverse() : out;
}

/**
 * Wrap an API tree (the oracle) into the fixes model. The result has the same
 * shape as `loadTree()` gives; only the hasher classes differ.
 */
export function fixesModel(api) {
  const hashers = {};
  for (const family of FAMILIES) {
    const Base = api.hashers[family.className];
    const le = LITTLE_ENDIAN.has(family.id);
    const hasLengthField = family.lengthFieldBytes > 0 || family.id === 'snefru';
    const Model = class extends Base {
      constructor(options) {
        modelCheck(family.id, options);
        super(options);
      }

      update(message) {
        super.update(modelBinary(message));
      }
    };
    if (hasLengthField) {
      Model.prototype.addLengthBits = function addLengthBits() {
        const len = this.state.length;
        // Non-numbers (only reachable through setState) keep the original code.
        if (typeof len !== 'number') return Base.prototype.addLengthBits.call(this);
        this.state.message += String.fromCharCode(...lengthFieldBytes(len, le));
      };
    }
    Object.defineProperty(Model, 'name', { value: family.className });
    hashers[family.className] = Model;
  }
  return { ...api, label: `${api.label}+fixes`, hashers, fromUtf: (m) => (typeof m === 'string' ? modelFromUtf(m) : api.fromUtf(m)) };
}
