// crypto-api-ng:facade
'use strict';

/**
 * Synchronous instantiation of one family wasm module (see docs/abi.md).
 *
 * Returns `null` instead of throwing when WebAssembly is unavailable or the
 * module cannot be compiled (CSP without 'wasm-unsafe-eval', Cloudflare
 * Workers, IE11, ...). Callers then use the legacy JS engine. The result is
 * meant to be cached by the caller, so a failure is paid for once.
 *
 * Must stay equal to `runtime.abi_version` in src/runtime.zig (a test checks).
 */
export const ABI_VERSION = 2;

/** Scratch layout, identical for every family (src/wasm/common.zig). */
export const STATE_OFF = 0;
export const OUT_OFF = 128;
export const INPUT_OFF = 256;

/**
 * Zero what a call left in the scratch region: the state and output slots and
 * the first `used` bytes of the input chunk. Facades call this on every way out
 * of a wasm call (including the fallbacks that hand back to the original code),
 * so message bytes, key-derived hash words and digests do not stay in wasm
 * memory until the next call.
 *
 * @param {Uint8Array} u8 - all of linear memory
 * @param {number} base - `rt.base`
 * @param {number} used - bytes of the input region that were written
 */
export function wipe(u8, base, used) {
  u8.fill(0, base, base + INPUT_OFF + used);
}

/**
 * @param {() => Uint8Array} getBytes - returns the embedded wasm bytes
 * @param {Object<string, number>} stateSizes - expected `<algo>_state_size()` values
 * @returns {null | {ex: Object, u8: Uint8Array, base: number, cap: number}}
 *   `u8` views all of linear memory (it never grows), `base` is the scratch
 *   address, `cap` the input chunk capacity in bytes.
 */
export function instantiate(getBytes, stateSizes) {
  try {
    const instance = new WebAssembly.Instance(new WebAssembly.Module(getBytes()), {});
    const ex = instance.exports;
    if (ex.abi_version() !== ABI_VERSION) return null;
    for (const name in stateSizes) {
      if (ex[name + '_state_size']() !== stateSizes[name]) return null;
    }
    return {
      ex,
      u8: new Uint8Array(ex.memory.buffer),
      base: ex.scratch_ptr(),
      cap: ex.scratch_len() - INPUT_OFF
    };
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Copying a message into wasm memory
// ---------------------------------------------------------------------------
//
// The block loops of every family read their message through these helpers, so
// that the same loop serves a binary string (`state.message`) and the bytes an
// `update()` call was given (src/tools/direct.mjs).

const WIDE = /[^\x00-\xff]/;
const CHUNK = 8192;
const encoder = typeof TextEncoder === 'function' ? new TextEncoder() : null;
const canEncodeInto = encoder !== null && typeof encoder.encodeInto === 'function';
// Node and Bun: Buffer#write(..., 'latin1') copies a binary string at memory speed.
// Read as a property so that bundlers do not pull in a Buffer shim for browsers.
const NodeBuffer = typeof globalThis === 'object' && globalThis !== null &&
  typeof globalThis.Buffer === 'function' && typeof globalThis.Buffer.from === 'function' &&
  typeof globalThis.Buffer.prototype.write === 'function' ? globalThis.Buffer : null;
let latin1Memory = null;
let latin1View = null;

/** A Buffer over all of `u8`'s memory, or null. Linear memory never grows, so the view is kept. */
function latin1Target(u8) {
  if (NodeBuffer === null) return null;
  if (latin1Memory !== u8.buffer) {
    try {
      latin1View = NodeBuffer.from(u8.buffer, 0, u8.buffer.byteLength);
      latin1Memory = u8.buffer;
    } catch (e) {
      return null;
    }
  }
  return latin1View;
}

/**
 * Copy `message[from, to)` to `u8[at, at + to - from)`.
 *
 * `message` is a binary string or a Uint8Array. A code unit above 0xFF is
 * written as its low byte. The result is 0, or the bitwise OR of the code units
 * of a string range: above 0xFF means the range has a code unit that is not a
 * byte (callers then hand the message back to the original code, as before).
 *
 * @param {Uint8Array} u8 - all of linear memory
 * @param {number} at
 * @param {string|Uint8Array} message
 * @param {number} from
 * @param {number} to
 * @returns {number}
 */
export function copyIn(u8, at, message, from, to) {
  const n = to - from;
  if (n <= 0) return 0;
  if (typeof message !== 'string') {
    u8.set(from === 0 && to === message.length ? message : message.subarray(from, to), at);
    return 0;
  }
  if (n >= 64) {
    const part = from === 0 && to === message.length ? message : message.substring(from, to);
    // ASCII text: UTF-8 is the same bytes, and encodeInto() is a bulk copy.
    if (canEncodeInto) {
      const r = encoder.encodeInto(part, u8.subarray(at, at + n));
      if (r.read === n && r.written === n) return 0;
    }
    const target = latin1Target(u8);
    if (target !== null && !WIDE.test(part)) {
      target.write(part, at, n, 'latin1');
      return 0;
    }
  }
  let bits = 0;
  for (let i = from, o = at; i < to; i++, o++) {
    const c = message.charCodeAt(i);
    bits |= c;
    u8[o] = c;
  }
  return bits;
}

/**
 * `message[from, to)` as a binary string. `to` defaults to the end.
 *
 * @param {string|Uint8Array} message
 * @param {number} from
 * @param {number} [to]
 * @returns {string}
 */
export function binaryOf(message, from, to) {
  if (to === undefined) to = message.length;
  if (typeof message === 'string') return message.substring(from, to);
  let s = '';
  for (let i = from; i < to; i += CHUNK) {
    s += String.fromCharCode.apply(null, message.subarray(i, Math.min(i + CHUNK, to)));
  }
  return s;
}
