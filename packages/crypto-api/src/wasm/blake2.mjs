// crypto-api-ng:facade
'use strict';

import {instantiate, STATE_OFF, OUT_OFF, INPUT_OFF} from "./family.mjs";

/*
 * The scratch-region plumbing of the BLAKE2 engines: the wasm `blake2{b,s}_blocks` and
 * `blake2{b,s}_final` exports (src/hash/blake2.zig, src/wasm/blake2_exports.zig) behind the
 * engine interface of src/blake/blake2{b,s}.mjs. When WebAssembly is not available (no
 * runtime, CSP, ...) every call is answered by that plain-JavaScript engine instead, which
 * computes the same values.
 *
 * Scratch `State` layout, `n` = bytes per word (8 for BLAKE2b, 4 for BLAKE2s):
 *
 *     h: 8 x n bytes   at 0     the chaining value, little-endian, as `state.hash` (int32 pairs)
 *     t: u64           at 8n    bytes compressed so far (low int32 first)
 */

const TWO32 = 4294967296;

/**
 * @param {() => Uint8Array} getBytes - the embedded wasm module
 * @param {string} prefix - export prefix, `blake2b` or `blake2s`
 * @param {number} wordBytes - 8 or 4
 * @param {{blocks: Function, final: Function}} fallback - the plain-JS engine
 */
export default function createEngine(getBytes, prefix, wordBytes, fallback) {
  const block = 16 * wordBytes;
  const hashInts = 2 * wordBytes;
  const stateSize = 8 * wordBytes + 8;
  let tried = false;
  let rt = null;
  let i32 = null;
  let calls = 0;

  function runtime() {
    if (!tried) {
      tried = true;
      const sizes = {};
      sizes[prefix] = stateSize;
      rt = instantiate(getBytes, sizes);
      if (rt) {
        i32 = new Int32Array(rt.u8.buffer);
      }
    }
    return rt;
  }

  /**
   * Refuse a state the engines cannot work on (both of them, so that the plain-JavaScript engine
   * never accepts what the wasm module would refuse): the hash words, the byte counter and the
   * pending block must be what `getState()` of a BLAKE2 hasher returns.
   */
  function checkState(state, tail) {
    if (state === null || typeof state !== 'object') {
      throw new TypeError(prefix + ': state must be an object');
    }
    const hash = state.hash;
    if (!Array.isArray(hash) || hash.length !== hashInts) {
      throw new TypeError(prefix + ': state.hash must be an array of ' + hashInts + ' integers');
    }
    for (let i = 0; i < hashInts; i++) {
      if (!Number.isInteger(hash[i])) {
        throw new TypeError(prefix + ': state.hash must be an array of ' + hashInts + ' integers');
      }
    }
    const counter = state.counter;
    if (typeof counter !== 'number') {
      throw new TypeError(prefix + ': state.counter must be a number');
    }
    if (!Number.isSafeInteger(counter) || counter < 0 || counter % block !== 0) {
      throw new RangeError(prefix + ': state.counter must be a multiple of ' + block + ' from 0, got ' + counter);
    }
    if (tail !== undefined) {
      if (typeof tail !== 'string') {
        throw new TypeError(prefix + ': the last block must be a string');
      }
      if (tail.length > block) {
        throw new RangeError(prefix + ': the last block can be at most ' + block + ' bytes, got ' + tail.length);
      }
      if (tail.length === 0 && counter !== 0) {
        throw new RangeError(prefix + ': state has compressed blocks but no last block');
      }
      if (counter + tail.length > Number.MAX_SAFE_INTEGER) {
        throw new RangeError(prefix + ': message too long');
      }
    }
  }

  function putState(r, state) {
    const w = (r.base + STATE_OFF) >> 2;
    for (let i = 0; i < hashInts; i++) {
      i32[w + i] = state.hash[i] | 0;
    }
    i32[w + hashInts] = state.counter % TWO32;
    i32[w + hashInts + 1] = Math.floor(state.counter / TWO32);
    return w;
  }

  /** Compress in wasm; false when the module refused a call (`state` is as it was). */
  function wasmBlocks(r, state, message, start, end) {
    const u8 = r.u8;
    const w = putState(r, state);
    const stateAddr = r.base + STATE_OFF;
    const inAddr = r.base + INPUT_OFF;
    const step = Math.floor(r.cap / block) * block;
    const run = r.ex[prefix + '_blocks'];
    for (let pos = start; pos < end; pos += step) {
      const n = Math.min(step, end - pos);
      for (let i = 0; i < n; i++) {
        u8[inAddr + i] = message.charCodeAt(pos + i);
      }
      if (run(stateAddr, inAddr, n) !== 0) {
        return false;
      }
      calls++;
    }
    for (let i = 0; i < hashInts; i++) {
      state.hash[i] = i32[w + i];
    }
    state.counter += end - start;
    return true;
  }

  /** The digest in wasm, or null when the module refused the call (its output is not read). */
  function wasmFinal(r, state, tail) {
    const u8 = r.u8;
    putState(r, state);
    const inAddr = r.base + INPUT_OFF;
    for (let i = 0; i < tail.length; i++) {
      u8[inAddr + i] = tail.charCodeAt(i);
    }
    if (r.ex[prefix + '_final'](r.base + STATE_OFF, inAddr, tail.length, r.base + OUT_OFF) !== 0) {
      return null;
    }
    calls++;
    let out = '';
    for (let i = 0; i < 8 * wordBytes; i++) {
      out += String.fromCharCode(u8[r.base + OUT_OFF + i]);
    }
    return out;
  }

  return {
    name: 'wasm',

    /**
     * Compress the whole blocks `message[start, end)`; updates `state.hash` and `state.counter`.
     * @throws {TypeError} for a state of the wrong shape
     * @throws {RangeError} for a range that is not whole blocks of `message`, or a counter out of range
     */
    blocks(state, message, start, end) {
      checkState(state);
      if (typeof message !== 'string') {
        throw new TypeError(prefix + ': the message must be a string');
      }
      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end > message.length ||
        (end - start) % block !== 0) {
        throw new RangeError(prefix + ': blocks must be whole blocks of the message');
      }
      if (state.counter + (end - start) > Number.MAX_SAFE_INTEGER) {
        throw new RangeError(prefix + ': message too long');
      }
      const r = runtime();
      // A refused call leaves `state` untouched; the plain-JavaScript engine then does the whole range.
      if (r === null || !wasmBlocks(r, state, message, start, end)) {
        fallback.blocks(state, message, start, end);
      }
    },

    /**
     * The full digest of the last block `tail` (1..block bytes, or none for an empty message); `state` is not modified.
     * @throws {TypeError} for a state of the wrong shape
     * @throws {RangeError} for a tail of the wrong length
     */
    final(state, tail) {
      checkState(state, tail);
      const r = runtime();
      const out = r === null ? null : wasmFinal(r, state, tail);
      return out !== null ? out : fallback.final(state, tail);
    },

    /** Test-only hooks; not public API. */
    hooks() {
      return {
        /** Number of calls that ran in wasm so far. */
        wasmCalls: () => calls,
        /** The instantiated wasm runtime, or null. */
        runtime: () => runtime(),
        /** Forget the cached runtime; with `disable`, behave as if WebAssembly failed. */
        reset: (disable) => {
          tried = !!disable;
          rt = null;
          i32 = null;
        },
        /** The plain-JavaScript engine. */
        fallback: fallback
      };
    }
  };
}
