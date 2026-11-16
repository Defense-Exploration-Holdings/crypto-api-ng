// crypto-api-ng:facade
'use strict';

import {instantiate, wipe, STATE_OFF, OUT_OFF, INPUT_OFF} from "./family.mjs";

/*
 * The scratch-region plumbing of the "blocks" engines: the wasm `<prefix>_blocks` and
 * `<prefix>_final` exports of Tiger, Streebog, CRC-32 and xxHash (src/hash/*.zig, wrapped by
 * src/wasm/blake2_exports.zig) behind the engine interface of src/blocks/*.mjs. When
 * WebAssembly is not available (no runtime, CSP, ...) every call is answered by the
 * plain-JavaScript engine of the algorithm instead, which computes the same values.
 *
 * Scratch `State` layout, `n` = number of hash int32 words (`spec.hashInts`):
 *
 *     t: u64            at 0     bytes compressed so far (low int32 first)
 *     h: n x int32      at 8     the algorithm's words, little-endian, as `state.hash`
 *
 * 64-bit words of an algorithm are int32 pairs, low half first, in both places.
 */

const TWO32 = 4294967296;

/**
 * @param {() => Uint8Array} getBytes - the embedded wasm module
 * @param {{prefix: string, block: number, hashInts: number, digest: number, outOff?: number, stateSize?: number}} spec
 *   `prefix` of the exports, block size in bytes, number of int32 hash words, bytes of the full digest,
 *   where in the scratch region the digest is written (default: the output slot), and the size of the
 *   Zig `State` when padding follows the hash words (default: 8 + 4 * hashInts)
 * @param {{blocks: Function, final: Function}} fallback - the plain-JS engine
 */
export default function createEngine(getBytes, spec, fallback) {
  const prefix = spec.prefix;
  const block = spec.block;
  const hashInts = spec.hashInts;
  const digest = spec.digest;
  const outOff = spec.outOff === undefined ? OUT_OFF : spec.outOff;
  // The size of the Zig `State`: its words may be followed by padding.
  const stateSize = spec.stateSize === undefined ? 8 + 4 * hashInts : spec.stateSize;
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
   * pending block must be what `getState()` of one of these hashers returns.
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
    i32[w] = state.counter % TWO32;
    i32[w + 1] = Math.floor(state.counter / TWO32);
    for (let i = 0; i < hashInts; i++) {
      i32[w + 2 + i] = state.hash[i] | 0;
    }
    return w;
  }

  /**
   * Compress in wasm; false when the module refused a call (`state` is as it was). The scratch
   * region (message bytes, chaining value) is zeroed on every way out.
   */
  function wasmBlocks(r, state, message, start, end) {
    const u8 = r.u8;
    // Bytes of the input region this call wrote.
    let used = 0;
    try {
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
        if (n > used) {
          used = n;
        }
        if (run(stateAddr, inAddr, n) !== 0) {
          return false;
        }
        calls++;
      }
      for (let i = 0; i < hashInts; i++) {
        state.hash[i] = i32[w + 2 + i];
      }
      state.counter += end - start;
      return true;
    } finally {
      wipe(u8, r.base, used);
    }
  }

  /**
   * The digest in wasm, or null when the module refused the call (its output is not read). The
   * digest string is built before the scratch region (last block, chaining value, digest) is zeroed.
   */
  function wasmFinal(r, state, tail) {
    const u8 = r.u8;
    try {
      putState(r, state);
      const inAddr = r.base + INPUT_OFF;
      for (let i = 0; i < tail.length; i++) {
        u8[inAddr + i] = tail.charCodeAt(i);
      }
      if (r.ex[prefix + '_final'](r.base + STATE_OFF, inAddr, tail.length, r.base + outOff) !== 0) {
        return null;
      }
      calls++;
      let out = '';
      for (let i = 0; i < digest; i++) {
        out += String.fromCharCode(u8[r.base + outOff + i]);
      }
      return out;
    } finally {
      wipe(u8, r.base, Math.max(tail.length, outOff + digest - INPUT_OFF));
    }
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
