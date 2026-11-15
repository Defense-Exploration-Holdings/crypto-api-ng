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

  /** The wasm runtime if `state` has the shape the wasm code models, else null. */
  function usable(state) {
    const r = runtime();
    if (r === null || !Array.isArray(state.hash) || state.hash.length !== hashInts ||
      !Number.isSafeInteger(state.counter) || state.counter < 0) {
      return null;
    }
    return r;
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

  return {
    name: 'wasm',

    /** Compress the whole blocks `message[start, end)`; updates `state.hash` and `state.counter`. */
    blocks(state, message, start, end) {
      const r = usable(state);
      if (r === null) {
        return fallback.blocks(state, message, start, end);
      }
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
        run(stateAddr, inAddr, n);
        calls++;
      }
      for (let i = 0; i < hashInts; i++) {
        state.hash[i] = i32[w + i];
      }
      state.counter += end - start;
    },

    /** The full digest of the last block `tail` (0..block bytes); `state` is not modified. */
    final(state, tail) {
      const r = usable(state);
      if (r === null || tail.length > block) {
        return fallback.final(state, tail);
      }
      const u8 = r.u8;
      putState(r, state);
      const inAddr = r.base + INPUT_OFF;
      for (let i = 0; i < tail.length; i++) {
        u8[inAddr + i] = tail.charCodeAt(i);
      }
      r.ex[prefix + '_final'](r.base + STATE_OFF, inAddr, tail.length, r.base + OUT_OFF);
      calls++;
      let out = '';
      for (let i = 0; i < 8 * wordBytes; i++) {
        out += String.fromCharCode(u8[r.base + OUT_OFF + i]);
      }
      return out;
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
