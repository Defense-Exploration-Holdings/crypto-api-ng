// crypto-api-ng:facade
'use strict';

import {instantiate, STATE_OFF, OUT_OFF, INPUT_OFF} from "./family.mjs";

/*
 * The scratch-region plumbing of the BLAKE3 engine: the wasm `blake3_update`, `blake3_root`
 * and `blake3_xof` exports (src/hash/blake3.zig, src/wasm/blake3.zig) behind the engine
 * interface of src/blake/blake3.mjs, which answers every call when WebAssembly is not
 * available.
 *
 * Scratch layout. The stack of subtree chaining values (54 x 32 bytes at most) does not fit
 * the 128-byte state slot, so it takes the head of the input region:
 *
 *     State (src/hash/blake3.zig)   at 0     key[8], flags, reserved, chunks (u64)
 *     RootParams                    at 128   cv[8], block[64], blockLen, flags  (104 bytes)
 *     stack                         at 256   up to 54 x 8 words, 1728 bytes
 *     data                          at 2304  whole chunks in, output bytes out
 */

const TWO32 = 4294967296;
const CHUNK = 1024;
const STACK_OFF = INPUT_OFF;
const DATA_OFF = INPUT_OFF + 2048;
const MAX_CHUNKS = 9007199254740992; // 2^53, the limit the wasm side enforces
// Index of the fields of State, as int32.
const FLAGS = 8;
const CHUNKS = 10;

function popcount(n) {
  let c = 0;
  while (n > 0) {
    c += n % 2;
    n = Math.floor(n / 2);
  }
  return c;
}

/**
 * @param {() => Uint8Array} getBytes - the embedded wasm module
 * @param {{update: Function, finalize: Function}} fallback - the plain-JS engine
 */
export default function createEngine(getBytes, fallback) {
  let tried = false;
  let rt = null;
  let i32 = null;
  let calls = 0;

  function runtime() {
    if (!tried) {
      tried = true;
      rt = instantiate(getBytes, {blake3: 48});
      if (rt) {
        i32 = new Int32Array(rt.u8.buffer);
      }
    }
    return rt;
  }

  /** The wasm runtime if `state` has the shape the wasm code models, else null. */
  function usable(state) {
    const r = runtime();
    if (r === null || !Number.isSafeInteger(state.chunks) || state.chunks < 0 ||
      state.chunks + 1024 > MAX_CHUNKS || !Array.isArray(state.stack) ||
      state.stack.length !== 8 * popcount(state.chunks)) {
      return null;
    }
    return r;
  }

  /** Copy the State and the stack into scratch memory. */
  function putState(r, state, init) {
    const w = (r.base + STATE_OFF) >> 2;
    for (let i = 0; i < 8; i++) {
      i32[w + i] = init.key[i] | 0;
    }
    i32[w + FLAGS] = init.flags;
    i32[w + FLAGS + 1] = 0;
    i32[w + CHUNKS] = state.chunks % TWO32;
    i32[w + CHUNKS + 1] = Math.floor(state.chunks / TWO32);
    const s = (r.base + STACK_OFF) >> 2;
    for (let i = 0; i < state.stack.length; i++) {
      i32[s + i] = state.stack[i] | 0;
    }
    return w;
  }

  return {
    name: 'wasm',

    /** Add the first `nchunks` whole chunks of `message` to the tree in `state`. */
    update(state, init, message, nchunks) {
      const r = usable(state);
      if (r === null) {
        return fallback.update(state, init, message, nchunks);
      }
      const u8 = r.u8;
      const w = putState(r, state, init);
      const dataAddr = r.base + DATA_OFF;
      const perCall = Math.floor((r.cap - (DATA_OFF - INPUT_OFF)) / CHUNK);
      const run = r.ex.blake3_update;
      for (let done = 0; done < nchunks; done += perCall) {
        const n = Math.min(perCall, nchunks - done);
        const from = done * CHUNK;
        for (let i = 0; i < n * CHUNK; i++) {
          u8[dataAddr + i] = message.charCodeAt(from + i);
        }
        run(r.base + STATE_OFF, r.base + STACK_OFF, dataAddr, n);
        calls++;
      }
      state.chunks = (i32[w + CHUNKS] >>> 0) + (i32[w + CHUNKS + 1] >>> 0) * TWO32;
      const s = (r.base + STACK_OFF) >> 2;
      state.stack = [];
      for (let i = 0; i < 8 * popcount(state.chunks); i++) {
        state.stack.push(i32[s + i]);
      }
    },

    /** The first `bytes` output bytes of the hash whose last chunk is `tail`; `state` is not modified. */
    finalize(state, init, tail, bytes) {
      const r = usable(state);
      if (r === null || tail.length > CHUNK) {
        return fallback.finalize(state, init, tail, bytes);
      }
      const u8 = r.u8;
      putState(r, state, init);
      const dataAddr = r.base + DATA_OFF;
      const paramsAddr = r.base + OUT_OFF;
      for (let i = 0; i < tail.length; i++) {
        u8[dataAddr + i] = tail.charCodeAt(i);
      }
      r.ex.blake3_root(r.base + STATE_OFF, r.base + STACK_OFF, dataAddr, tail.length, paramsAddr);
      calls++;
      // The tail is no longer needed: the output overwrites it.
      const perCall = Math.floor((r.cap - (DATA_OFF - INPUT_OFF)) / 64) * 64;
      let out = '';
      for (let pos = 0; pos < bytes; pos += perCall) {
        const n = Math.min(perCall, bytes - pos);
        r.ex.blake3_xof(paramsAddr, pos / 64, dataAddr, n);
        calls++;
        for (let i = 0; i < n; i += 8192) {
          out += String.fromCharCode.apply(null, u8.subarray(dataAddr + i, dataAddr + Math.min(i + 8192, n)));
        }
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
