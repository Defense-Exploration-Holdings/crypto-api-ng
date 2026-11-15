// crypto-api-ng:facade
'use strict';

import {instantiate, wipe, STATE_OFF, OUT_OFF, INPUT_OFF} from "./family.mjs";

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
const MAX_CHUNKS = 9007199254740992; // 2^53, the limit the wasm side enforces (`chunks` stays below it)
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

  /**
   * Refuse a tree state or key setup the engines cannot work on (both engines, so that the
   * plain-JavaScript one never accepts what the wasm module would refuse): `chunks` below the
   * limit, `stack` the chaining values of `popcount(chunks)` subtrees, `init` eight key words
   * and the flags.
   */
  function checkState(state, init) {
    if (state === null || typeof state !== 'object') {
      throw new TypeError('Blake3: state must be an object');
    }
    const chunks = state.chunks;
    if (typeof chunks !== 'number') {
      throw new TypeError('Blake3: state.chunks must be a number');
    }
    if (!Number.isSafeInteger(chunks) || chunks < 0 || chunks >= MAX_CHUNKS) {
      throw new RangeError('Blake3: state.chunks must be an integer from 0 to 2^53 - 1, got ' + chunks);
    }
    const stack = state.stack;
    const words = 8 * popcount(chunks);
    if (!Array.isArray(stack) || stack.length !== words) {
      throw new TypeError('Blake3: state.stack must be an array of ' + words + ' integers for ' + chunks + ' chunks');
    }
    for (let i = 0; i < words; i++) {
      if (!Number.isInteger(stack[i])) {
        throw new TypeError('Blake3: state.stack must be an array of ' + words + ' integers for ' + chunks + ' chunks');
      }
    }
    if (init === null || typeof init !== 'object' || !Array.isArray(init.key) || init.key.length !== 8 ||
      !Number.isInteger(init.flags)) {
      throw new TypeError('Blake3: the key words must be an array of 8 integers and the flags an integer');
    }
    for (let i = 0; i < 8; i++) {
      if (!Number.isInteger(init.key[i])) {
        throw new TypeError('Blake3: the key words must be an array of 8 integers and the flags an integer');
      }
    }
  }

  /**
   * Zero what a call left in scratch memory: the State and root parameters, the first `stackBytes`
   * of the stack region and the first `dataBytes` of the data region (the rest of the stack region is never written).
   */
  function wipeScratch(r, stackBytes, dataBytes) {
    wipe(r.u8, r.base, stackBytes);
    r.u8.fill(0, r.base + DATA_OFF, r.base + DATA_OFF + dataBytes);
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

  /**
   * Add the chunks in wasm; false when the module refused a call (`state` is as it was). The
   * scratch region (key words, stack of chaining values, message bytes) is zeroed on every way out.
   */
  function wasmUpdate(r, state, init, message, nchunks) {
    const u8 = r.u8;
    // Bytes of the stack and of the data region this call wrote.
    let stackBytes = 0;
    let dataBytes = 0;
    try {
      const w = putState(r, state, init);
      stackBytes = 4 * state.stack.length;
      const dataAddr = r.base + DATA_OFF;
      const perCall = Math.floor((r.cap - (DATA_OFF - INPUT_OFF)) / CHUNK);
      const run = r.ex.blake3_update;
      for (let done = 0; done < nchunks; done += perCall) {
        const n = Math.min(perCall, nchunks - done);
        const from = done * CHUNK;
        for (let i = 0; i < n * CHUNK; i++) {
          u8[dataAddr + i] = message.charCodeAt(from + i);
        }
        dataBytes = Math.max(dataBytes, n * CHUNK);
        if (run(r.base + STATE_OFF, r.base + STACK_OFF, dataAddr, n) !== 0) {
          return false;
        }
        calls++;
      }
      const chunks = (i32[w + CHUNKS] >>> 0) + (i32[w + CHUNKS + 1] >>> 0) * TWO32;
      const s = (r.base + STACK_OFF) >> 2;
      const stack = [];
      for (let i = 0; i < 8 * popcount(chunks); i++) {
        stack.push(i32[s + i]);
      }
      stackBytes = Math.max(stackBytes, 4 * stack.length);
      state.chunks = chunks;
      state.stack = stack;
      return true;
    } finally {
      wipeScratch(r, stackBytes, dataBytes);
    }
  }

  /**
   * The output in wasm, or null when the module refused a call: the root parameters are
   * only used after `blake3_root` succeeded in this call, and the output region of a
   * refused call is not read. The output string is built before the scratch region (key
   * words, stack, root parameters, last chunk, output) is zeroed, on every way out.
   */
  function wasmFinalize(r, state, init, tail, bytes) {
    const u8 = r.u8;
    // Bytes of the stack and of the data region (the tail, then the output) this call wrote.
    let stackBytes = 0;
    let dataBytes = 0;
    try {
      putState(r, state, init);
      stackBytes = 4 * state.stack.length;
      const dataAddr = r.base + DATA_OFF;
      const paramsAddr = r.base + OUT_OFF;
      for (let i = 0; i < tail.length; i++) {
        u8[dataAddr + i] = tail.charCodeAt(i);
      }
      dataBytes = tail.length;
      if (r.ex.blake3_root(r.base + STATE_OFF, r.base + STACK_OFF, dataAddr, tail.length, paramsAddr) !== 0) {
        return null;
      }
      calls++;
      // The tail is no longer needed: the output overwrites it.
      const perCall = Math.floor((r.cap - (DATA_OFF - INPUT_OFF)) / 64) * 64;
      let out = '';
      for (let pos = 0; pos < bytes; pos += perCall) {
        const n = Math.min(perCall, bytes - pos);
        dataBytes = Math.max(dataBytes, n);
        if (r.ex.blake3_xof(paramsAddr, pos / 64, dataAddr, n) !== 0) {
          return null;
        }
        calls++;
        for (let i = 0; i < n; i += 8192) {
          out += String.fromCharCode.apply(null, u8.subarray(dataAddr + i, dataAddr + Math.min(i + 8192, n)));
        }
      }
      return out;
    } finally {
      wipeScratch(r, stackBytes, dataBytes);
    }
  }

  return {
    name: 'wasm',

    /**
     * Add the first `nchunks` whole chunks of `message` to the tree in `state`.
     * @throws {TypeError} for a state of the wrong shape
     * @throws {RangeError} for more chunks than `message` holds, or a chunk count out of range
     */
    update(state, init, message, nchunks) {
      checkState(state, init);
      if (typeof message !== 'string') {
        throw new TypeError('Blake3: the message must be a string');
      }
      if (!Number.isInteger(nchunks) || nchunks < 0 || nchunks * CHUNK > message.length) {
        throw new RangeError('Blake3: cannot add ' + nchunks + ' chunks of a message of ' + message.length + ' bytes');
      }
      if (state.chunks + nchunks >= MAX_CHUNKS) {
        throw new RangeError('Blake3: message too long');
      }
      const r = runtime();
      // A refused call leaves `state` untouched; the plain-JavaScript engine then adds all the chunks.
      if (r === null || !wasmUpdate(r, state, init, message, nchunks)) {
        fallback.update(state, init, message, nchunks);
      }
    },

    /**
     * The first `bytes` output bytes of the hash whose last chunk is `tail`; `state` is not modified.
     * @throws {TypeError} for a state of the wrong shape
     * @throws {RangeError} for a tail that is not 1..1024 bytes (empty only when no chunk was added)
     */
    finalize(state, init, tail, bytes) {
      checkState(state, init);
      if (typeof tail !== 'string') {
        throw new TypeError('Blake3: the last chunk must be a string');
      }
      if (tail.length > CHUNK) {
        throw new RangeError('Blake3: the last chunk can be at most ' + CHUNK + ' bytes, got ' + tail.length);
      }
      if (tail.length === 0 && state.chunks !== 0) {
        throw new RangeError('Blake3: state has finished chunks but no last chunk');
      }
      if (!Number.isSafeInteger(bytes) || bytes < 0) {
        throw new RangeError('Blake3: the output length must be a non-negative integer, got ' + bytes);
      }
      const r = runtime();
      const out = r === null ? null : wasmFinalize(r, state, init, tail, bytes);
      return out !== null ? out : fallback.finalize(state, init, tail, bytes);
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
